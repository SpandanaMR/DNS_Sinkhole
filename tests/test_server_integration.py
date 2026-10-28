"""Integration tests: end-to-end over loopback, UDP and TCP.

These tests start a real DNSSinkholeServer on a random high port with a
fake upstream, send queries using raw sockets, and verify responses.
"""

from __future__ import annotations

import dataclasses
import pathlib
import socket
import struct
import threading
import time

import pytest

import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire
from dnssink.config import (
    BlocklistConfig, CacheConfig, EdnsConfig, LoggingConfig,
    ServerConfig, SinkholeConfig, UpstreamConfig,
)
from dnssink.server import DNSSinkholeServer


# ---------------------------------------------------------------------------
# Fake upstream (inline, lightweight)
# ---------------------------------------------------------------------------

class _FakeUpstream:
    """Minimal fake upstream DNS server for integration tests."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(1.0)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
                resp = self._respond(data)
                if resp:
                    self._sock.sendto(resp, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    @staticmethod
    def _respond(query: bytes) -> bytes:
        if len(query) < 12:
            return b""
        try:
            msg = wire.decode_message(query)
        except wire.DNSDecodeError:
            return b""
        qname = msg.questions[0].qname if msg.questions else ""
        qtype = msg.questions[0].qtype if msg.questions else wire.QTYPE_A

        # Return NXDOMAIN for domains containing "nonexistent"
        if "nonexistent" in qname.lower():
            rcode = wire.RCODE_NXDOMAIN
            answers = []
        else:
            rcode = wire.RCODE_NOERROR
            if qtype == wire.QTYPE_A:
                answers = [wire.DNSRecord(
                    name=qname, rtype=wire.QTYPE_A, rclass=wire.QCLASS_IN,
                    ttl=120, rdata=bytes([93, 184, 216, 34]), decoded="93.184.216.34",
                )]
            elif qtype == wire.QTYPE_AAAA:
                answers = [wire.DNSRecord(
                    name=qname, rtype=wire.QTYPE_AAAA, rclass=wire.QCLASS_IN,
                    ttl=120, rdata=b"\x20\x01\x0d\xb8" + b"\x00" * 12,
                    decoded="2001:0db8:0000:0000:0000:0000:0000:0000",
                )]
            else:
                answers = []

        resp_hdr = wire.build_response_header(msg.header, rcode=rcode)
        resp = wire.DNSMessage(
            header=dataclasses.replace(resp_hdr,
                                       qdcount=len(msg.questions),
                                       ancount=len(answers)),
            questions=msg.questions,
            answers=answers,
        )
        return wire.encode_message(resp)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def server_and_port(tmp_path: pathlib.Path):
    """Start a sinkhole server with fake upstream and return (server, port)."""
    fake = _FakeUpstream()
    fake.start()

    # Write a small blocklist
    bl_file = tmp_path / "blocked.txt"
    bl_file.write_text("example-ads.test\ntracker.evil.test\n")

    # Find a free port for the server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        dns_port = s.getsockname()[1]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        dash_port = s.getsockname()[1]

    cfg = SinkholeConfig(
        server=ServerConfig(
            listen_address="127.0.0.1",
            listen_port=dns_port,
            dashboard_port=dash_port,
            worker_threads=2,
            tcp_idle_timeout=5,
            max_tcp_connections=10,
        ),
        upstream=UpstreamConfig(
            primary="127.0.0.1",
            secondary=None,
            port=fake.port,
            timeout=2.0,
            retries=1,
        ),
        cache=CacheConfig(max_entries=100, max_negative_ttl=60),
        blocklist=BlocklistConfig(
            hosts_files=[],
            domain_files=[str(bl_file)],
            block_mode="null",
            block_ttl=30,
        ),
        logging=LoggingConfig(
            log_file=str(tmp_path / "test.log"),
            level="WARNING",
        ),
        edns=EdnsConfig(max_udp_payload=1232),
    )

    server = DNSSinkholeServer(cfg, base_path=tmp_path)
    server.start()
    time.sleep(0.3)  # let listeners bind

    yield server, dns_port, dash_port

    server.stop()
    fake.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_udp_query(qname: str, qtype: int, port: int,
                    timeout: float = 3.0) -> wire.DNSMessage:
    """Send a UDP DNS query and return the parsed response."""
    hdr = wire.DNSHeader(id=0xABCD, flags=wire.FLAG_RD, qdcount=1)
    q = wire.DNSQuestion(qname=qname, qtype=qtype, qclass=wire.QCLASS_IN)
    msg = wire.DNSMessage(header=hdr, questions=[q])
    query_bytes = wire.encode_message(msg)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query_bytes, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
        return wire.decode_message(data)
    finally:
        sock.close()


def _send_tcp_query(qname: str, qtype: int, port: int,
                    timeout: float = 3.0) -> wire.DNSMessage:
    """Send a TCP DNS query and return the parsed response."""
    hdr = wire.DNSHeader(id=0xBEEF, flags=wire.FLAG_RD, qdcount=1)
    q = wire.DNSQuestion(qname=qname, qtype=qtype, qclass=wire.QCLASS_IN)
    msg = wire.DNSMessage(header=hdr, questions=[q])
    query_bytes = wire.encode_message(msg)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        sock.sendall(struct.pack("!H", len(query_bytes)) + query_bytes)
        len_data = sock.recv(2)
        resp_len = struct.unpack("!H", len_data)[0]
        data = b""
        while len(data) < resp_len:
            chunk = sock.recv(resp_len - len(data))
            if not chunk:
                break
            data += chunk
        return wire.decode_message(data)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestUDPIntegration:
    def test_normal_query(self, server_and_port) -> None:
        """A normal domain should resolve via the upstream."""
        server, port, _ = server_and_port
        resp = _send_udp_query("example.com", wire.QTYPE_A, port)
        assert resp.header.qr is True
        assert resp.header.rcode == wire.RCODE_NOERROR
        assert len(resp.answers) >= 1
        assert resp.answers[0].decoded == "93.184.216.34"

    def test_blocked_domain(self, server_and_port) -> None:
        """A blocked domain should return 0.0.0.0."""
        server, port, _ = server_and_port
        resp = _send_udp_query("example-ads.test", wire.QTYPE_A, port)
        assert resp.header.qr is True
        assert len(resp.answers) >= 1
        assert resp.answers[0].decoded == "0.0.0.0"

    def test_blocked_subdomain(self, server_and_port) -> None:
        """A subdomain of a blocked domain should also be blocked."""
        server, port, _ = server_and_port
        resp = _send_udp_query("sub.example-ads.test", wire.QTYPE_A, port)
        assert resp.header.qr is True
        assert len(resp.answers) >= 1
        assert resp.answers[0].decoded == "0.0.0.0"

    def test_cache_hit(self, server_and_port) -> None:
        """Second query for the same name should be a cache hit."""
        server, port, _ = server_and_port
        # First query
        resp1 = _send_udp_query("cached.example.com", wire.QTYPE_A, port)
        assert resp1.header.rcode == wire.RCODE_NOERROR
        time.sleep(0.1)
        # Second query
        resp2 = _send_udp_query("cached.example.com", wire.QTYPE_A, port)
        assert resp2.header.rcode == wire.RCODE_NOERROR
        # TTL should have decayed
        if resp1.answers and resp2.answers:
            assert resp2.answers[0].ttl <= resp1.answers[0].ttl

    def test_nxdomain_passthrough(self, server_and_port) -> None:
        """NXDOMAIN from upstream should be passed through."""
        server, port, _ = server_and_port
        resp = _send_udp_query("nonexistent.example.com", wire.QTYPE_A, port)
        assert resp.header.rcode == wire.RCODE_NXDOMAIN

    def test_aaaa_query(self, server_and_port) -> None:
        """AAAA query should work."""
        server, port, _ = server_and_port
        resp = _send_udp_query("example.com", wire.QTYPE_AAAA, port)
        assert resp.header.qr is True

    def test_malformed_query(self, server_and_port) -> None:
        """Sending garbage should get FORMERR, not crash the server."""
        server, port, _ = server_and_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(3.0)
            sock.sendto(b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                        ("127.0.0.1", port))
            data, _ = sock.recvfrom(4096)
            resp = wire.decode_message(data)
            # Should still be alive – try another real query.
            resp2 = _send_udp_query("example.com", wire.QTYPE_A, port)
            assert resp2.header.qr is True
        finally:
            sock.close()


class TestTCPIntegration:
    def test_tcp_query(self, server_and_port) -> None:
        """TCP query should resolve normally."""
        server, port, _ = server_and_port
        resp = _send_tcp_query("example.com", wire.QTYPE_A, port)
        assert resp.header.qr is True
        assert resp.header.rcode == wire.RCODE_NOERROR
        assert len(resp.answers) >= 1

    def test_tcp_blocked(self, server_and_port) -> None:
        """Blocked domain should also work over TCP."""
        server, port, _ = server_and_port
        resp = _send_tcp_query("tracker.evil.test", wire.QTYPE_A, port)
        assert resp.header.qr is True
        assert len(resp.answers) >= 1
        assert resp.answers[0].decoded == "0.0.0.0"

    def test_tcp_multiple_queries(self, server_and_port) -> None:
        """Multiple queries on one TCP connection."""
        server, port, _ = server_and_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", port))
            for i in range(3):
                hdr = wire.DNSHeader(id=0x1000 + i, flags=wire.FLAG_RD, qdcount=1)
                q = wire.DNSQuestion(qname=f"multi{i}.example.com",
                                     qtype=wire.QTYPE_A, qclass=wire.QCLASS_IN)
                msg = wire.DNSMessage(header=hdr, questions=[q])
                qb = wire.encode_message(msg)
                sock.sendall(struct.pack("!H", len(qb)) + qb)
                ld = sock.recv(2)
                rl = struct.unpack("!H", ld)[0]
                rd = b""
                while len(rd) < rl:
                    chunk = sock.recv(rl - len(rd))
                    if not chunk:
                        break
                    rd += chunk
                resp = wire.decode_message(rd)
                assert resp.header.qr is True
                assert resp.header.id == 0x1000 + i
        finally:
            sock.close()


class TestDashboardIntegration:
    def test_dashboard_responds(self, server_and_port) -> None:
        """Dashboard HTTP endpoint should respond."""
        import http.client
        server, _, dash_port = server_and_port
        conn = http.client.HTTPConnection("127.0.0.1", dash_port, timeout=3)
        try:
            conn.request("GET", "/api/stats")
            resp = conn.getresponse()
            assert resp.status == 200
            import json
            data = json.loads(resp.read().decode())
            assert "total_queries" in data
        finally:
            conn.close()

    def test_dashboard_html(self, server_and_port) -> None:
        """Dashboard HTML page should load."""
        import http.client
        server, _, dash_port = server_and_port
        conn = http.client.HTTPConnection("127.0.0.1", dash_port, timeout=3)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            assert resp.status == 200
            body = resp.read().decode()
            assert "DNS Sinkhole" in body
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Feature tests against tools/fake_upstream.py (UDP + TCP fake resolver)
# ---------------------------------------------------------------------------

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
from fake_upstream import FakeUpstream  # noqa: E402


def _free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def make_server(tmp_path: pathlib.Path):
    """Factory: make_server(fake_upstream, block_mode=...) -> (server, port)."""
    started = []

    def _make(fake: FakeUpstream, block_mode: str = "null"):
        bl_file = tmp_path / "blocked.txt"
        bl_file.write_text("example-ads.test\n")
        cfg = SinkholeConfig(
            server=ServerConfig(listen_address="127.0.0.1",
                                listen_port=_free_port(socket.SOCK_DGRAM),
                                dashboard_port=_free_port(socket.SOCK_STREAM),
                                worker_threads=4, tcp_idle_timeout=5),
            upstream=UpstreamConfig(primary="127.0.0.1", secondary=None,
                                    port=fake.port, timeout=1.0, retries=1),
            cache=CacheConfig(max_entries=100, max_negative_ttl=60),
            blocklist=BlocklistConfig(hosts_files=[], domain_files=[str(bl_file)],
                                      block_mode=block_mode, block_ttl=30),
            logging=LoggingConfig(log_file=str(tmp_path / "test.log"), level="WARNING"),
        )
        server = DNSSinkholeServer(cfg, base_path=tmp_path)
        server.start()
        time.sleep(0.2)
        started.append((server, fake))
        return server, cfg.server.listen_port

    yield _make
    for server, fake in started:
        server.stop()
        fake.stop()


def _query_bytes(qname: str, qtype: int, edns: bool = False, qid: int = 0x4242) -> bytes:
    msg = wire.DNSMessage(header=wire.DNSHeader(id=qid, flags=wire.FLAG_RD),
                          questions=[wire.DNSQuestion(qname, qtype, wire.QCLASS_IN)])
    if edns:
        msg.additionals.append(wire.build_opt_record(1232))
    return wire.encode_message(msg)


def _udp_raw(query: bytes, port: int, timeout: float = 5.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(query, ("127.0.0.1", port))
        return s.recvfrom(65535)[0]


class TestLargeResponsesAndTCP:
    def test_big_txt_truncated_over_udp_full_over_tcp(self, make_server) -> None:
        """A7 + R7c: >512-byte answer sets TC on UDP and arrives whole over TCP."""
        _, port = make_server(FakeUpstream().start())
        udp = _udp_raw(_query_bytes("big.example.com", wire.QTYPE_TXT), port)
        assert len(udp) <= 512
        assert wire.decode_message(udp).header.tc is True

        tcp = _send_tcp_query("big.example.com", wire.QTYPE_TXT, port)
        assert tcp.header.tc is False
        assert len(tcp.answers) == 1 and len(tcp.answers[0].rdata) > 1500

    def test_upstream_tc_triggers_tcp_retry(self, make_server) -> None:
        """R7b: upstream UDP reply with TC=1 is retried over TCP."""
        fake = FakeUpstream(truncate_udp=True).start()
        _, port = make_server(fake)
        resp = _send_tcp_query("www.example.com", wire.QTYPE_A, port)
        assert resp.header.tc is False
        assert resp.answers and resp.answers[0].rtype == wire.QTYPE_A
        assert fake.udp_queries == 1 and fake.tcp_queries == 1


class TestEdns:
    @pytest.mark.parametrize("qname", ["fwd.example.com", "example-ads.test"])
    def test_opt_echoed(self, make_server, qname: str) -> None:
        """R8: an OPT record comes back for forwarded, cached and blocked answers."""
        _, port = make_server(FakeUpstream().start())
        for _ in range(2):   # second round is a cache hit for the forwarded name
            resp = wire.decode_message(_udp_raw(_query_bytes(qname, wire.QTYPE_A, edns=True), port))
            assert resp.edns is not None
            assert sum(r.rtype == wire.QTYPE_OPT for r in resp.additionals) == 1

    def test_no_opt_without_edns(self, make_server) -> None:
        """Clients that did not send OPT must not receive one."""
        _, port = make_server(FakeUpstream().start())
        resp = wire.decode_message(_udp_raw(_query_bytes("plain.example.com", wire.QTYPE_A), port))
        assert resp.edns is None

    def test_edns_client_gets_big_answer_over_udp(self, make_server) -> None:
        """With EDNS0 the 1232-byte limit applies instead of 512."""
        _, port = make_server(FakeUpstream().start())
        resp = _udp_raw(_query_bytes("fwd.example.com", wire.QTYPE_A, edns=True), port)
        assert wire.decode_message(resp).header.tc is False


class TestCachingBehaviour:
    def test_ttl_expiry_refetches(self, make_server) -> None:
        """A5: after the TTL runs out the query goes upstream again."""
        fake = FakeUpstream(ttl=1).start()
        _, port = make_server(fake)
        q = _query_bytes("short-ttl.example.com", wire.QTYPE_A)
        _udp_raw(q, port)
        _udp_raw(q, port)
        assert fake.udp_queries == 1          # second one was a cache hit
        time.sleep(1.3)
        _udp_raw(q, port)
        assert fake.udp_queries == 2          # expired -> refetched

    def test_negative_cache_hit_keeps_soa(self, make_server) -> None:
        """NXDOMAIN is cached (RFC 2308) and the cached reply still has a valid SOA."""
        fake = FakeUpstream().start()
        _, port = make_server(fake)
        q = _query_bytes("nonexistent.example.com", wire.QTYPE_A)
        first = wire.decode_message(_udp_raw(q, port))
        second = wire.decode_message(_udp_raw(q, port))
        assert fake.udp_queries == 1
        assert second.header.rcode == wire.RCODE_NXDOMAIN
        assert second.authorities[0].decoded.split()[:2] == first.authorities[0].decoded.split()[:2]
        assert second.authorities[0].ttl <= 60


class TestSpoofingAndIds:
    def test_wrong_id_reply_ignored_and_client_id_restored(self, make_server) -> None:
        """R6: a reply with the wrong transaction ID is discarded."""
        _, port = make_server(FakeUpstream(spoof_first=True).start())
        q = _query_bytes("id.example.com", wire.QTYPE_A, qid=0x1357)
        resp = wire.decode_message(_udp_raw(q, port))
        assert resp.header.id == 0x1357
        assert resp.answers and resp.answers[0].rtype == wire.QTYPE_A


class TestBlockModes:
    def test_nxdomain_mode(self, make_server) -> None:
        """R4: block_mode nxdomain answers NXDOMAIN for blocked names."""
        _, port = make_server(FakeUpstream().start(), block_mode="nxdomain")
        resp = wire.decode_message(_udp_raw(_query_bytes("x.example-ads.test", wire.QTYPE_A), port))
        assert resp.header.rcode == wire.RCODE_NXDOMAIN
        assert resp.answers == []


class TestShutdown:
    def test_stop_is_prompt_with_idle_tcp_client(self, make_server) -> None:
        """R12: an idle TCP connection does not delay shutdown by tcp_idle_timeout."""
        server, port = make_server(FakeUpstream().start())
        idle = socket.create_connection(("127.0.0.1", port))
        try:
            time.sleep(0.2)
            start = time.monotonic()
            server.stop()
            assert time.monotonic() - start < 3.5
        finally:
            idle.close()

    def test_idle_tcp_clients_do_not_starve_udp(self, make_server) -> None:
        """More idle TCP clients than worker threads must not block UDP queries."""
        _, port = make_server(FakeUpstream().start())
        conns = [socket.create_connection(("127.0.0.1", port)) for _ in range(6)]
        try:
            q = _query_bytes("after-tcp.example.com", wire.QTYPE_A)
            resp = wire.decode_message(_udp_raw(q, port, timeout=2))
            assert resp.header.rcode == wire.RCODE_NOERROR
        finally:
            for c in conns:
                c.close()
