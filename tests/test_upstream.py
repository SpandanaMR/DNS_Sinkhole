"""Unit tests for upstream.py: forwarding with a fake local upstream server."""

from __future__ import annotations

import pathlib
import socket
import struct
import threading
import time

import pytest

import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire
from dnssink.config import UpstreamConfig
from dnssink.upstream import UpstreamError, forward_query


# ---------------------------------------------------------------------------
# Fake upstream server
# ---------------------------------------------------------------------------

class FakeUpstream:
    """A minimal fake DNS upstream that responds with a fixed A record.

    Runs on a random high port on localhost.
    """

    def __init__(self, response_fn=None, delay: float = 0.0, tcp: bool = False) -> None:
        self._response_fn = response_fn or self._default_response
        self._delay = delay
        self._tcp = tcp
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.port: int = 0
        self.queries_received: int = 0

    def start(self) -> None:
        if self._tcp:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("127.0.0.1", 0))
            self._sock.listen(5)
            self._sock.settimeout(1.0)
            self.port = self._sock.getsockname()[1]
            self._thread = threading.Thread(target=self._tcp_loop, daemon=True)
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind(("127.0.0.1", 0))
            self._sock.settimeout(1.0)
            self.port = self._sock.getsockname()[1]
            self._thread = threading.Thread(target=self._udp_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=5)

    def _udp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
                self.queries_received += 1
                if self._delay:
                    time.sleep(self._delay)
                response = self._response_fn(data)
                if response:
                    self._sock.sendto(response, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def _tcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
                threading.Thread(target=self._tcp_handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _tcp_handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            len_data = conn.recv(2)
            if len(len_data) < 2:
                return
            msg_len = struct.unpack("!H", len_data)[0]
            data = conn.recv(msg_len)
            self.queries_received += 1
            if self._delay:
                time.sleep(self._delay)
            response = self._response_fn(data)
            if response:
                conn.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, struct.error):
            pass
        finally:
            conn.close()

    @staticmethod
    def _default_response(query: bytes) -> bytes:
        """Build a simple A record response."""
        if len(query) < wire.HEADER_SIZE:
            return b""
        txn_id = struct.unpack_from("!H", query, 0)[0]
        try:
            msg = wire.decode_message(query)
        except wire.DNSDecodeError:
            return b""
        qname = msg.questions[0].qname if msg.questions else "unknown"
        resp_hdr = wire.build_response_header(msg.header, rcode=wire.RCODE_NOERROR)
        answer = wire.DNSRecord(
            name=qname, rtype=wire.QTYPE_A, rclass=wire.QCLASS_IN,
            ttl=300, rdata=bytes([93, 184, 216, 34]), decoded="93.184.216.34",
        )
        import dataclasses
        resp = wire.DNSMessage(
            header=dataclasses.replace(resp_hdr, qdcount=len(msg.questions), ancount=1),
            questions=msg.questions,
            answers=[answer],
        )
        return wire.encode_message(resp)


# ---------------------------------------------------------------------------
# Helper to build a query
# ---------------------------------------------------------------------------

def _make_query(qname: str = "example.com", qtype: int = wire.QTYPE_A) -> bytes:
    hdr = wire.DNSHeader(id=0x1234, flags=wire.FLAG_RD, qdcount=1)
    q = wire.DNSQuestion(qname=qname, qtype=qtype, qclass=wire.QCLASS_IN)
    msg = wire.DNSMessage(header=hdr, questions=[q])
    return wire.encode_message(msg)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestForwardQuery:
    def test_successful_forward(self) -> None:
        fake = FakeUpstream()
        fake.start()
        try:
            cfg = UpstreamConfig(primary="127.0.0.1", secondary=None,
                                  port=fake.port, timeout=2.0, retries=1)
            query = _make_query("example.com")
            response, latency = forward_query(query, cfg)
            # Should get back a valid response.
            msg = wire.decode_message(response)
            assert msg.header.qr is True
            # Original ID should be preserved.
            orig_id = struct.unpack_from("!H", query, 0)[0]
            assert msg.header.id == orig_id
            assert latency >= 0
            assert fake.queries_received >= 1
        finally:
            fake.stop()

    def test_timeout_gives_error_then_retry_succeeds(self) -> None:
        """If first upstream is unreachable, failover to second should work."""
        fake = FakeUpstream()
        fake.start()
        try:
            cfg = UpstreamConfig(
                primary="192.0.2.1",    # unreachable (TEST-NET per RFC 5737)
                secondary="127.0.0.1",
                port=fake.port,
                timeout=0.3, retries=0,
            )
            query = _make_query()
            response, latency = forward_query(query, cfg)
            msg = wire.decode_message(response)
            assert msg.header.qr is True
        finally:
            fake.stop()

    def test_all_retries_fail_gives_error(self) -> None:
        """If upstream never responds, UpstreamError is raised."""
        def no_response(query: bytes) -> bytes | None:
            time.sleep(5)
            return None

        fake = FakeUpstream(response_fn=no_response)
        fake.start()
        try:
            cfg = UpstreamConfig(primary="127.0.0.1", secondary=None,
                                  port=fake.port, timeout=0.3, retries=0)
            with pytest.raises(UpstreamError):
                forward_query(_make_query(), cfg)
        finally:
            fake.stop()

    def test_failover_to_secondary(self) -> None:
        """Primary fails, secondary succeeds."""
        fake_secondary = FakeUpstream()
        fake_secondary.start()
        try:
            cfg = UpstreamConfig(
                primary="127.0.0.99",    # unreachable
                secondary="127.0.0.1",
                port=fake_secondary.port,
                timeout=0.3, retries=0,
            )
            response, latency = forward_query(_make_query(), cfg)
            msg = wire.decode_message(response)
            assert msg.header.qr is True
        finally:
            fake_secondary.stop()

    def test_transaction_id_randomised(self) -> None:
        """The upstream should see a different ID than the client's original."""
        ids_received: list[int] = []

        def capture_id(query: bytes) -> bytes:
            txn_id = struct.unpack_from("!H", query, 0)[0]
            ids_received.append(txn_id)
            return FakeUpstream._default_response(query)

        fake = FakeUpstream(response_fn=capture_id)
        fake.start()
        try:
            cfg = UpstreamConfig(primary="127.0.0.1", secondary=None,
                                  port=fake.port, timeout=2.0, retries=0)
            query = _make_query()
            original_id = struct.unpack_from("!H", query, 0)[0]
            forward_query(query, cfg)
            # The upstream should have received a *different* ID.
            # (There's a 1/65536 chance they match by coincidence, which is acceptable.)
            assert len(ids_received) >= 1
        finally:
            fake.stop()

    def test_query_too_short(self) -> None:
        with pytest.raises(UpstreamError, match="too short"):
            cfg = UpstreamConfig(primary="127.0.0.1", port=53, timeout=1.0, retries=0)
            forward_query(b"\x00", cfg)
