"""Fake upstream DNS resolver for tests and offline demos.

Answers on both UDP and TCP (2-byte length framing) using only wire.py.
Run it standalone when there is no internet, then point the sinkhole at it:

    python tools/fake_upstream.py --port 5300
    python -m dnssink --port 5353 --upstream 127.0.0.1   (with [upstream] port = 5300)

Behaviour by query name:
    *nonexistent*  -> NXDOMAIN with an SOA in the authority section
    *big*  (TXT)   -> a ~2 KB TXT record (forces TC on UDP without EDNS0)
    anything else  -> A 10.0.0.x / AAAA 2001:db8::x, derived from the name

Options let tests simulate a truncating upstream (TC=1 on every UDP reply)
or a spoofer that first replies with the wrong transaction ID.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import socket
import struct
import sys
import threading
import zlib
from typing import List, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire  # noqa: E402

BIG_TXT_CHUNKS = 8       # 8 x 250-byte strings = ~2 KB of TXT data


class FakeUpstream:
    """A tiny authoritative-style DNS server bound to 127.0.0.1."""

    def __init__(self, port: int = 0, ttl: int = 120,
                 truncate_udp: bool = False, spoof_first: bool = False) -> None:
        self.ttl = ttl
        self.truncate_udp = truncate_udp
        self.spoof_first = spoof_first
        self.udp_queries = 0
        self.tcp_queries = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", port))
        self.port: int = self._udp.getsockname()[1]
        self._udp.settimeout(0.5)

        # TCP on the same port number, like a real DNS server.
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.bind(("127.0.0.1", self.port))
        self._tcp.listen(16)
        self._tcp.settimeout(0.5)

        self._threads = [
            threading.Thread(target=self._udp_loop, daemon=True),
            threading.Thread(target=self._tcp_loop, daemon=True),
        ]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "FakeUpstream":
        """Start the UDP and TCP threads; returns self for chaining."""
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        """Stop serving and close both sockets."""
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self._udp.close()
        self._tcp.close()

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def _udp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.udp_queries += 1
            resp = self.build_response(data, over_tcp=False)
            if resp is None:
                continue
            if self.spoof_first:
                # Send a reply with a wrong ID first; a correct resolver must ignore it.
                bad_id = (struct.unpack_from("!H", resp, 0)[0] + 1) & 0xFFFF
                self._udp.sendto(struct.pack("!H", bad_id) + resp[2:], addr)
            self._udp.sendto(resp, addr)

    def _tcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve_tcp, args=(conn,), daemon=True).start()

    def _serve_tcp(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(2.0)
            try:
                while True:
                    prefix = _recv_exact(conn, 2)
                    if not prefix:
                        return
                    (length,) = struct.unpack("!H", prefix)
                    query = _recv_exact(conn, length)
                    with self._lock:
                        self.tcp_queries += 1
                    resp = self.build_response(query, over_tcp=True)
                    if resp is None:
                        return
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
            except OSError:
                return

    # ------------------------------------------------------------------
    # Answer logic
    # ------------------------------------------------------------------

    def build_response(self, query: bytes, over_tcp: bool) -> Optional[bytes]:
        """Build the reply for *query*, or None if it cannot be parsed."""
        try:
            msg = wire.decode_message(query)
        except wire.DNSDecodeError:
            return None
        if not msg.questions:
            return None
        q = msg.questions[0]
        name = q.qname.lower()

        rcode = wire.RCODE_NOERROR
        answers: List[wire.DNSRecord] = []
        authorities: List[wire.DNSRecord] = []

        if "nonexistent" in name:
            rcode = wire.RCODE_NXDOMAIN
            authorities.append(_soa_record(name.split(".", 1)[-1] or name, self.ttl))
        elif q.qtype == wire.QTYPE_TXT and "big" in name:
            answers.append(_big_txt_record(q.qname, self.ttl))
        elif q.qtype == wire.QTYPE_A:
            last = zlib.crc32(name.encode()) % 250 + 1
            answers.append(wire.DNSRecord(q.qname, wire.QTYPE_A, wire.QCLASS_IN, self.ttl,
                                          bytes([10, 0, 0, last]), f"10.0.0.{last}"))
        elif q.qtype == wire.QTYPE_AAAA:
            last = zlib.crc32(name.encode()) % 250 + 1
            rdata = bytes.fromhex("20010db8") + bytes(11) + bytes([last])
            answers.append(wire.DNSRecord(q.qname, wire.QTYPE_AAAA, wire.QCLASS_IN,
                                          self.ttl, rdata, None))

        hdr = wire.build_response_header(msg.header, rcode=rcode, aa=True)
        resp = wire.DNSMessage(header=hdr, questions=msg.questions,
                               answers=answers, authorities=authorities)
        if msg.edns:
            resp.additionals.append(wire.build_opt_record(1232))

        if self.truncate_udp and not over_tcp:
            # Simulate a large answer that did not fit: TC=1, no records.
            resp.header = dataclasses.replace(resp.header, flags=resp.header.flags | wire.FLAG_TC)
            resp.answers = []
            resp.authorities = []
        return wire.encode_message(resp)


def _soa_record(zone: str, ttl: int) -> wire.DNSRecord:
    """SOA for negative answers; MINIMUM = 60 so negative caching is visible."""
    rdata = (wire.encode_name_uncompressed(f"ns1.{zone}")
             + wire.encode_name_uncompressed(f"hostmaster.{zone}")
             + struct.pack("!IIIII", 1, 3600, 600, 86400, 60))
    return wire.DNSRecord(zone, wire.QTYPE_SOA, wire.QCLASS_IN, ttl, rdata, None)


def _big_txt_record(name: str, ttl: int) -> wire.DNSRecord:
    """A TXT record made of several 250-byte character-strings."""
    rdata = b"".join(bytes([250]) + (b"%d" % i) * 250 for i in range(BIG_TXT_CHUNKS))
    return wire.DNSRecord(name, wire.QTYPE_TXT, wire.QCLASS_IN, ttl, rdata, None)


def _recv_exact(conn: socket.socket, nbytes: int) -> bytes:
    """Read exactly *nbytes*; returns b"" if the peer closed first."""
    buf = bytearray()
    while len(buf) < nbytes:
        chunk = conn.recv(nbytes - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)


def main() -> None:
    """Run the fake upstream until Ctrl+C."""
    p = argparse.ArgumentParser(description="Fake upstream DNS server (offline demo)")
    p.add_argument("--port", type=int, default=5300)
    p.add_argument("--ttl", type=int, default=120)
    p.add_argument("--truncate-udp", action="store_true",
                   help="set TC=1 on every UDP reply (forces TCP fallback)")
    args = p.parse_args()

    server = FakeUpstream(args.port, args.ttl, truncate_udp=args.truncate_udp).start()
    print(f"Fake upstream listening on 127.0.0.1:{server.port} (UDP+TCP). Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
