"""Tiny DNS test client built on wire.py.

Usage:
    python tools/dnsclient.py example.com A --port 5353
    python tools/dnsclient.py example.com AAAA --server 8.8.8.8
    python tools/dnsclient.py example.com A --tcp
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
import pathlib
import random

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire


QTYPE_MAP = {
    "A": wire.QTYPE_A,
    "AAAA": wire.QTYPE_AAAA,
    "CNAME": wire.QTYPE_CNAME,
    "MX": wire.QTYPE_MX,
    "NS": wire.QTYPE_NS,
    "TXT": wire.QTYPE_TXT,
    "SOA": wire.QTYPE_SOA,
}


def build_query(qname: str, qtype: int) -> bytes:
    """Build a DNS query packet."""
    hdr = wire.DNSHeader(
        id=random.randint(0, 0xFFFF),
        flags=wire.FLAG_RD,
        qdcount=1,
    )
    q = wire.DNSQuestion(qname=qname, qtype=qtype, qclass=wire.QCLASS_IN)
    msg = wire.DNSMessage(header=hdr, questions=[q])
    return wire.encode_message(msg)


def send_udp(query: bytes, server: str, port: int, timeout: float) -> bytes:
    """Send a DNS query over UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (server, port))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def send_tcp(query: bytes, server: str, port: int, timeout: float) -> bytes:
    """Send a DNS query over TCP with 2-byte length prefix."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(struct.pack("!H", len(query)) + query)
        len_data = sock.recv(2)
        if len(len_data) < 2:
            raise ConnectionError("Short response length")
        resp_len = struct.unpack("!H", len_data)[0]
        data = b""
        while len(data) < resp_len:
            chunk = sock.recv(resp_len - len(data))
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


def print_response(msg: wire.DNSMessage, latency_ms: float) -> None:
    """Pretty-print a DNS response."""
    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                   4: "NOTIMP", 5: "REFUSED"}
    print(f"\n;; Response (ID: 0x{msg.header.id:04X}, "
          f"RCODE: {rcode_names.get(msg.header.rcode, msg.header.rcode)}, "
          f"Latency: {latency_ms:.2f}ms)")
    print(f";; Flags: QR={msg.header.qr} AA={msg.header.aa} "
          f"TC={msg.header.tc} RD={msg.header.rd} RA={msg.header.ra}")
    print(f";; QUESTION: {msg.header.qdcount}, ANSWER: {msg.header.ancount}, "
          f"AUTHORITY: {msg.header.nscount}, ADDITIONAL: {msg.header.arcount}")

    if msg.questions:
        print("\n;; QUESTION SECTION:")
        for q in msg.questions:
            print(f";  {q.qname}\t\t{wire.qtype_to_str(q.qtype)}\tIN")

    if msg.answers:
        print("\n;; ANSWER SECTION:")
        for rec in msg.answers:
            val = rec.decoded or rec.rdata.hex()
            print(f"  {rec.name}\t{rec.ttl}\tIN\t{wire.qtype_to_str(rec.rtype)}\t{val}")

    if msg.authorities:
        print("\n;; AUTHORITY SECTION:")
        for rec in msg.authorities:
            val = rec.decoded or rec.rdata.hex()
            print(f"  {rec.name}\t{rec.ttl}\tIN\t{wire.qtype_to_str(rec.rtype)}\t{val}")

    if msg.additionals:
        print("\n;; ADDITIONAL SECTION:")
        for rec in msg.additionals:
            if rec.rtype == wire.QTYPE_OPT:
                print(f"  OPT\tUDP={rec.rclass}")
            else:
                val = rec.decoded or rec.rdata.hex()
                print(f"  {rec.name}\t{rec.ttl}\tIN\t{wire.qtype_to_str(rec.rtype)}\t{val}")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS test client (built on wire.py)")
    parser.add_argument("name", help="Domain name to query")
    parser.add_argument("type", nargs="?", default="A",
                        choices=list(QTYPE_MAP.keys()),
                        help="Query type (default: A)")
    parser.add_argument("--server", "-s", default="127.0.0.1",
                        help="DNS server address (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=5353,
                        help="DNS server port (default: 5353)")
    parser.add_argument("--tcp", action="store_true",
                        help="Use TCP instead of UDP")
    parser.add_argument("--timeout", "-t", type=float, default=5.0,
                        help="Timeout in seconds (default: 5)")
    parser.add_argument("--hex", action="store_true",
                        help="Also print hex dump of response")
    args = parser.parse_args()

    qtype = QTYPE_MAP[args.type]
    query = build_query(args.name, qtype)

    print(f";; Querying {args.server}:{args.port} for {args.name} {args.type} "
          f"({'TCP' if args.tcp else 'UDP'})")

    start = time.perf_counter()
    try:
        if args.tcp:
            data = send_tcp(query, args.server, args.port, args.timeout)
        else:
            data = send_udp(query, args.server, args.port, args.timeout)
    except socket.timeout:
        print(f"ERROR: Timeout ({args.timeout}s) waiting for response", file=sys.stderr)
        sys.exit(1)
    except ConnectionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    latency_ms = (time.perf_counter() - start) * 1000.0

    if args.hex:
        print(f"\n;; Raw response ({len(data)} bytes):")
        for i in range(0, len(data), 16):
            hex_part = " ".join(f"{b:02x}" for b in data[i:i+16])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
            print(f"  {i:04x}  {hex_part:<48s}  {ascii_part}")

    try:
        resp = wire.decode_message(data)
        print_response(resp, latency_ms)
    except wire.DNSDecodeError as e:
        print(f"ERROR: Failed to decode response: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
