"""Compare the sinkhole's answers with a public resolver, query by query.

    python tools/crossvalidate.py --port 5353 --reference 8.8.8.8

For each (name, type) it asks both servers and checks that the RCODE and
the record data match.  TTLs are expected to differ (the sinkhole returns
the decayed cache TTL), and load-balanced names may return different
address sets, so those are reported as "same types, different set".
"""

from __future__ import annotations

import argparse
import pathlib
import random
import socket
import struct
import sys
from typing import List, Optional, Set, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire  # noqa: E402

QUERIES: List[Tuple[str, int]] = [
    ("example.com", wire.QTYPE_A), ("example.com", wire.QTYPE_AAAA),
    ("example.com", wire.QTYPE_NS), ("example.com", wire.QTYPE_SOA),
    ("www.github.com", wire.QTYPE_A), ("wikipedia.org", wire.QTYPE_A),
    ("gmail.com", wire.QTYPE_MX), ("example.com", wire.QTYPE_TXT),
    ("cloudflare.com", wire.QTYPE_AAAA), ("python.org", wire.QTYPE_A),
    ("www.microsoft.com", wire.QTYPE_A),
    ("does-not-exist-7q2x9.example.com", wire.QTYPE_A),   # NODATA
    ("no-such-domain-58213x.com", wire.QTYPE_A),         # NXDOMAIN
]


def ask(server: str, port: int, name: str, qtype: int) -> wire.DNSMessage:
    """Send one query (UDP, retry over TCP if truncated) and decode the reply."""
    query = wire.encode_message(wire.DNSMessage(
        header=wire.DNSHeader(id=random.randint(0, 0xFFFF), flags=wire.FLAG_RD),
        questions=[wire.DNSQuestion(name, qtype, wire.QCLASS_IN)]))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(query, (server, port))
        data = s.recvfrom(65535)[0]
    msg = wire.decode_message(data)
    if msg.header.tc:
        with socket.create_connection((server, port), timeout=5) as t:
            t.sendall(struct.pack("!H", len(query)) + query)
            (length,) = struct.unpack("!H", _recv(t, 2))
            msg = wire.decode_message(_recv(t, length))
    return msg


def _recv(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def records(msg: wire.DNSMessage, section: str = "answers") -> Set[Tuple[str, str, str]]:
    """Comparable view of a section: (name, type, data), TTL dropped."""
    out = set()
    for r in getattr(msg, section):
        data = r.decoded if r.decoded is not None else r.rdata.hex()
        if r.rtype == wire.QTYPE_SOA and r.decoded:
            data = " ".join(r.decoded.split()[:2])   # mname rname (serials change constantly)
        out.add((r.name.lower(), wire.qtype_to_str(r.rtype), data))
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Cross-validate the sinkhole against a public resolver")
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5353)
    p.add_argument("--reference", default="8.8.8.8")
    args = p.parse_args()

    print(f"| Query | RCODE (sinkhole / {args.reference}) | Answers | Result |")
    print("|---|---|---|---|")
    exact = similar = differ = 0
    for name, qtype in QUERIES:
        ours = ask(args.server, args.port, name, qtype)
        ref = ask(args.reference, 53, name, qtype)
        section = "answers" if ref.answers else "authorities"
        a, b = records(ours, section), records(ref, section)
        if ours.header.rcode != ref.header.rcode:
            verdict, differ = "**RCODE differs**", differ + 1
        elif a == b:
            verdict, exact = "match", exact + 1
        elif {t for _, t, _ in a} == {t for _, t, _ in b}:
            verdict, similar = "same types, different set (load-balanced/rotating)", similar + 1
        else:
            verdict, differ = "**records differ**", differ + 1
        ttls: List[Optional[int]] = [r.ttl for r in ours.answers][:1] + [r.ttl for r in ref.answers][:1]
        ttl_note = f" TTL {ttls[0]}/{ttls[1]}" if len(ttls) == 2 else ""
        print(f"| {name} {wire.qtype_to_str(qtype)} | {ours.header.rcode} / {ref.header.rcode} "
              f"| {len(ours.answers)} / {len(ref.answers)}{ttl_note} | {verdict} |")
    print(f"\n{exact} exact, {similar} same-type, {differ} different, out of {len(QUERIES)} queries")


if __name__ == "__main__":
    main()
