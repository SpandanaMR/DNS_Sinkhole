"""Record real query/response bytes to a .pcap file and annotate them.

Sends DNS queries to the running sinkhole, keeps the exact bytes sent and
received, and writes them as a standard libpcap file that Wireshark can
open on any machine (no Npcap needed just to *open* a file).  It also
prints a field-by-field breakdown of each packet for the report.

    python tools/capture_pcap.py --port 5353 --out docs/capture.pcap

Why build the pcap ourselves: capturing live loopback traffic on Windows
needs the Npcap driver (admin install).  The DNS payload bytes here are
exactly what went over the socket; only the IPv4/UDP headers around them
are reconstructed (UDP checksum 0 = "not computed", which IPv4 allows).
"""

from __future__ import annotations

import argparse
import pathlib
import random
import socket
import struct
import sys
import time
from typing import List, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire  # noqa: E402

LINKTYPE_RAW = 101   # packets start directly with the IPv4 header

Packet = Tuple[float, str, int, str, int, bytes]   # time, src, sport, dst, dport, payload


def _ipv4_udp(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    """Wrap *payload* in IPv4 + UDP headers (network byte order)."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, random.randint(0, 0xFFFF), 0,
                      64, socket.IPPROTO_UDP, 0, socket.inet_aton(src), socket.inet_aton(dst))
    # IPv4 header checksum: one's-complement sum of the 16-bit words.
    s = sum(struct.unpack("!10H", hdr))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    hdr = hdr[:10] + struct.pack("!H", ~s & 0xFFFF) + hdr[12:]
    return hdr + udp


def write_pcap(path: pathlib.Path, packets: List[Packet]) -> None:
    """Write packets in classic libpcap format (magic 0xa1b2c3d4)."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        for ts, src, sport, dst, dport, payload in packets:
            frame = _ipv4_udp(src, sport, dst, dport, payload)
            sec = int(ts)
            fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
            fh.write(frame)


def annotate(label: str, data: bytes) -> str:
    """Return a human-readable breakdown of a DNS message's wire bytes."""
    msg = wire.decode_message(data)
    h = msg.header
    lines = [f"=== {label} ({len(data)} bytes) ===",
             "hex: " + data.hex(" "),
             f"[0-1]   ID       = 0x{h.id:04X}",
             f"[2-3]   Flags    = 0x{h.flags:04X}  QR={int(h.qr)} Opcode={(h.flags >> 11) & 0xF} "
             f"AA={int(bool(h.flags & wire.FLAG_AA))} TC={int(h.tc)} RD={int(h.rd)} "
             f"RA={int(bool(h.flags & wire.FLAG_RA))} RCODE={h.rcode}",
             f"[4-11]  QDCOUNT={h.qdcount} ANCOUNT={h.ancount} NSCOUNT={h.nscount} ARCOUNT={h.arcount}"]
    for q in msg.questions:
        lines.append(f"[12-]   Question: {q.qname} {wire.qtype_to_str(q.qtype)} class={q.qclass}")
    for rec in msg.answers + msg.authorities:
        lines.append(f"        RR: {rec.name} {wire.qtype_to_str(rec.rtype)} TTL={rec.ttl} -> {rec.decoded}")
    for off, val in _owner_name_pointers(data, msg):
        lines.append(f"        [{off}-{off + 1}] owner name = pointer 0x{val:04X} -> offset {val & 0x3FFF}"
                     + ("  (the question name)" if val == 0xC00C else ""))
    return "\n".join(lines)


def _owner_name_pointers(data: bytes, msg: wire.DNSMessage) -> List[Tuple[int, int]]:
    """Walk the resource records and return (offset, pointer) for owner names."""
    offset = wire.HEADER_SIZE
    for _ in msg.questions:
        _, offset = wire.decode_name(data, offset)
        offset += 4
    found: List[Tuple[int, int]] = []
    total = msg.header.ancount + msg.header.nscount + msg.header.arcount
    for _ in range(total):
        pos = offset
        while data[pos] != 0 and data[pos] & 0xC0 != 0xC0:   # skip plain labels
            pos += 1 + data[pos]
        if data[pos] & 0xC0 == 0xC0:
            found.append((pos, struct.unpack_from("!H", data, pos)[0]))
        _, offset = wire.decode_name(data, offset)
        (rdlength,) = struct.unpack_from("!H", data, offset + 8)
        offset += 10 + rdlength
    return found


def main() -> None:
    p = argparse.ArgumentParser(description="Capture DNS exchanges to a .pcap file")
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5353)
    p.add_argument("--out", type=pathlib.Path, default=pathlib.Path("docs/capture.pcap"))
    p.add_argument("names", nargs="*", default=["example.com", "example.com", "ads.example-ads.test"])
    args = p.parse_args()

    packets: List[Packet] = []
    for i, name in enumerate(args.names):
        query = wire.encode_message(wire.DNSMessage(
            header=wire.DNSHeader(id=random.randint(0, 0xFFFF), flags=wire.FLAG_RD),
            questions=[wire.DNSQuestion(name, wire.QTYPE_A, wire.QCLASS_IN)]))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.bind(("127.0.0.1", 0))
            cport = s.getsockname()[1]
            t0 = time.time()
            p0 = time.perf_counter()
            s.sendto(query, (args.server, args.port))
            resp, _ = s.recvfrom(65535)
            t1 = time.time()
            ms = (time.perf_counter() - p0) * 1000
        packets.append((t0, "127.0.0.1", cport, args.server, args.port, query))
        packets.append((t1, args.server, args.port, "127.0.0.1", cport, resp))
        print(annotate(f"#{i + 1} query  {name}", query))
        print(annotate(f"#{i + 1} reply  {name} ({ms:.2f} ms)", resp))
        print()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_pcap(args.out, packets)
    print(f"Wrote {len(packets)} packets to {args.out}")


if __name__ == "__main__":
    main()
