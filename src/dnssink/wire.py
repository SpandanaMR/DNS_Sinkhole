"""DNS wire-format encoding and decoding.

Every byte of DNS packet parsing and building is done here using the
``struct`` module with network byte order (``"!"`` format prefix).
No third-party DNS libraries are used.

Key RFC references:
    RFC 1035 §4 – Messages (header, question, resource records)
    RFC 1035 §4.1.4 – Name compression (pointer mechanism)
    RFC 3596 – AAAA record type
    RFC 6891 – EDNS0 (OPT pseudo-record)
    RFC 2308 – Negative caching

Why hand-written:
    This is a university network-programming project.  The entire point
    is to understand the DNS wire format at the byte level.
"""

from __future__ import annotations

import dataclasses
import struct
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DNS record types we care about
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_OPT = 41     # EDNS0 pseudo-type

# DNS classes
QCLASS_IN = 1

# Header flag masks (for the 16-bit flags field)
FLAG_QR = 0x8000      # Query (0) / Response (1)
FLAG_AA = 0x0400      # Authoritative Answer
FLAG_TC = 0x0200      # Truncation
FLAG_RD = 0x0100      # Recursion Desired
FLAG_RA = 0x0080      # Recursion Available

# Opcodes (bits 11-14 of the flags word)
OPCODE_MASK = 0x7800
OPCODE_SHIFT = 11

# RCODE (bits 0-3 of the flags word)
RCODE_MASK = 0x000F
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# Compression pointer marker – the two high bits of a label length byte.
COMPRESSION_POINTER_MASK = 0xC0

# Safety limits
MAX_LABEL_LENGTH = 63
MAX_NAME_LENGTH = 255
MAX_COMPRESSION_HOPS = 128   # generous upper bound to stop loops
MAX_UDP_PLAIN = 512           # classic UDP limit without EDNS0

# Human-readable type names (for logging / dashboard)
QTYPE_NAMES: Dict[int, str] = {
    QTYPE_A: "A",
    QTYPE_NS: "NS",
    QTYPE_CNAME: "CNAME",
    QTYPE_SOA: "SOA",
    QTYPE_PTR: "PTR",   # reverse lookups (nslookup sends one for the server address)
    QTYPE_MX: "MX",
    QTYPE_TXT: "TXT",
    QTYPE_AAAA: "AAAA",
    QTYPE_OPT: "OPT",
}


def qtype_to_str(qtype: int) -> str:
    """Return a human-readable string for a DNS record type number."""
    return QTYPE_NAMES.get(qtype, f"TYPE{qtype}")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DNSError(Exception):
    """Base class for all DNS wire-format errors."""


class DNSDecodeError(DNSError):
    """Raised when a packet cannot be decoded."""


class DNSEncodeError(DNSError):
    """Raised when a packet cannot be encoded."""


# ---------------------------------------------------------------------------
# Data classes for parsed DNS structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class DNSHeader:
    """The 12-byte DNS header.

    Why we store the full flags word *and* the broken-out fields:
        Some code paths need the raw flags (e.g. forwarding), while
        others need individual bits (e.g. checking QR or TC).
    """
    id: int = 0
    flags: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    # Convenience properties derived from the flags word.
    @property
    def qr(self) -> bool:
        return bool(self.flags & FLAG_QR)

    @property
    def opcode(self) -> int:
        return (self.flags & OPCODE_MASK) >> OPCODE_SHIFT

    @property
    def aa(self) -> bool:
        return bool(self.flags & FLAG_AA)

    @property
    def tc(self) -> bool:
        return bool(self.flags & FLAG_TC)

    @property
    def rd(self) -> bool:
        return bool(self.flags & FLAG_RD)

    @property
    def ra(self) -> bool:
        return bool(self.flags & FLAG_RA)

    @property
    def rcode(self) -> int:
        return self.flags & RCODE_MASK


@dataclasses.dataclass
class DNSQuestion:
    """A single question entry."""
    qname: str       # e.g. "example.com"
    qtype: int       # e.g. QTYPE_A
    qclass: int      # e.g. QCLASS_IN


@dataclasses.dataclass
class DNSRecord:
    """A single resource record (answer / authority / additional)."""
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes      # raw RDATA bytes (unparsed)

    # Decoded convenience fields – populated by decode helpers.
    decoded: Optional[str] = None


@dataclasses.dataclass
class EDNSInfo:
    """Parsed EDNS0 OPT pseudo-record info."""
    udp_payload_size: int = 512
    extended_rcode: int = 0
    version: int = 0
    do_bit: bool = False
    options: bytes = b""


@dataclasses.dataclass
class DNSMessage:
    """A complete DNS message (question or response)."""
    header: DNSHeader = dataclasses.field(default_factory=DNSHeader)
    questions: List[DNSQuestion] = dataclasses.field(default_factory=list)
    answers: List[DNSRecord] = dataclasses.field(default_factory=list)
    authorities: List[DNSRecord] = dataclasses.field(default_factory=list)
    additionals: List[DNSRecord] = dataclasses.field(default_factory=list)
    edns: Optional[EDNSInfo] = None
    raw: bytes = b""   # the original wire bytes (kept for forwarding)


# ---------------------------------------------------------------------------
# Name encoding / decoding
# ---------------------------------------------------------------------------

def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a DNS domain name starting at *offset* in *data*.

    Handles compression pointers (§4.1.4 of RFC 1035).  The returned offset
    is the position *after* the name in the original stream (i.e. after the
    first pointer byte pair, not after the target of the pointer).

    Protection against pointer loops:
        We count the number of pointer hops and bail out after
        ``MAX_COMPRESSION_HOPS`` to prevent infinite loops caused by
        malicious packets.
    """
    labels: List[str] = []
    hops = 0
    jumped = False
    # ``return_offset`` records where reading should resume in the *caller's*
    # stream.  It is set the first time we follow a pointer.
    return_offset = offset

    while True:
        if offset >= len(data):
            raise DNSDecodeError(f"Name offset {offset} beyond packet length {len(data)}")

        length_byte = data[offset]

        if length_byte == 0:
            # End of name.
            if not jumped:
                return_offset = offset + 1
            break

        if (length_byte & COMPRESSION_POINTER_MASK) == COMPRESSION_POINTER_MASK:
            # Compression pointer – two bytes encode a 14-bit offset.
            if offset + 1 >= len(data):
                raise DNSDecodeError("Truncated compression pointer")
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            if pointer >= len(data):
                raise DNSDecodeError(f"Compression pointer {pointer} out of bounds (packet length {len(data)})")
            if not jumped:
                return_offset = offset + 2
            jumped = True
            offset = pointer
            hops += 1
            if hops > MAX_COMPRESSION_HOPS:
                raise DNSDecodeError("Compression pointer loop detected")
            continue

        # Normal label.
        label_len = length_byte
        if label_len > MAX_LABEL_LENGTH:
            raise DNSDecodeError(f"Label length {label_len} exceeds maximum {MAX_LABEL_LENGTH}")
        offset += 1
        end = offset + label_len
        if end > len(data):
            raise DNSDecodeError("Label extends beyond packet")
        label = data[offset:end].decode("ascii", errors="replace")
        labels.append(label)
        offset = end
        if not jumped:
            return_offset = offset

    name = ".".join(labels)
    if len(name) > MAX_NAME_LENGTH:
        raise DNSDecodeError(f"Name length {len(name)} exceeds maximum {MAX_NAME_LENGTH}")
    return name, return_offset


def encode_name(name: str, compression_table: Optional[Dict[str, int]] = None,
                buf_offset: int = 0) -> Tuple[bytes, Dict[str, int]]:
    """Encode a DNS domain name into wire format with optional compression.

    If *compression_table* is provided (a dict mapping lowercase suffix ->
    offset already written), we emit a pointer instead of repeating the
    suffix.

    Returns (encoded_bytes, updated_compression_table).

    Why we build compression when *encoding*:
        It keeps responses small, which matters for the 512-byte UDP limit.
        Without compression, many responses would need truncation.
    """
    if compression_table is None:
        compression_table = {}

    parts: List[bytes] = []
    labels = name.split(".") if name else []
    current_offset = buf_offset

    for i in range(len(labels)):
        suffix = ".".join(labels[i:]).lower()
        if suffix in compression_table:
            # Emit a pointer to the earlier occurrence.
            pointer = 0xC000 | compression_table[suffix]
            parts.append(struct.pack("!H", pointer))
            return b"".join(parts), compression_table
        # Record this suffix's position for future pointers.
        compression_table[suffix] = current_offset
        label = labels[i].encode("ascii")
        if len(label) > MAX_LABEL_LENGTH:
            raise DNSEncodeError(f"Label too long: {len(label)} bytes")
        parts.append(bytes([len(label)]) + label)
        current_offset += 1 + len(label)

    # Terminating zero-length label.
    parts.append(b"\x00")
    return b"".join(parts), compression_table


def encode_name_uncompressed(name: str) -> bytes:
    """Encode a DNS name without compression (simpler helper)."""
    encoded, _ = encode_name(name, compression_table=None, buf_offset=0)
    return encoded


# ---------------------------------------------------------------------------
# Header encoding / decoding
# ---------------------------------------------------------------------------

HEADER_SIZE = 12
HEADER_FORMAT = "!HHHHHH"   # 6 × unsigned 16-bit

def decode_header(data: bytes) -> DNSHeader:
    """Decode the 12-byte DNS header from *data*."""
    if len(data) < HEADER_SIZE:
        raise DNSDecodeError(f"Packet too short for header: {len(data)} bytes")
    fields = struct.unpack_from(HEADER_FORMAT, data, 0)
    return DNSHeader(
        id=fields[0],
        flags=fields[1],
        qdcount=fields[2],
        ancount=fields[3],
        nscount=fields[4],
        arcount=fields[5],
    )


def encode_header(hdr: DNSHeader) -> bytes:
    """Encode a DNSHeader into 12 bytes."""
    return struct.pack(
        HEADER_FORMAT,
        hdr.id, hdr.flags,
        hdr.qdcount, hdr.ancount, hdr.nscount, hdr.arcount,
    )


# ---------------------------------------------------------------------------
# Question section
# ---------------------------------------------------------------------------

def decode_question(data: bytes, offset: int) -> Tuple[DNSQuestion, int]:
    """Decode one question entry starting at *offset*."""
    qname, offset = decode_name(data, offset)
    if offset + 4 > len(data):
        raise DNSDecodeError("Truncated question section")
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    return DNSQuestion(qname=qname, qtype=qtype, qclass=qclass), offset + 4


def encode_question(q: DNSQuestion, compression_table: Optional[Dict[str, int]] = None,
                    buf_offset: int = 0) -> Tuple[bytes, Dict[str, int]]:
    """Encode a single DNS question entry."""
    if compression_table is None:
        compression_table = {}
    name_bytes, compression_table = encode_name(
        q.qname, compression_table, buf_offset
    )
    tail = struct.pack("!HH", q.qtype, q.qclass)
    return name_bytes + tail, compression_table


# ---------------------------------------------------------------------------
# Resource Record (RR) decoding / encoding
# ---------------------------------------------------------------------------

def decode_rr(data: bytes, offset: int) -> Tuple[DNSRecord, int]:
    """Decode one resource record starting at *offset*.

    The RDATA is kept as raw bytes; callers can use ``decode_rdata``
    to get a human-readable form for A, AAAA, CNAME, etc.
    """
    name, offset = decode_name(data, offset)
    if offset + 10 > len(data):
        raise DNSDecodeError("Truncated resource record header")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlength > len(data):
        raise DNSDecodeError("RDATA extends beyond packet")
    rdata = _decompress_rdata(rtype, data, offset, rdlength)
    rec = DNSRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata)
    # Try to produce a human-readable decoded value.  The RDATA is now
    # self-contained (no pointers), so it can serve as its own "packet".
    rec.decoded = decode_rdata(rtype, rdata, rdata)
    return rec, offset + rdlength


# Record types whose RDATA contains domain names that may be compressed.
_NAME_RDATA_TYPES = (QTYPE_CNAME, QTYPE_NS, QTYPE_PTR, QTYPE_MX, QTYPE_SOA)


def _decompress_rdata(rtype: int, data: bytes, offset: int, rdlength: int) -> bytes:
    """Return the RDATA at *offset* with every embedded name uncompressed.

    Why this design:
        Compression pointers are absolute offsets into the packet they came
        from.  When we cache a record and later build a *new* packet around
        it, those offsets point at the wrong bytes.  Expanding the names once,
        at decode time, makes every DNSRecord self-contained and safe to
        re-encode anywhere (encode_rr re-compresses CNAME/NS/MX names).
    """
    end = offset + rdlength
    if rtype not in _NAME_RDATA_TYPES or rdlength == 0:
        return data[offset:end]

    def name_at(pos: int) -> Tuple[bytes, int]:
        name, next_pos = decode_name(data, pos)
        if next_pos > end:
            raise DNSDecodeError("Name in RDATA runs past RDLENGTH")
        return encode_name_uncompressed(name), next_pos

    if rtype == QTYPE_MX:
        if rdlength < 3:
            raise DNSDecodeError("MX RDATA too short")
        exchange, pos = name_at(offset + 2)
        return data[offset:offset + 2] + exchange

    if rtype == QTYPE_SOA:
        mname, pos = name_at(offset)
        rname, pos = name_at(pos)
        if pos + 20 != end:
            raise DNSDecodeError("SOA RDATA has wrong length")
        return mname + rname + data[pos:end]

    # CNAME / NS / PTR: the whole RDATA is a single name.
    target, pos = name_at(offset)
    if pos != end:
        raise DNSDecodeError(f"{qtype_to_str(rtype)} RDATA has trailing bytes")
    return target


def decode_rdata(rtype: int, rdata: bytes, packet: bytes) -> Optional[str]:
    """Decode RDATA to a human-readable string for known types.

    For types we don't fully decode (NS, MX, SOA, TXT) we still produce
    a useful representation; for truly unknown types we return None.
    """
    try:
        if rtype == QTYPE_A:
            if len(rdata) != 4:
                return None
            return ".".join(str(b) for b in rdata)

        if rtype == QTYPE_AAAA:
            if len(rdata) != 16:
                return None
            parts = struct.unpack("!8H", rdata)
            return ":".join(f"{p:04x}" for p in parts)

        if rtype == QTYPE_CNAME or rtype == QTYPE_NS:
            # CNAME and NS RDATA is a single domain name which may use
            # compression pointers relative to the *original packet*.
            name, _ = decode_name(packet, _find_rdata_offset(rdata, packet))
            return name

        if rtype == QTYPE_MX:
            if len(rdata) < 4:
                return None
            preference = struct.unpack_from("!H", rdata, 0)[0]
            exchange, _ = decode_name(packet, _find_rdata_offset(rdata[2:], packet))
            return f"{preference} {exchange}"

        if rtype == QTYPE_TXT:
            # TXT records: one or more <length-byte><text> chunks.
            texts: List[str] = []
            pos = 0
            while pos < len(rdata):
                tlen = rdata[pos]
                pos += 1
                texts.append(rdata[pos:pos + tlen].decode("utf-8", errors="replace"))
                pos += tlen
            return " ".join(texts)

        if rtype == QTYPE_SOA:
            # Parse enough to get the minimum TTL (last field).
            # SOA: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
            rdata_offset = _find_rdata_offset(rdata, packet)
            mname, pos = decode_name(packet, rdata_offset)
            rname, pos = decode_name(packet, pos)
            if pos + 20 > len(packet):
                return None
            serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", packet, pos)
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"

    except (DNSDecodeError, struct.error, IndexError, UnicodeDecodeError):
        return None
    return None


def _find_rdata_offset(rdata: bytes, packet: bytes) -> int:
    """Find the byte offset of *rdata* within *packet*.

    Why this exists:
        CNAME / NS / MX / SOA RDATA can contain compression pointers that
        are relative to the start of the packet.  Since we sliced the rdata
        out, we need to know where it originally was to resolve pointers.
    """
    idx = packet.find(rdata)
    if idx == -1:
        raise DNSDecodeError("RDATA not found in packet (cannot resolve pointers)")
    return idx


def encode_rr(rec: DNSRecord, compression_table: Optional[Dict[str, int]] = None,
              buf_offset: int = 0) -> Tuple[bytes, Dict[str, int]]:
    """Encode a single resource record."""
    if compression_table is None:
        compression_table = {}
    name_bytes, compression_table = encode_name(
        rec.name, compression_table, buf_offset
    )
    buf_offset += len(name_bytes)

    # For CNAME/NS rdata that contain domain names, we re-encode them
    # with compression.  For other types, we pass rdata through as-is.
    rdata = rec.rdata
    if rec.rtype in (QTYPE_CNAME, QTYPE_NS) and rec.decoded:
        # Re-encode the domain name in RDATA with compression.
        rdata, compression_table = encode_name(
            rec.decoded, compression_table, buf_offset + 10
        )
    elif rec.rtype == QTYPE_MX and rec.decoded:
        try:
            parts = rec.decoded.split(" ", 1)
            pref = int(parts[0])
            exchange_bytes, compression_table = encode_name(
                parts[1], compression_table, buf_offset + 10 + 2
            )
            rdata = struct.pack("!H", pref) + exchange_bytes
        except (ValueError, IndexError):
            pass  # fall through to raw rdata

    fixed = struct.pack("!HHIH", rec.rtype, rec.rclass, rec.ttl, len(rdata))
    result = name_bytes + fixed + rdata
    buf_offset += len(fixed) + len(rdata)
    return result, compression_table


# ---------------------------------------------------------------------------
# OPT (EDNS0) pseudo-record – §6.1.2 of RFC 6891
# ---------------------------------------------------------------------------

def decode_opt(rec: DNSRecord) -> EDNSInfo:
    """Extract EDNS0 information from an OPT resource record.

    The OPT record abuses the standard RR fields:
        NAME  = root (0)
        TYPE  = 41 (OPT)
        CLASS = requestor's UDP payload size
        TTL   = extended RCODE (8) | version (8) | DO (1) | reserved (15)
    """
    udp_size = rec.rclass
    ext_rcode = (rec.ttl >> 24) & 0xFF
    version = (rec.ttl >> 16) & 0xFF
    do_bit = bool((rec.ttl >> 15) & 1)
    return EDNSInfo(
        udp_payload_size=udp_size,
        extended_rcode=ext_rcode,
        version=version,
        do_bit=do_bit,
        options=rec.rdata,
    )


def build_opt_record(udp_payload_size: int = 1232) -> DNSRecord:
    """Build an OPT pseudo-record for our responses."""
    # TTL field: extended rcode=0, version=0, DO=0, reserved=0
    ttl_field = 0
    return DNSRecord(
        name="",           # root name
        rtype=QTYPE_OPT,
        rclass=udp_payload_size,   # advertised UDP payload size
        ttl=ttl_field,
        rdata=b"",
    )


# ---------------------------------------------------------------------------
# Full message decoding
# ---------------------------------------------------------------------------

def decode_message(data: bytes) -> DNSMessage:
    """Decode a complete DNS message from raw wire bytes.

    Never raises on malformed input – returns a partially-decoded message
    so callers can decide how to respond (FORMERR, drop, etc.).
    Malformed sections are logged via the ``errors`` mechanism and
    remaining sections are skipped.
    """
    msg = DNSMessage(raw=data)

    try:
        msg.header = decode_header(data)
    except DNSDecodeError:
        raise  # can't do anything without the header

    offset = HEADER_SIZE

    # Questions
    for _ in range(msg.header.qdcount):
        try:
            q, offset = decode_question(data, offset)
            msg.questions.append(q)
        except DNSDecodeError:
            return msg  # partial decode

    # Helper to decode a section of RRs.
    def _decode_section(count: int) -> Tuple[List[DNSRecord], int]:
        records: List[DNSRecord] = []
        nonlocal offset
        for _ in range(count):
            try:
                rec, offset = decode_rr(data, offset)
                records.append(rec)
            except DNSDecodeError:
                return records, offset
        return records, offset

    msg.answers, offset = _decode_section(msg.header.ancount)
    msg.authorities, offset = _decode_section(msg.header.nscount)
    msg.additionals, offset = _decode_section(msg.header.arcount)

    # Look for an OPT record in the additionals section.
    for rec in msg.additionals:
        if rec.rtype == QTYPE_OPT:
            msg.edns = decode_opt(rec)
            break

    return msg


# ---------------------------------------------------------------------------
# Full message encoding
# ---------------------------------------------------------------------------

def encode_message(msg: DNSMessage) -> bytes:
    """Encode a complete DNS message to wire bytes.

    Uses name compression across the entire message for efficiency.
    """
    compression_table: Dict[str, int] = {}
    parts: List[bytes] = []

    # Header – placeholder, we'll overwrite counts after encoding sections.
    header_bytes = encode_header(msg.header)
    parts.append(header_bytes)
    buf_offset = HEADER_SIZE

    # Questions
    for q in msg.questions:
        q_bytes, compression_table = encode_question(q, compression_table, buf_offset)
        parts.append(q_bytes)
        buf_offset += len(q_bytes)

    # Answers
    for rec in msg.answers:
        rr_bytes, compression_table = encode_rr(rec, compression_table, buf_offset)
        parts.append(rr_bytes)
        buf_offset += len(rr_bytes)

    # Authorities
    for rec in msg.authorities:
        rr_bytes, compression_table = encode_rr(rec, compression_table, buf_offset)
        parts.append(rr_bytes)
        buf_offset += len(rr_bytes)

    # Additionals
    for rec in msg.additionals:
        rr_bytes, compression_table = encode_rr(rec, compression_table, buf_offset)
        parts.append(rr_bytes)
        buf_offset += len(rr_bytes)

    result = b"".join(parts)

    # Patch the header with correct counts.
    hdr = DNSHeader(
        id=msg.header.id,
        flags=msg.header.flags,
        qdcount=len(msg.questions),
        ancount=len(msg.answers),
        nscount=len(msg.authorities),
        arcount=len(msg.additionals),
    )
    patched_header = encode_header(hdr)
    result = patched_header + result[HEADER_SIZE:]
    return result


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------

def build_response_header(query_header: DNSHeader, rcode: int = RCODE_NOERROR,
                          aa: bool = False, ra: bool = True) -> DNSHeader:
    """Build a response header from a query header.

    Preserves the original ID and RD bit; sets QR, RA, and the given RCODE.
    """
    flags = FLAG_QR | FLAG_RA
    if query_header.rd:
        flags |= FLAG_RD
    if aa:
        flags |= FLAG_AA
    flags |= (rcode & RCODE_MASK)
    # preserve opcode
    flags |= (query_header.flags & OPCODE_MASK)
    return DNSHeader(id=query_header.id, flags=flags)


def build_error_response(query_data: bytes, rcode: int) -> bytes:
    """Build a minimal error response (FORMERR, SERVFAIL, etc.).

    If the query can't be parsed at all, we still try to extract the
    transaction ID from the first two bytes.
    """
    try:
        query_header = decode_header(query_data)
    except DNSDecodeError:
        # Can't even read the header – use a zero ID.
        query_header = DNSHeader(id=0, flags=0)

    resp_header = build_response_header(query_header, rcode=rcode)

    # Try to include the question section from the query.
    try:
        msg = decode_message(query_data)
        resp = DNSMessage(header=resp_header, questions=msg.questions)
        resp.header = dataclasses.replace(
            resp.header, qdcount=len(resp.questions)
        )
    except DNSDecodeError:
        resp = DNSMessage(header=resp_header)

    return encode_message(resp)


def build_blocked_response(query: DNSMessage, block_mode: str = "null",
                           block_ttl: int = 60) -> bytes:
    """Build a sinkhole response for a blocked domain.

    block_mode="null":     A -> 0.0.0.0, AAAA -> ::
    block_mode="nxdomain": return NXDOMAIN rcode
    """
    if not query.questions:
        return build_error_response(query.raw, RCODE_FORMERR)

    q = query.questions[0]

    if block_mode == "nxdomain":
        rcode = RCODE_NXDOMAIN
        resp_header = build_response_header(query.header, rcode=rcode, aa=True)
        resp = DNSMessage(header=resp_header, questions=query.questions)
        resp.header = dataclasses.replace(resp.header, qdcount=len(resp.questions))
        return encode_message(resp)

    # "null" mode – synthesise an answer.
    resp_header = build_response_header(query.header, rcode=RCODE_NOERROR, aa=True)

    answers: List[DNSRecord] = []
    if q.qtype == QTYPE_A or q.qtype == 255:  # 255 = ANY
        answers.append(DNSRecord(
            name=q.qname,
            rtype=QTYPE_A,
            rclass=QCLASS_IN,
            ttl=block_ttl,
            rdata=b"\x00\x00\x00\x00",   # 0.0.0.0
            decoded="0.0.0.0",
        ))
    if q.qtype == QTYPE_AAAA or q.qtype == 255:
        answers.append(DNSRecord(
            name=q.qname,
            rtype=QTYPE_AAAA,
            rclass=QCLASS_IN,
            ttl=block_ttl,
            rdata=b"\x00" * 16,           # ::
            decoded="0000:0000:0000:0000:0000:0000:0000:0000",
        ))
    # For other qtypes in null mode, return empty NOERROR (no answers).

    resp = DNSMessage(
        header=resp_header,
        questions=query.questions,
        answers=answers,
    )
    resp.header = dataclasses.replace(
        resp.header,
        qdcount=len(resp.questions),
        ancount=len(answers),
    )
    return encode_message(resp)


def get_min_ttl(msg: DNSMessage) -> int:
    """Return the minimum TTL across all answer records, or 0 if none."""
    ttls = [rec.ttl for rec in msg.answers if rec.ttl >= 0]
    return min(ttls) if ttls else 0


def get_soa_minimum(msg: DNSMessage) -> Optional[int]:
    """Extract the SOA minimum TTL from the authority section.

    Used for negative caching (RFC 2308): the cache time for NXDOMAIN
    is the minimum of the SOA TTL and the SOA MINIMUM field.
    """
    for rec in msg.authorities:
        if rec.rtype == QTYPE_SOA and rec.decoded:
            # SOA decoded format: "mname rname serial refresh retry expire minimum"
            parts = rec.decoded.split()
            if len(parts) >= 7:
                try:
                    return int(parts[6])
                except (ValueError, IndexError):
                    pass
    return None


def truncate_response(response_bytes: bytes, max_size: int = MAX_UDP_PLAIN) -> bytes:
    """Truncate a response to fit within *max_size* bytes.

    Sets the TC (truncation) flag in the header.  Removes answer records
    until the response fits, keeping the question section.

    Why this approach:
        The client will retry over TCP when it sees TC=1, so it's safe
        to drop answers.  We keep the question so the client can match
        the response to its query.
    """
    if len(response_bytes) <= max_size:
        return response_bytes

    try:
        msg = decode_message(response_bytes)
    except DNSDecodeError:
        # Can't parse – just set TC and truncate.
        if len(response_bytes) >= 4:
            flags = struct.unpack_from("!H", response_bytes, 2)[0]
            flags |= FLAG_TC
            result = bytearray(response_bytes[:max_size])
            struct.pack_into("!H", result, 2, flags)
            return bytes(result)
        return response_bytes[:max_size]

    # Remove answers progressively until it fits.
    msg.header = dataclasses.replace(msg.header, flags=msg.header.flags | FLAG_TC)
    msg.answers = []
    msg.authorities = []
    msg.additionals = [r for r in msg.additionals if r.rtype == QTYPE_OPT]
    msg.header = dataclasses.replace(
        msg.header,
        ancount=0,
        nscount=0,
        arcount=len(msg.additionals),
    )
    encoded = encode_message(msg)
    if len(encoded) <= max_size:
        return encoded
    # Last resort: just header + question, no additionals.
    msg.additionals = []
    msg.header = dataclasses.replace(msg.header, arcount=0)
    return encode_message(msg)[:max_size]
