"""Unit tests for wire.py: DNS packet encoding/decoding.

Tests cover:
    - Header encode/decode round-trip
    - Name encode/decode with and without compression
    - Compression pointer handling (normal, loops, out-of-bounds)
    - Question encode/decode
    - Resource record encode/decode (A, AAAA, CNAME)
    - Full message decode of hand-built packets
    - Blocked response building (null mode and nxdomain mode)
    - Error response building
    - Truncation
    - Malformed packet handling (too short, truncated, bad labels)
"""

from __future__ import annotations

import struct
import pytest

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire


# ---------------------------------------------------------------------------
# Helper: build raw packets by hand
# ---------------------------------------------------------------------------

def _build_header(
    txn_id: int = 0x1234,
    flags: int = 0,
    qdcount: int = 0,
    ancount: int = 0,
    nscount: int = 0,
    arcount: int = 0,
) -> bytes:
    return struct.pack("!HHHHHH", txn_id, flags, qdcount, ancount, nscount, arcount)


def _encode_name_raw(name: str) -> bytes:
    """Encode a name without compression (for test packet building)."""
    parts = []
    for label in name.split("."):
        encoded = label.encode("ascii")
        parts.append(bytes([len(encoded)]) + encoded)
    parts.append(b"\x00")
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Header tests
# ---------------------------------------------------------------------------

class TestHeader:
    def test_decode_basic(self) -> None:
        raw = _build_header(txn_id=0xABCD, flags=0x8180, qdcount=1, ancount=2)
        hdr = wire.decode_header(raw)
        assert hdr.id == 0xABCD
        assert hdr.qr is True       # bit 15
        assert hdr.rd is True       # bit 8
        assert hdr.ra is True       # bit 7
        assert hdr.rcode == 0
        assert hdr.qdcount == 1
        assert hdr.ancount == 2

    def test_encode_roundtrip(self) -> None:
        hdr = wire.DNSHeader(id=0x5678, flags=0x0100, qdcount=1)
        encoded = wire.encode_header(hdr)
        decoded = wire.decode_header(encoded)
        assert decoded.id == 0x5678
        assert decoded.rd is True
        assert decoded.qdcount == 1

    def test_too_short_raises(self) -> None:
        with pytest.raises(wire.DNSDecodeError):
            wire.decode_header(b"\x00" * 5)

    def test_rcode_extraction(self) -> None:
        raw = _build_header(flags=wire.FLAG_QR | wire.RCODE_NXDOMAIN)
        hdr = wire.decode_header(raw)
        assert hdr.rcode == wire.RCODE_NXDOMAIN
        assert hdr.qr is True

    def test_opcode_extraction(self) -> None:
        flags = (2 << wire.OPCODE_SHIFT) | wire.FLAG_RD
        raw = _build_header(flags=flags)
        hdr = wire.decode_header(raw)
        assert hdr.opcode == 2
        assert hdr.rd is True


# ---------------------------------------------------------------------------
# Name encoding / decoding tests
# ---------------------------------------------------------------------------

class TestNameCoding:
    def test_simple_name(self) -> None:
        raw = _encode_name_raw("example.com")
        name, offset = wire.decode_name(raw, 0)
        assert name == "example.com"
        assert offset == len(raw)

    def test_root_name(self) -> None:
        raw = b"\x00"
        name, offset = wire.decode_name(raw, 0)
        assert name == ""
        assert offset == 1

    def test_single_label(self) -> None:
        raw = _encode_name_raw("localhost")
        name, offset = wire.decode_name(raw, 0)
        assert name == "localhost"

    def test_encode_uncompressed_roundtrip(self) -> None:
        original = "www.example.com"
        encoded = wire.encode_name_uncompressed(original)
        decoded, _ = wire.decode_name(encoded, 0)
        assert decoded == original

    def test_compression_pointer(self) -> None:
        # Build a packet with name at offset 12, then a pointer at offset 28.
        name_bytes = _encode_name_raw("example.com")  # 13 bytes
        # Position the pointer at the end.
        pointer = struct.pack("!H", 0xC000 | 0)   # point to offset 0
        packet = name_bytes + pointer
        # Decode the pointer.
        name, offset = wire.decode_name(packet, len(name_bytes))
        assert name == "example.com"
        assert offset == len(name_bytes) + 2  # past the pointer bytes

    def test_pointer_loop_detection(self) -> None:
        # Two pointers pointing at each other.
        packet = struct.pack("!HH", 0xC002, 0xC000)
        with pytest.raises(wire.DNSDecodeError, match="loop"):
            wire.decode_name(packet, 0)

    def test_pointer_out_of_bounds(self) -> None:
        packet = struct.pack("!H", 0xC0FF)  # points to offset 255
        with pytest.raises(wire.DNSDecodeError, match="out of bounds"):
            wire.decode_name(packet, 0)

    def test_label_too_long(self) -> None:
        # A label claiming 64 bytes.
        packet = bytes([64]) + b"x" * 64 + b"\x00"
        with pytest.raises(wire.DNSDecodeError, match="Label length"):
            wire.decode_name(packet, 0)

    def test_truncated_label(self) -> None:
        # Label says 10 bytes but only 5 available.
        packet = bytes([10]) + b"abcde"
        with pytest.raises(wire.DNSDecodeError, match="beyond packet"):
            wire.decode_name(packet, 0)

    def test_compression_table_reuse(self) -> None:
        """Encoding two names sharing a suffix should produce a pointer."""
        table: dict = {}
        name1_bytes, table = wire.encode_name("www.example.com", table, 0)
        name2_bytes, table = wire.encode_name("mail.example.com", table, len(name1_bytes))
        # The second encoding should be shorter due to compression.
        assert len(name2_bytes) < len(_encode_name_raw("mail.example.com"))
        # Verify we can decode both.
        combined = name1_bytes + name2_bytes
        n1, off1 = wire.decode_name(combined, 0)
        assert n1 == "www.example.com"
        n2, off2 = wire.decode_name(combined, len(name1_bytes))
        assert n2 == "mail.example.com"


# ---------------------------------------------------------------------------
# Question tests
# ---------------------------------------------------------------------------

class TestQuestion:
    def test_decode_question(self) -> None:
        name_bytes = _encode_name_raw("example.com")
        q_bytes = name_bytes + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
        q, offset = wire.decode_question(q_bytes, 0)
        assert q.qname == "example.com"
        assert q.qtype == wire.QTYPE_A
        assert q.qclass == wire.QCLASS_IN

    def test_encode_roundtrip(self) -> None:
        q = wire.DNSQuestion(qname="test.example.com", qtype=wire.QTYPE_AAAA, qclass=wire.QCLASS_IN)
        encoded, _ = wire.encode_question(q)
        decoded, _ = wire.decode_question(encoded, 0)
        assert decoded.qname == q.qname
        assert decoded.qtype == q.qtype
        assert decoded.qclass == q.qclass

    def test_truncated_question(self) -> None:
        name_bytes = _encode_name_raw("example.com")
        q_bytes = name_bytes + b"\x00"  # missing qtype and qclass
        with pytest.raises(wire.DNSDecodeError, match="Truncated"):
            wire.decode_question(q_bytes, 0)


# ---------------------------------------------------------------------------
# Resource Record tests
# ---------------------------------------------------------------------------

class TestResourceRecord:
    def _build_a_record(self, name: str, ip: str, ttl: int = 300) -> bytes:
        """Build a raw A record."""
        name_bytes = _encode_name_raw(name)
        ip_parts = [int(p) for p in ip.split(".")]
        rdata = bytes(ip_parts)
        return name_bytes + struct.pack("!HHIH", wire.QTYPE_A, wire.QCLASS_IN, ttl, len(rdata)) + rdata

    def _build_aaaa_record(self, name: str, ttl: int = 300) -> bytes:
        """Build a raw AAAA record (all zeros = ::)."""
        name_bytes = _encode_name_raw(name)
        rdata = b"\x00" * 16
        return name_bytes + struct.pack("!HHIH", wire.QTYPE_AAAA, wire.QCLASS_IN, ttl, len(rdata)) + rdata

    def test_decode_a_record(self) -> None:
        raw = self._build_a_record("example.com", "93.184.216.34")
        rec, offset = wire.decode_rr(raw, 0)
        assert rec.name == "example.com"
        assert rec.rtype == wire.QTYPE_A
        assert rec.ttl == 300
        assert rec.decoded == "93.184.216.34"

    def test_decode_aaaa_record(self) -> None:
        raw = self._build_aaaa_record("example.com")
        rec, offset = wire.decode_rr(raw, 0)
        assert rec.name == "example.com"
        assert rec.rtype == wire.QTYPE_AAAA
        assert rec.decoded is not None
        assert "0000" in rec.decoded

    def test_truncated_rr(self) -> None:
        name_bytes = _encode_name_raw("example.com")
        # Only 5 bytes of the 10-byte fixed header.
        raw = name_bytes + b"\x00" * 5
        with pytest.raises(wire.DNSDecodeError, match="Truncated"):
            wire.decode_rr(raw, 0)

    def test_rdata_beyond_packet(self) -> None:
        name_bytes = _encode_name_raw("example.com")
        # Claim 100 bytes of rdata but only provide 4.
        raw = name_bytes + struct.pack("!HHIH", wire.QTYPE_A, wire.QCLASS_IN, 300, 100) + b"\x00" * 4
        with pytest.raises(wire.DNSDecodeError, match="RDATA extends"):
            wire.decode_rr(raw, 0)


# ---------------------------------------------------------------------------
# Full message tests
# ---------------------------------------------------------------------------

class TestMessage:
    def test_decode_simple_query(self) -> None:
        """Build a simple A query for example.com by hand."""
        header = _build_header(txn_id=0x1234, flags=wire.FLAG_RD, qdcount=1)
        question = _encode_name_raw("example.com") + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
        packet = header + question

        msg = wire.decode_message(packet)
        assert msg.header.id == 0x1234
        assert msg.header.rd is True
        assert msg.header.qr is False
        assert len(msg.questions) == 1
        assert msg.questions[0].qname == "example.com"
        assert msg.questions[0].qtype == wire.QTYPE_A

    def test_decode_response_with_answer(self) -> None:
        """Build a response with one A answer record by hand."""
        header = _build_header(
            txn_id=0x1234,
            flags=wire.FLAG_QR | wire.FLAG_RD | wire.FLAG_RA,
            qdcount=1, ancount=1,
        )
        question = _encode_name_raw("example.com") + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
        # Answer: name (with pointer to question name at offset 12), A, IN, TTL=300, 4 bytes rdata
        answer_name = struct.pack("!H", 0xC00C)  # pointer to offset 12 (start of question name)
        answer = answer_name + struct.pack("!HHIH", wire.QTYPE_A, wire.QCLASS_IN, 300, 4)
        answer += bytes([93, 184, 216, 34])
        packet = header + question + answer

        msg = wire.decode_message(packet)
        assert msg.header.qr is True
        assert len(msg.answers) == 1
        assert msg.answers[0].decoded == "93.184.216.34"
        assert msg.answers[0].ttl == 300

    def test_encode_decode_roundtrip(self) -> None:
        """Create a message, encode it, decode it, verify."""
        q = wire.DNSQuestion(qname="test.example.com", qtype=wire.QTYPE_A, qclass=wire.QCLASS_IN)
        hdr = wire.DNSHeader(id=0x5678, flags=wire.FLAG_QR | wire.FLAG_RD | wire.FLAG_RA,
                              qdcount=1, ancount=1)
        answer = wire.DNSRecord(
            name="test.example.com", rtype=wire.QTYPE_A, rclass=wire.QCLASS_IN,
            ttl=120, rdata=bytes([10, 0, 0, 1]), decoded="10.0.0.1",
        )
        msg = wire.DNSMessage(header=hdr, questions=[q], answers=[answer])
        encoded = wire.encode_message(msg)
        decoded = wire.decode_message(encoded)
        assert decoded.header.id == 0x5678
        assert len(decoded.questions) == 1
        assert decoded.questions[0].qname == "test.example.com"
        assert len(decoded.answers) == 1
        assert decoded.answers[0].decoded == "10.0.0.1"

    def test_nxdomain_response(self) -> None:
        """Build an NXDOMAIN response by hand."""
        header = _build_header(
            txn_id=0xAAAA,
            flags=wire.FLAG_QR | wire.FLAG_RD | wire.FLAG_RA | wire.RCODE_NXDOMAIN,
            qdcount=1,
        )
        question = _encode_name_raw("nonexistent.example.com") + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
        packet = header + question
        msg = wire.decode_message(packet)
        assert msg.header.rcode == wire.RCODE_NXDOMAIN
        assert len(msg.answers) == 0

    def test_cname_chain(self) -> None:
        """Build a response with a CNAME chain: www -> cdn -> actual A."""
        header = _build_header(
            txn_id=0xBBBB,
            flags=wire.FLAG_QR | wire.FLAG_RD | wire.FLAG_RA,
            qdcount=1, ancount=3,
        )
        q_name = _encode_name_raw("www.example.com")
        question = q_name + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
        base = header + question
        base_len = len(base)

        # CNAME record: www.example.com -> cdn.example.com (no compression for simplicity)
        cname_target = _encode_name_raw("cdn.example.com")
        cname_rr = _encode_name_raw("www.example.com") + struct.pack("!HHIH", wire.QTYPE_CNAME, wire.QCLASS_IN, 600, len(cname_target)) + cname_target

        # Second CNAME: cdn.example.com -> actual.example.com
        cname2_target = _encode_name_raw("actual.example.com")
        cname2_rr = _encode_name_raw("cdn.example.com") + struct.pack("!HHIH", wire.QTYPE_CNAME, wire.QCLASS_IN, 600, len(cname2_target)) + cname2_target

        # A record: actual.example.com -> 1.2.3.4
        a_rr = _encode_name_raw("actual.example.com") + struct.pack("!HHIH", wire.QTYPE_A, wire.QCLASS_IN, 300, 4) + bytes([1, 2, 3, 4])

        packet = base + cname_rr + cname2_rr + a_rr
        msg = wire.decode_message(packet)
        assert len(msg.answers) == 3
        assert msg.answers[0].rtype == wire.QTYPE_CNAME
        assert msg.answers[1].rtype == wire.QTYPE_CNAME
        assert msg.answers[2].rtype == wire.QTYPE_A
        assert msg.answers[2].decoded == "1.2.3.4"


# ---------------------------------------------------------------------------
# Blocked response tests
# ---------------------------------------------------------------------------

class TestBlockedResponse:
    def _make_query(self, qname: str, qtype: int = wire.QTYPE_A) -> wire.DNSMessage:
        hdr = wire.DNSHeader(id=0x1111, flags=wire.FLAG_RD, qdcount=1)
        q = wire.DNSQuestion(qname=qname, qtype=qtype, qclass=wire.QCLASS_IN)
        msg = wire.DNSMessage(header=hdr, questions=[q])
        msg.raw = wire.encode_message(msg)
        return msg

    def test_null_block_a(self) -> None:
        query = self._make_query("ads.example.com", wire.QTYPE_A)
        resp_bytes = wire.build_blocked_response(query, block_mode="null", block_ttl=60)
        resp = wire.decode_message(resp_bytes)
        assert resp.header.qr is True
        assert resp.header.rcode == wire.RCODE_NOERROR
        assert len(resp.answers) == 1
        assert resp.answers[0].decoded == "0.0.0.0"
        assert resp.answers[0].ttl == 60

    def test_null_block_aaaa(self) -> None:
        query = self._make_query("ads.example.com", wire.QTYPE_AAAA)
        resp_bytes = wire.build_blocked_response(query, block_mode="null")
        resp = wire.decode_message(resp_bytes)
        assert len(resp.answers) == 1
        assert "0000" in resp.answers[0].decoded

    def test_nxdomain_block(self) -> None:
        query = self._make_query("ads.example.com", wire.QTYPE_A)
        resp_bytes = wire.build_blocked_response(query, block_mode="nxdomain")
        resp = wire.decode_message(resp_bytes)
        assert resp.header.rcode == wire.RCODE_NXDOMAIN
        assert len(resp.answers) == 0


# ---------------------------------------------------------------------------
# Error response tests
# ---------------------------------------------------------------------------

class TestErrorResponse:
    def test_formerr(self) -> None:
        query_data = _build_header(txn_id=0x9999, flags=wire.FLAG_RD, qdcount=1)
        query_data += _encode_name_raw("example.com") + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
        resp_bytes = wire.build_error_response(query_data, wire.RCODE_FORMERR)
        resp = wire.decode_message(resp_bytes)
        assert resp.header.id == 0x9999
        assert resp.header.rcode == wire.RCODE_FORMERR
        assert resp.header.qr is True

    def test_servfail(self) -> None:
        query_data = _build_header(txn_id=0x7777) + b"\x00" * 4
        resp_bytes = wire.build_error_response(query_data, wire.RCODE_SERVFAIL)
        resp = wire.decode_message(resp_bytes)
        assert resp.header.rcode == wire.RCODE_SERVFAIL

    def test_broken_query(self) -> None:
        """Even a completely broken query should produce some response."""
        resp_bytes = wire.build_error_response(b"\x00\x01", wire.RCODE_FORMERR)
        resp = wire.decode_message(resp_bytes)
        assert resp.header.qr is True


# ---------------------------------------------------------------------------
# Truncation tests
# ---------------------------------------------------------------------------

class TestTruncation:
    def test_no_truncation_needed(self) -> None:
        small = b"\x00" * 100
        result = wire.truncate_response(small, 512)
        assert result == small

    def test_truncation_sets_tc_flag(self) -> None:
        # Build a large response.
        hdr = wire.DNSHeader(id=0x3333, flags=wire.FLAG_QR | wire.FLAG_RD | wire.FLAG_RA,
                              qdcount=1, ancount=10)
        q = wire.DNSQuestion(qname="example.com", qtype=wire.QTYPE_TXT, qclass=wire.QCLASS_IN)
        answers = []
        for i in range(10):
            txt_data = (f"long text record number {i} " * 5).encode("utf-8")
            rdata = bytes([len(txt_data)]) + txt_data
            answers.append(wire.DNSRecord(
                name="example.com", rtype=wire.QTYPE_TXT, rclass=wire.QCLASS_IN,
                ttl=300, rdata=rdata,
            ))
        msg = wire.DNSMessage(header=hdr, questions=[q], answers=answers)
        encoded = wire.encode_message(msg)
        assert len(encoded) > 512

        truncated = wire.truncate_response(encoded, 512)
        assert len(truncated) <= 512
        trunc_msg = wire.decode_message(truncated)
        assert trunc_msg.header.tc is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_packet(self) -> None:
        with pytest.raises(wire.DNSDecodeError):
            wire.decode_message(b"")

    def test_header_only(self) -> None:
        raw = _build_header(qdcount=0)
        msg = wire.decode_message(raw)
        assert len(msg.questions) == 0

    def test_txt_record_decoding(self) -> None:
        """Build a TXT record and verify decoding."""
        name_bytes = _encode_name_raw("example.com")
        txt = b"v=spf1 include:example.com ~all"
        rdata = bytes([len(txt)]) + txt
        raw = name_bytes + struct.pack("!HHIH", wire.QTYPE_TXT, wire.QCLASS_IN, 300, len(rdata)) + rdata
        rec, _ = wire.decode_rr(raw, 0)
        assert rec.rtype == wire.QTYPE_TXT
        assert "spf1" in rec.decoded

    def test_qtype_to_str(self) -> None:
        assert wire.qtype_to_str(wire.QTYPE_A) == "A"
        assert wire.qtype_to_str(wire.QTYPE_AAAA) == "AAAA"
        assert wire.qtype_to_str(999) == "TYPE999"


# ---------------------------------------------------------------------------
# Re-encoding records whose RDATA contains compressed names
# ---------------------------------------------------------------------------

def _nodata_packet_with_rdata_pointers() -> bytes:
    """Hand-built NODATA response whose SOA RDATA points into an NS RDATA.

    Layout (offsets in brackets):
      [12] question  example.com A IN
      [29] NS   owner example.com (uncompressed), RDATA ns1.zone.test at [52]
      [67] SOA  owner -> 0xC00C, MNAME -> 0xC034 (=52, ns1.zone.test),
                RNAME "admin" + pointer -> 0xC038 (=56, zone.test)
    When this message is re-encoded, the NS owner gets compressed and the
    NS RDATA moves, so raw SOA RDATA pointers would point at garbage.
    """
    hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 2, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    ns_rdata = b"\x03ns1\x04zone\x04test\x00"
    ns_rr = (b"\x07example\x03com\x00" + struct.pack("!HHIH", 2, 1, 3600, len(ns_rdata))
             + ns_rdata)
    soa_rdata = (struct.pack("!H", 0xC000 | 52) + b"\x05admin" + struct.pack("!H", 0xC000 | 56)
                 + struct.pack("!IIIII", 2024010101, 7200, 900, 1209600, 300))
    soa_rr = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 6, 1, 3600, len(soa_rdata)) + soa_rdata
    packet = hdr + question + ns_rr + soa_rr
    assert packet.index(ns_rdata) == 52  # guard the hand-computed offsets
    return packet


def test_reencode_preserves_soa_with_rdata_pointers() -> None:
    """Decode -> encode -> decode must keep SOA names intact (cache-hit path)."""
    original = wire.decode_message(_nodata_packet_with_rdata_pointers())
    soa = original.authorities[1]
    assert soa.decoded == "ns1.zone.test admin.zone.test 2024010101 7200 900 1209600 300"

    rebuilt = wire.decode_message(wire.encode_message(original))
    assert [r.decoded for r in rebuilt.authorities] == [r.decoded for r in original.authorities]
    assert wire.get_soa_minimum(rebuilt) == 300


def test_reencode_preserves_ptr_rdata() -> None:
    """PTR RDATA that uses a pointer must survive re-encoding too."""
    hdr = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    qname = b"\x011\x010\x010\x03127\x07in-addr\x04arpa\x00"
    question = qname + struct.pack("!HH", 12, 1)
    # RDATA "localhost.arpa" written as "localhost" + pointer to the "arpa" label.
    arpa_offset = 12 + qname.index(b"\x04arpa")
    ptr_rdata = b"\x09localhost" + struct.pack("!H", 0xC000 | arpa_offset)
    answer = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 12, 1, 60, len(ptr_rdata)) + ptr_rdata
    msg = wire.decode_message(hdr + question + answer)
    # Prepend an extra answer so every later offset shifts on re-encode.
    extra = wire.DNSRecord(name="pad.example", rtype=wire.QTYPE_A, rclass=1, ttl=60,
                           rdata=bytes(4), decoded="0.0.0.0")
    msg.answers.insert(0, extra)
    rebuilt = wire.decode_message(wire.encode_message(msg))
    assert wire.decode_name(rebuilt.answers[1].rdata, 0)[0] == "localhost.arpa"
