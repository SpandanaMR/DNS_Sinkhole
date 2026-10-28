"""Fuzz tests: send 10,000 random and mutated packets to the DNS parser.

Goal: zero crashes and zero hangs.

Strategy:
    1. Pure random bytes (various lengths from 0 to 1024).
    2. Valid header + random body.
    3. Mutated real packets (bit flips, truncation, extension).
    4. Pathological cases (huge counts, pointer loops, overlong labels).
"""

from __future__ import annotations

import os
import pathlib
import random
import struct
import time

import pytest

import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire


# Seed for reproducibility.
FUZZ_SEED = int(os.environ.get("FUZZ_SEED", "42"))
NUM_PACKETS = 10000
TIMEOUT_PER_PACKET = 0.1  # seconds – if any single decode takes longer, it's a hang


def _random_bytes(max_len: int = 1024) -> bytes:
    length = random.randint(0, max_len)
    return bytes(random.getrandbits(8) for _ in range(length))


def _build_valid_query() -> bytes:
    """Build a syntactically valid DNS query."""
    hdr = struct.pack("!HHHHHH",
                      random.randint(0, 0xFFFF),  # ID
                      wire.FLAG_RD,                 # flags
                      1, 0, 0, 0)                   # qdcount=1
    name = wire.encode_name_uncompressed("example.com")
    question = name + struct.pack("!HH", wire.QTYPE_A, wire.QCLASS_IN)
    return hdr + question


def _mutate(data: bytes) -> bytes:
    """Apply random mutations to a packet."""
    if not data:
        return data
    result = bytearray(data)
    mutations = random.randint(1, 5)
    for _ in range(mutations):
        op = random.choice(["flip", "truncate", "extend", "zero", "insert"])
        if op == "flip" and result:
            idx = random.randint(0, len(result) - 1)
            result[idx] ^= (1 << random.randint(0, 7))
        elif op == "truncate" and len(result) > 1:
            result = result[:random.randint(1, len(result) - 1)]
        elif op == "extend":
            extra = bytes(random.getrandbits(8) for _ in range(random.randint(1, 100)))
            result.extend(extra)
        elif op == "zero" and result:
            idx = random.randint(0, len(result) - 1)
            result[idx] = 0
        elif op == "insert" and result:
            idx = random.randint(0, len(result))
            result.insert(idx, random.randint(0, 255))
    return bytes(result)


class TestFuzz:
    """Fuzz the DNS wire-format parser with random and mutated packets."""

    def test_fuzz_random_packets(self) -> None:
        """Send purely random bytes to decode_message."""
        random.seed(FUZZ_SEED)
        crashes = 0
        hangs = 0

        for i in range(NUM_PACKETS // 2):
            data = _random_bytes()
            start = time.monotonic()
            try:
                wire.decode_message(data)
            except (wire.DNSDecodeError, wire.DNSError):
                pass  # expected for garbage
            except Exception as e:
                crashes += 1
            elapsed = time.monotonic() - start
            if elapsed > TIMEOUT_PER_PACKET:
                hangs += 1

        assert crashes == 0, f"{crashes} crashes on random packets"
        assert hangs == 0, f"{hangs} hangs (>{TIMEOUT_PER_PACKET}s) on random packets"

    def test_fuzz_mutated_packets(self) -> None:
        """Mutate valid packets and send to decode_message."""
        random.seed(FUZZ_SEED + 1)
        base_query = _build_valid_query()
        crashes = 0
        hangs = 0

        for i in range(NUM_PACKETS // 2):
            data = _mutate(base_query)
            start = time.monotonic()
            try:
                wire.decode_message(data)
            except (wire.DNSDecodeError, wire.DNSError):
                pass
            except Exception as e:
                crashes += 1
            elapsed = time.monotonic() - start
            if elapsed > TIMEOUT_PER_PACKET:
                hangs += 1

        assert crashes == 0, f"{crashes} crashes on mutated packets"
        assert hangs == 0, f"{hangs} hangs on mutated packets"

    def test_pathological_header_counts(self) -> None:
        """Headers claiming huge record counts should not crash or hang."""
        random.seed(FUZZ_SEED + 2)
        for _ in range(200):
            hdr = struct.pack("!HHHHHH",
                              random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF),
                              random.randint(0, 0xFFFF))
            body = _random_bytes(200)
            data = hdr + body
            try:
                wire.decode_message(data)
            except (wire.DNSDecodeError, wire.DNSError):
                pass

    def test_pointer_loops_dont_hang(self) -> None:
        """Various pointer loop patterns should be caught, not infinite-loop."""
        patterns = [
            # Self-referencing pointer at offset 12
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + struct.pack("!H", 0xC00C),
            # Two pointers pointing at each other
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + struct.pack("!HH", 0xC00E, 0xC00C),
            # Long chain of pointers
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
            b"".join(struct.pack("!H", 0xC000 | (12 + i * 2 + 2)) for i in range(50)) +
            struct.pack("!H", 0xC00C),  # loop back
        ]
        for data in patterns:
            start = time.monotonic()
            try:
                wire.decode_message(data)
            except (wire.DNSDecodeError, wire.DNSError):
                pass
            elapsed = time.monotonic() - start
            assert elapsed < 1.0, f"Pointer loop took {elapsed:.2f}s"

    def test_empty_packet(self) -> None:
        """Empty packet should raise, not crash."""
        with pytest.raises(wire.DNSDecodeError):
            wire.decode_message(b"")

    def test_one_byte_packet(self) -> None:
        """Single byte packet."""
        with pytest.raises(wire.DNSDecodeError):
            wire.decode_message(b"\xff")

    def test_header_only_packet(self) -> None:
        """Just a 12-byte header with qdcount=1 but no question data."""
        data = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # Should not crash – partial decode is fine.
        try:
            msg = wire.decode_message(data)
        except wire.DNSDecodeError:
            pass

    def test_overlong_label(self) -> None:
        """A label claiming 63 bytes but actually only having 5."""
        data = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        data += bytes([63]) + b"hello"
        try:
            wire.decode_message(data)
        except wire.DNSDecodeError:
            pass

    def test_build_error_response_on_garbage(self) -> None:
        """build_error_response should handle any input without crashing."""
        for _ in range(100):
            data = _random_bytes(50)
            resp = wire.build_error_response(data, wire.RCODE_FORMERR)
            assert isinstance(resp, bytes)
            assert len(resp) >= wire.HEADER_SIZE
