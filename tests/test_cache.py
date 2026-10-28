"""Unit tests for cache.py: TTL decay, LRU eviction, negative caching, thread safety."""

from __future__ import annotations

import dataclasses
import pathlib
import struct
import threading
import time

import pytest

import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire
from dnssink.cache import CacheEntry, DNSCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(qname: str, qtype: int = wire.QTYPE_A,
                   rcode: int = wire.RCODE_NOERROR,
                   answers: list[wire.DNSRecord] | None = None,
                   authorities: list[wire.DNSRecord] | None = None,
                   ttl: int = 300) -> wire.DNSMessage:
    """Build a DNSMessage suitable for caching."""
    hdr = wire.DNSHeader(
        id=0x1234,
        flags=wire.FLAG_QR | wire.FLAG_RD | wire.FLAG_RA | (rcode & wire.RCODE_MASK),
        qdcount=1,
        ancount=len(answers) if answers else 0,
        nscount=len(authorities) if authorities else 0,
    )
    q = wire.DNSQuestion(qname=qname, qtype=qtype, qclass=wire.QCLASS_IN)
    if answers is None:
        if rcode == wire.RCODE_NOERROR:
            answers = [wire.DNSRecord(
                name=qname, rtype=qtype, rclass=wire.QCLASS_IN,
                ttl=ttl, rdata=b"\x01\x02\x03\x04", decoded="1.2.3.4",
            )]
        else:
            answers = []
    if authorities is None:
        authorities = []
    return wire.DNSMessage(
        header=hdr, questions=[q], answers=answers, authorities=authorities,
    )


# ---------------------------------------------------------------------------
# Basic cache operations
# ---------------------------------------------------------------------------

class TestCacheBasic:
    def test_put_and_get(self) -> None:
        cache = DNSCache(max_entries=100)
        msg = _make_response("example.com", ttl=300)
        cache.put("example.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        entry = cache.get("example.com", wire.QTYPE_A)
        assert entry is not None
        assert len(entry.answers) == 1
        assert entry.rcode == wire.RCODE_NOERROR

    def test_miss(self) -> None:
        cache = DNSCache()
        assert cache.get("nonexistent.com", wire.QTYPE_A) is None
        assert cache.misses == 1

    def test_case_insensitive_key(self) -> None:
        cache = DNSCache()
        msg = _make_response("Example.Com", ttl=300)
        cache.put("Example.Com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        assert cache.get("example.com", wire.QTYPE_A) is not None
        assert cache.get("EXAMPLE.COM", wire.QTYPE_A) is not None

    def test_different_qtypes(self) -> None:
        cache = DNSCache()
        msg_a = _make_response("example.com", qtype=wire.QTYPE_A, ttl=300)
        msg_aaaa = _make_response("example.com", qtype=wire.QTYPE_AAAA, ttl=300,
                                   answers=[wire.DNSRecord(
                                       name="example.com", rtype=wire.QTYPE_AAAA,
                                       rclass=wire.QCLASS_IN, ttl=300,
                                       rdata=b"\x00" * 16,
                                   )])
        cache.put("example.com", wire.QTYPE_A, wire.QCLASS_IN, msg_a)
        cache.put("example.com", wire.QTYPE_AAAA, wire.QCLASS_IN, msg_aaaa)
        assert cache.get("example.com", wire.QTYPE_A) is not None
        assert cache.get("example.com", wire.QTYPE_AAAA) is not None
        assert cache.size == 2

    def test_hit_miss_counters(self) -> None:
        cache = DNSCache()
        msg = _make_response("example.com", ttl=300)
        cache.put("example.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        cache.get("example.com", wire.QTYPE_A)
        cache.get("example.com", wire.QTYPE_A)
        cache.get("miss.com", wire.QTYPE_A)
        assert cache.hits == 2
        assert cache.misses == 1


# ---------------------------------------------------------------------------
# TTL decay
# ---------------------------------------------------------------------------

class TestTTLDecay:
    def test_ttl_decays(self) -> None:
        cache = DNSCache()
        msg = _make_response("example.com", ttl=100)
        cache.put("example.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        time.sleep(0.1)
        entry = cache.get("example.com", wire.QTYPE_A)
        assert entry is not None
        # TTL should be less than the original 100.
        assert entry.answers[0].ttl < 100
        assert entry.answers[0].ttl >= 99  # at most 1 second elapsed

    def test_expired_entry_evicted(self) -> None:
        cache = DNSCache()
        # TTL of 0 should not be cached.
        msg = _make_response("shortlived.com", ttl=0)
        cache.put("shortlived.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        assert cache.get("shortlived.com", wire.QTYPE_A) is None


# ---------------------------------------------------------------------------
# LRU eviction
# ---------------------------------------------------------------------------

class TestLRUEviction:
    def test_eviction_on_overflow(self) -> None:
        cache = DNSCache(max_entries=3)
        for i in range(5):
            msg = _make_response(f"domain{i}.com", ttl=300)
            cache.put(f"domain{i}.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        assert cache.size == 3
        # First two should be evicted.
        assert cache.get("domain0.com", wire.QTYPE_A) is None
        assert cache.get("domain1.com", wire.QTYPE_A) is None
        # Last three should be present.
        assert cache.get("domain2.com", wire.QTYPE_A) is not None
        assert cache.get("domain3.com", wire.QTYPE_A) is not None
        assert cache.get("domain4.com", wire.QTYPE_A) is not None

    def test_access_refreshes_lru(self) -> None:
        cache = DNSCache(max_entries=3)
        for i in range(3):
            msg = _make_response(f"domain{i}.com", ttl=300)
            cache.put(f"domain{i}.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        # Access domain0 to refresh it.
        cache.get("domain0.com", wire.QTYPE_A)
        # Add a 4th entry – domain1 should be evicted (it's the LRU now).
        msg = _make_response("domain3.com", ttl=300)
        cache.put("domain3.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        assert cache.get("domain1.com", wire.QTYPE_A) is None
        assert cache.get("domain0.com", wire.QTYPE_A) is not None


# ---------------------------------------------------------------------------
# Negative caching
# ---------------------------------------------------------------------------

class TestNegativeCache:
    def test_nxdomain_cached(self) -> None:
        cache = DNSCache(max_negative_ttl=300)
        soa = wire.DNSRecord(
            name="example.com", rtype=wire.QTYPE_SOA, rclass=wire.QCLASS_IN,
            ttl=600,
            rdata=b"",
            decoded="ns1.example.com admin.example.com 2024010100 3600 900 604800 60",
        )
        msg = _make_response(
            "nonexistent.example.com",
            rcode=wire.RCODE_NXDOMAIN,
            answers=[],
            authorities=[soa],
            ttl=0,
        )
        cache.put("nonexistent.example.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        entry = cache.get("nonexistent.example.com", wire.QTYPE_A)
        assert entry is not None
        assert entry.is_negative is True
        assert entry.rcode == wire.RCODE_NXDOMAIN

    def test_negative_ttl_capped(self) -> None:
        cache = DNSCache(max_negative_ttl=30)
        soa = wire.DNSRecord(
            name="example.com", rtype=wire.QTYPE_SOA, rclass=wire.QCLASS_IN,
            ttl=86400,
            rdata=b"",
            decoded="ns1.example.com admin.example.com 1 3600 900 604800 86400",
        )
        msg = _make_response(
            "neg.example.com",
            rcode=wire.RCODE_NXDOMAIN,
            answers=[],
            authorities=[soa],
            ttl=0,
        )
        cache.put("neg.example.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        entry = cache.get("neg.example.com", wire.QTYPE_A)
        assert entry is not None
        # TTL should be capped at max_negative_ttl (30).
        assert entry.answers == []
        assert entry.original_ttl <= 30


# ---------------------------------------------------------------------------
# Flush
# ---------------------------------------------------------------------------

class TestCacheFlush:
    def test_flush_clears_all(self) -> None:
        cache = DNSCache()
        for i in range(5):
            msg = _make_response(f"d{i}.com", ttl=300)
            cache.put(f"d{i}.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
        assert cache.size == 5
        removed = cache.flush()
        assert removed == 5
        assert cache.size == 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestCacheThreadSafety:
    def test_concurrent_put_get(self) -> None:
        """Multiple threads putting and getting should not crash."""
        cache = DNSCache(max_entries=100)
        errors: list[Exception] = []
        stop = threading.Event()

        def writer(thread_id: int) -> None:
            for i in range(200):
                try:
                    msg = _make_response(f"domain{i}-t{thread_id}.com", ttl=60)
                    cache.put(f"domain{i}-t{thread_id}.com", wire.QTYPE_A, wire.QCLASS_IN, msg)
                except Exception as e:
                    errors.append(e)

        def reader() -> None:
            for i in range(200):
                try:
                    cache.get(f"domain{i}-t0.com", wire.QTYPE_A)
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=writer, args=(0,)),
            threading.Thread(target=writer, args=(1,)),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Errors: {errors}"
