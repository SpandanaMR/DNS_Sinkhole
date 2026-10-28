"""DNS response cache with TTL decay, negative caching, and LRU eviction.

Key design decisions:
    - Cache key = (lowercased qname, qtype, qclass) per RFC 1035 §7.4.
    - Each entry stores the absolute expiry time, computed from the minimum
      TTL of the answer records at insertion time.
    - When serving a cached entry, we compute the *remaining* TTL
      (original_ttl - elapsed) and patch the answer records.
    - Negative caching (NXDOMAIN / NODATA) follows RFC 2308: TTL is the
      minimum of the SOA TTL and the SOA MINIMUM field, capped at a
      configurable maximum.
    - LRU eviction: we use an OrderedDict so that ``move_to_end`` on
      access and ``popitem(last=False)`` for eviction are both O(1).

Thread safety:
    All public methods acquire self._lock (a threading.Lock).  We use a
    plain Lock (not RLock) because no method calls another public method
    while holding the lock.
"""

from __future__ import annotations

import collections
import dataclasses
import threading
import time
from typing import Dict, List, Optional, Tuple

from . import wire


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CacheEntry:
    """A single cached DNS response."""
    answers: List[wire.DNSRecord]
    authorities: List[wire.DNSRecord]
    additionals: List[wire.DNSRecord]
    rcode: int
    # Absolute time (monotonic) when this entry expires.
    expires_at: float
    # The original minimum TTL at insertion time (for decay math).
    original_ttl: int
    # Insertion time (monotonic), used to compute remaining TTL.
    inserted_at: float
    # Is this a negative cache entry (NXDOMAIN or NODATA)?
    is_negative: bool = False


# Cache key type alias.
CacheKey = Tuple[str, int, int]   # (lowercased qname, qtype, qclass)


class DNSCache:
    """Thread-safe DNS response cache with LRU eviction and TTL decay."""

    def __init__(self, max_entries: int = 10000,
                 max_negative_ttl: int = 300,
                 min_ttl: int = 0) -> None:
        self._max_entries = max_entries
        self._max_negative_ttl = max_negative_ttl
        self._min_ttl = min_ttl
        # OrderedDict gives us O(1) LRU eviction.
        self._store: collections.OrderedDict[CacheKey, CacheEntry] = (
            collections.OrderedDict()
        )
        self._lock = threading.Lock()
        # Stats
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Properties for stats
    # ------------------------------------------------------------------

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)

    @property
    def max_entries(self) -> int:
        return self._max_entries

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, qname: str, qtype: int,
            qclass: int = wire.QCLASS_IN) -> Optional[CacheEntry]:
        """Look up a cache entry and return it with TTLs adjusted.

        Returns None on cache miss or expired entry.  Expired entries are
        evicted lazily (on access).
        """
        key: CacheKey = (qname.lower(), qtype, qclass)
        now = time.monotonic()

        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None

            if now >= entry.expires_at:
                # Expired – evict lazily.
                del self._store[key]
                self._misses += 1
                return None

            # Move to end (most recently used).
            self._store.move_to_end(key)
            self._hits += 1

            # Return a copy with decayed TTLs.
            remaining = max(0, int(entry.expires_at - now))
            return self._decay_entry(entry, remaining)

    def put(self, qname: str, qtype: int, qclass: int,
            msg: wire.DNSMessage) -> None:
        """Cache a DNS response message.

        Computes the expiry from the minimum TTL of the answer records.
        For negative responses (NXDOMAIN, NODATA with SOA), uses the
        SOA minimum TTL capped by max_negative_ttl.
        """
        key: CacheKey = (qname.lower(), qtype, qclass)
        now = time.monotonic()

        is_negative = (
            msg.header.rcode == wire.RCODE_NXDOMAIN or
            (msg.header.rcode == wire.RCODE_NOERROR and len(msg.answers) == 0)
        )

        ttl = self._compute_ttl(msg, is_negative)
        if ttl <= 0:
            return  # Don't cache zero-TTL records.

        ttl = max(ttl, self._min_ttl)

        entry = CacheEntry(
            answers=list(msg.answers),
            authorities=list(msg.authorities),
            additionals=[r for r in msg.additionals if r.rtype != wire.QTYPE_OPT],
            rcode=msg.header.rcode,
            expires_at=now + ttl,
            original_ttl=ttl,
            inserted_at=now,
            is_negative=is_negative,
        )

        with self._lock:
            if key in self._store:
                # Update existing entry.
                self._store.move_to_end(key)
            self._store[key] = entry
            # LRU eviction.
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def flush(self) -> int:
        """Remove all entries. Returns the number of entries removed."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            return count

    def reset_stats(self) -> None:
        """Reset hit/miss counters."""
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _compute_ttl(self, msg: wire.DNSMessage, is_negative: bool) -> int:
        """Compute the TTL for caching a message."""
        if is_negative:
            # RFC 2308: use the SOA MINIMUM field from the authority section,
            # capped at max_negative_ttl.
            soa_min = wire.get_soa_minimum(msg)
            if soa_min is not None:
                soa_ttl = 0
                for rec in msg.authorities:
                    if rec.rtype == wire.QTYPE_SOA:
                        soa_ttl = rec.ttl
                        break
                ttl = min(soa_min, soa_ttl) if soa_ttl > 0 else soa_min
                return min(ttl, self._max_negative_ttl)
            # No SOA in authority – use a short default.
            return min(60, self._max_negative_ttl)

        # Positive response: use the minimum TTL of all answer records.
        ttl = wire.get_min_ttl(msg)
        return ttl

    @staticmethod
    def _decay_entry(entry: CacheEntry, remaining_ttl: int) -> CacheEntry:
        """Return a copy of *entry* with all TTLs replaced by *remaining_ttl*."""
        decayed_answers = [
            dataclasses.replace(rec, ttl=remaining_ttl)
            for rec in entry.answers
        ]
        decayed_authorities = [
            dataclasses.replace(rec, ttl=remaining_ttl)
            for rec in entry.authorities
        ]
        decayed_additionals = [
            dataclasses.replace(rec, ttl=remaining_ttl)
            for rec in entry.additionals
        ]
        return dataclasses.replace(
            entry,
            answers=decayed_answers,
            authorities=decayed_authorities,
            additionals=decayed_additionals,
        )
