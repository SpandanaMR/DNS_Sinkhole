"""Live statistics collector for the DNS sinkhole.

Design:
    - All counters are protected by a threading.Lock.
    - QPS is computed over a rolling 60-second window using a deque of
      timestamps.
    - Latency tracking uses sorted insertion into a bounded list per
      outcome category so p50/p95/p99 can be computed.
    - Top-N tracking uses Counter objects.

Why not asyncio / atomics:
    We chose ThreadPoolExecutor for concurrency (see DESIGN.md), so a
    plain Lock is the simplest correct synchronisation.
"""

from __future__ import annotations

import collections
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple


# Outcome categories for logging and stats.
OUTCOME_BLOCKED = "BLOCKED"
OUTCOME_CACHE_HIT = "CACHE_HIT"
OUTCOME_FORWARDED = "FORWARDED"
OUTCOME_NXDOMAIN = "NXDOMAIN"
OUTCOME_SERVFAIL = "SERVFAIL"
OUTCOME_ERROR = "ERROR"

# Rolling window for QPS calculation.
QPS_WINDOW_SECONDS = 60

# Maximum number of latency samples to keep per outcome.
MAX_LATENCY_SAMPLES = 10000


class QueryRecord:
    """A single query log record for the dashboard's recent-queries table."""
    __slots__ = ("timestamp", "client_ip", "qname", "qtype", "outcome", "latency_ms")

    def __init__(self, timestamp: float, client_ip: str,
                 qname: str, qtype: str, outcome: str,
                 latency_ms: float) -> None:
        self.timestamp = timestamp
        self.client_ip = client_ip
        self.qname = qname
        self.qtype = qtype
        self.outcome = outcome
        self.latency_ms = latency_ms

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a dict for the JSON API."""
        return {
            "timestamp": self.timestamp,
            "client_ip": self.client_ip,
            "qname": self.qname,
            "qtype": self.qtype,
            "outcome": self.outcome,
            "latency_ms": round(self.latency_ms, 3),
        }


class Stats:
    """Thread-safe statistics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_queries: int = 0
        self._query_timestamps: Deque[float] = collections.deque()
        self._outcome_counts: Dict[str, int] = collections.defaultdict(int)
        self._latency_samples: Dict[str, List[float]] = collections.defaultdict(list)
        self._top_queried: collections.Counter[str] = collections.Counter()
        self._top_blocked: collections.Counter[str] = collections.Counter()
        self._top_clients: collections.Counter[str] = collections.Counter()
        self._upstream_failures: int = 0
        self._recent_queries: Deque[QueryRecord] = collections.deque(maxlen=50)

    def record_query(self, client_ip: str, qname: str, qtype: str,
                     outcome: str, latency_ms: float) -> None:
        """Record a completed query."""
        now = time.time()
        with self._lock:
            self._total_queries += 1
            self._query_timestamps.append(time.monotonic())
            self._outcome_counts[outcome] += 1

            # Latency sample (bounded per outcome).
            samples = self._latency_samples[outcome]
            if len(samples) < MAX_LATENCY_SAMPLES:
                samples.append(latency_ms)
            else:
                # Rotate: drop the oldest sample.
                samples[self._total_queries % MAX_LATENCY_SAMPLES] = latency_ms

            self._top_queried[qname] += 1
            if outcome == OUTCOME_BLOCKED:
                self._top_blocked[qname] += 1
            self._top_clients[client_ip] += 1

            if outcome == OUTCOME_SERVFAIL:
                self._upstream_failures += 1

            self._recent_queries.append(QueryRecord(
                timestamp=now,
                client_ip=client_ip,
                qname=qname,
                qtype=qtype,
                outcome=outcome,
                latency_ms=latency_ms,
            ))

    def snapshot(self) -> Dict[str, Any]:
        """Return a snapshot of all stats for the JSON API and dashboard."""
        now_mono = time.monotonic()
        with self._lock:
            # Prune old timestamps for QPS window.
            cutoff = now_mono - QPS_WINDOW_SECONDS
            while self._query_timestamps and self._query_timestamps[0] < cutoff:
                self._query_timestamps.popleft()
            qps = len(self._query_timestamps) / QPS_WINDOW_SECONDS

            total = self._total_queries
            blocked = self._outcome_counts.get(OUTCOME_BLOCKED, 0)
            cache_hits = self._outcome_counts.get(OUTCOME_CACHE_HIT, 0)
            forwarded = self._outcome_counts.get(OUTCOME_FORWARDED, 0)

            cache_hit_rate = (cache_hits / total * 100.0) if total > 0 else 0.0
            blocked_pct = (blocked / total * 100.0) if total > 0 else 0.0

            # Latency percentiles per outcome.
            latency_stats: Dict[str, Dict[str, float]] = {}
            for outcome, samples in self._latency_samples.items():
                if samples:
                    sorted_s = sorted(samples)
                    latency_stats[outcome] = {
                        "avg": sum(sorted_s) / len(sorted_s),
                        "p50": _percentile(sorted_s, 50),
                        "p95": _percentile(sorted_s, 95),
                        "p99": _percentile(sorted_s, 99),
                    }

            return {
                "total_queries": total,
                "qps": round(qps, 2),
                "cache_hit_rate": round(cache_hit_rate, 2),
                "cache_hits": cache_hits,
                "forwarded": forwarded,
                "blocked": blocked,
                "blocked_pct": round(blocked_pct, 2),
                "nxdomain": self._outcome_counts.get(OUTCOME_NXDOMAIN, 0),
                "servfail": self._outcome_counts.get(OUTCOME_SERVFAIL, 0),
                "errors": self._outcome_counts.get(OUTCOME_ERROR, 0),
                "upstream_failures": self._upstream_failures,
                "latency": latency_stats,
                "top_queried": self._top_queried.most_common(10),
                "top_blocked": self._top_blocked.most_common(10),
                "top_clients": self._top_clients.most_common(10),
                "recent_queries": [
                    q.to_dict() for q in reversed(self._recent_queries)
                ],
            }


def _percentile(sorted_data: List[float], pct: int) -> float:
    """Compute a percentile from pre-sorted data."""
    if not sorted_data:
        return 0.0
    idx = int(len(sorted_data) * pct / 100)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]
