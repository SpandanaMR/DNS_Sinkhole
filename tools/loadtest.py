"""Multithreaded DNS load test with latency report.

Usage:
    python tools/loadtest.py --clients 50 --queries 2000
    python tools/loadtest.py --clients 10 --queries 20000 --mode cache
    python tools/loadtest.py --clients 50 --queries 2000 --mode blocked
    python tools/loadtest.py --clients 20 --queries 5000 --mode mixed
"""

from __future__ import annotations

import argparse
import random
import socket
import statistics
import struct
import sys
import pathlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink import wire


# ---------------------------------------------------------------------------
# Query generation
# ---------------------------------------------------------------------------

# Pre-built pool of domain names for different modes
CACHE_DOMAINS = [f"cached-domain-{i}.example.com" for i in range(10)]
BLOCKED_DOMAINS = [f"blocked-{i}.example-ads.test" for i in range(10)]
MISS_DOMAINS = [f"unique-{i}-{random.randint(0, 999999)}.example.com" for i in range(5000)]


def build_query(qname: str) -> bytes:
    """Build a minimal DNS A query."""
    hdr = wire.DNSHeader(
        id=random.randint(0, 0xFFFF),
        flags=wire.FLAG_RD,
        qdcount=1,
    )
    q = wire.DNSQuestion(qname=qname, qtype=wire.QTYPE_A, qclass=wire.QCLASS_IN)
    msg = wire.DNSMessage(header=hdr, questions=[q])
    return wire.encode_message(msg)


def get_domain(mode: str, index: int) -> str:
    """Return a domain name based on the test mode."""
    if mode == "cache":
        return CACHE_DOMAINS[index % len(CACHE_DOMAINS)]
    elif mode == "blocked":
        return BLOCKED_DOMAINS[index % len(BLOCKED_DOMAINS)]
    elif mode == "mixed":
        # 70% cache hits, 20% blocked, 10% misses
        r = random.random()
        if r < 0.7:
            return CACHE_DOMAINS[index % len(CACHE_DOMAINS)]
        elif r < 0.9:
            return BLOCKED_DOMAINS[index % len(BLOCKED_DOMAINS)]
        else:
            return MISS_DOMAINS[index % len(MISS_DOMAINS)]
    else:  # miss
        return MISS_DOMAINS[index % len(MISS_DOMAINS)]


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def worker(client_id: int, server: str, port: int,
           num_queries: int, mode: str, timeout: float) -> List[Tuple[float, bool]]:
    """Send queries and collect latency results.

    Returns a list of (latency_ms, success) tuples.
    """
    results: List[Tuple[float, bool]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        for i in range(num_queries):
            domain = get_domain(mode, client_id * num_queries + i)
            query = build_query(domain)
            start = time.perf_counter()
            try:
                sock.sendto(query, (server, port))
                data, _ = sock.recvfrom(4096)
                elapsed = (time.perf_counter() - start) * 1000.0
                results.append((elapsed, True))
            except socket.timeout:
                elapsed = (time.perf_counter() - start) * 1000.0
                results.append((elapsed, False))
            except OSError:
                elapsed = (time.perf_counter() - start) * 1000.0
                results.append((elapsed, False))
    finally:
        sock.close()

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def percentile(data: List[float], p: int) -> float:
    """Compute p-th percentile."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS load test tool")
    parser.add_argument("--server", "-s", default="127.0.0.1",
                        help="DNS server address (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=5353,
                        help="DNS server port (default: 5353)")
    parser.add_argument("--clients", "-c", type=int, default=10,
                        help="Number of concurrent clients (default: 10)")
    parser.add_argument("--queries", "-q", type=int, default=1000,
                        help="Number of queries per client (default: 1000)")
    parser.add_argument("--mode", "-m", default="cache",
                        choices=["cache", "blocked", "mixed", "miss"],
                        help="Query mode (default: cache)")
    parser.add_argument("--timeout", "-t", type=float, default=5.0,
                        help="Per-query timeout in seconds (default: 5)")
    args = parser.parse_args()

    total_queries = args.clients * args.queries
    print(f"DNS Load Test")
    print(f"{'='*60}")
    print(f"Server:     {args.server}:{args.port}")
    print(f"Clients:    {args.clients}")
    print(f"Queries:    {args.queries} per client ({total_queries} total)")
    print(f"Mode:       {args.mode}")
    print(f"{'='*60}")

    # Pre-warm: send a few queries to populate the cache
    if args.mode in ("cache", "mixed"):
        print("\nPre-warming cache...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        for domain in CACHE_DOMAINS:
            try:
                query = build_query(domain)
                sock.sendto(query, (args.server, args.port))
                sock.recvfrom(4096)
            except (socket.timeout, OSError):
                pass
        sock.close()
        time.sleep(0.2)

    print(f"\nRunning load test with {args.clients} concurrent clients...")
    all_results: List[Tuple[float, bool]] = []
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.clients) as executor:
        futures = [
            executor.submit(worker, i, args.server, args.port,
                            args.queries, args.mode, args.timeout)
            for i in range(args.clients)
        ]
        for future in as_completed(futures):
            all_results.extend(future.result())

    total_time = time.perf_counter() - start_time

    # Analyse results
    successes = [lat for lat, ok in all_results if ok]
    failures = [lat for lat, ok in all_results if not ok]

    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    print(f"Total time:      {total_time:.2f}s")
    print(f"Total queries:   {len(all_results)}")
    print(f"Successful:      {len(successes)}")
    print(f"Failed:          {len(failures)}")
    print(f"QPS:             {len(successes) / total_time:.1f}")

    if successes:
        print(f"\nLatency (ms):")
        print(f"  Min:           {min(successes):.2f}")
        print(f"  Avg:           {statistics.mean(successes):.2f}")
        print(f"  Median (p50):  {percentile(successes, 50):.2f}")
        print(f"  p95:           {percentile(successes, 95):.2f}")
        print(f"  p99:           {percentile(successes, 99):.2f}")
        print(f"  Max:           {max(successes):.2f}")

    print(f"\nError rate:      {len(failures)/len(all_results)*100:.2f}%")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
