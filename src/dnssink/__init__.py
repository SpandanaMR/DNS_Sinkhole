"""DNS Sinkhole / Caching Resolver package.

A DNS server written from scratch in Python that blocks unwanted domains,
caches responses with TTL-based expiry, forwards cache misses to an upstream
resolver, and shows live statistics in a web dashboard.
"""

__version__ = "1.0.0"
