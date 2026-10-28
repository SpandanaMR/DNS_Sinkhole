# DNS Sinkhole / Caching Resolver – Design Document

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     DNS Sinkhole Server                         │
│                                                                 │
│  ┌──────────┐  ┌──────────┐     ┌─────────────────────────┐   │
│  │   UDP    │  │   TCP    │     │   HTTP Dashboard        │   │
│  │ Listener │  │ Listener │     │   (port 8080)           │   │
│  └────┬─────┘  └────┬─────┘     │  GET /                  │   │
│       │              │           │  GET /api/stats          │   │
│       └──────┬───────┘           │  POST /api/reload       │   │
│              │                   │  POST /api/flush         │   │
│              ▼                   └─────────────────────────┘   │
│  ┌───────────────────────┐                                     │
│  │  ThreadPoolExecutor   │       ┌──────────────┐              │
│  │  (8 worker threads)   │◄─────►│    Stats     │              │
│  └───────────┬───────────┘       │  Collector   │              │
│              │                   └──────────────┘              │
│              ▼                                                 │
│  ┌───────────────────────────────────────────────────┐         │
│  │              Request Pipeline                      │         │
│  │                                                    │         │
│  │  1. Parse (wire.decode_message)                    │         │
│  │          │                                         │         │
│  │  2. Blocklist Check ──── BLOCKED ──► Sinkhole Resp │         │
│  │          │                                         │         │
│  │  3. Cache Lookup ──── HIT ──► Cached Response      │         │
│  │          │               (TTL decayed)             │         │
│  │  4. Forward to Upstream                            │         │
│  │          │  (random ID, fresh socket)              │         │
│  │          │  timeout → retry → failover             │         │
│  │          │  TC bit → retry over TCP                │         │
│  │          │                                         │         │
│  │  5. Cache the Response                             │         │
│  │          │                                         │         │
│  │  6. Return to Client                               │         │
│  └───────────────────────────────────────────────────┘         │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Blocklist│  │  Cache   │  │ Upstream │  │  Config  │       │
│  │ (Trie)   │  │ (LRU)   │  │ Forwarder│  │  (TOML)  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Concurrency Model: ThreadPoolExecutor

**Choice:** `concurrent.futures.ThreadPoolExecutor` with 8 worker threads.

**Why not asyncio?**
1. The standard-library socket API is inherently blocking. Wrapping every
   `sendto`/`recvfrom` in `asyncio` would add significant complexity (e.g.
   `loop.sock_recvfrom`, protocol classes) without a clear performance win
   for our target throughput (~10k QPS on localhost).
2. Threads are conceptually simpler for a student project. Each query runs
   in a single function (`handle_query`) with a straightforward pipeline,
   which is much easier to explain in a viva than an event-loop with
   callbacks and coroutines.
3. DNS query handling is I/O-bound (we spend most of the time waiting for
   the upstream resolver to respond), so the GIL is not a significant
   bottleneck.

**Trade-offs:**
- The GIL limits CPU parallelism, so pure-Python packet encoding/decoding
  does not benefit from multiple cores. For higher throughput, a C extension
  or an async implementation (e.g. with `asyncio.DatagramProtocol`) would
  be needed.
- Thread overhead: each thread uses ~8 KB of stack. With 8 threads, this
  is negligible.

**TCP connections get their own threads (not the pool).** A TCP client may
stay connected but idle for `tcp_idle_timeout` (30 s). If each connection
held one of the 8 pool workers, eight idle TCP clients would block every UDP
query. TCP connection threads are instead capped by `max_tcp_connections`,
and `test_idle_tcp_clients_do_not_starve_udp` checks this.

### Graceful shutdown (R12)

Ctrl+C (SIGINT) or Ctrl+Break (SIGBREAK) sets the shutdown event, then:

1. **Stop accepting:** the UDP receive loop and the TCP accept loop use 1 s
   socket timeouts, so they see the flag within a second. Idle TCP
   connections wait with `select()` in 1 s steps for the same reason.
2. **Drain:** `executor.shutdown(wait=True)` lets queued UDP queries finish.
   The UDP socket is still open, so their replies are still sent.
3. **Close sockets**, then 4. **flush log handlers**.

The main thread waits with `Event.wait(timeout=0.5)` in a loop. A plain
`Event.wait()` cannot be interrupted on Windows, so Ctrl+C would never stop
the server.

### Binding the listen sockets

The server tries `SO_EXCLUSIVEADDRUSE` first. On Windows, `SO_REUSEADDR`
lets a second process bind the same port and silently take queries. Port
5353 is also used by mDNS: Windows and browsers already hold
`0.0.0.0:5353` in shared mode, so an exclusive bind there fails with
WinError 10013. In that case the server falls back to `SO_REUSEADDR` and
logs a warning. Binding to 127.0.0.1 specifically means the loopback
unicast queries still reach us.

## Data Structures

### DNS Wire Format (wire.py)

All parsing uses `struct.unpack_from` with the `"!"` (network byte order)
format prefix. Key structures:

| Section | Format | Size |
|---------|--------|------|
| Header | `!HHHHHH` (6 × uint16) | 12 bytes |
| Name | Sequence of length-prefixed labels + `\x00` | Variable |
| Question | Name + `!HH` (qtype, qclass) | Variable |
| RR | Name + `!HHIH` (type, class, TTL, rdlength) + rdata | Variable |

**Name Compression (RFC 1035 §4.1.4):**
When the two high bits of a label-length byte are both 1 (`0xC0`), the
remaining 14 bits form a pointer to an earlier position in the packet.
Our decoder limits pointer hops to 128 to prevent infinite loops from
malicious packets, and rejects pointers beyond the end of the packet.

**Names inside RDATA are decompressed on decode.** CNAME, NS, PTR, MX and
SOA RDATA can contain compression pointers. Those pointers are offsets into
the *upstream's* packet. Cached records are later placed in a new packet
where those offsets point at different bytes. `decode_rr` therefore expands
those names once (`_decompress_rdata`), so every `DNSRecord` is
self-contained. `encode_rr` re-compresses CNAME/NS/MX names within the new
packet. `test_reencode_preserves_soa_with_rdata_pointers` is a hand-built
packet where the old raw-copy approach produced a corrupt SOA.

### Blocklist (blocklist.py)

**Structure:** Reversed-label trie.

```
Example: blocking "ads.example.com"

Root
 └─ "com"
     └─ "example"
         └─ "ads" [TERMINAL]
```

Lookup for `x.ads.example.com` walks: com → example → ads (terminal found → blocked).
Lookup for `safe.example.com` walks: com → example → safe (not found → not blocked).

**Why a trie?** O(number of labels) lookup vs O(n) linear scan. Supports
100k+ entries with sub-millisecond lookups.

### Cache (cache.py)

**Structure:** `collections.OrderedDict` keyed by `(qname_lower, qtype, qclass)`.

- **LRU eviction:** `move_to_end()` on access, `popitem(last=False)` on overflow.
- **TTL decay:** Stores absolute expiry time; returns `remaining = expiry - now`.
- **Negative caching (RFC 2308):** NXDOMAIN/NODATA responses are cached using
  the SOA minimum TTL, capped at `max_negative_ttl`.

### Statistics (stats.py)

- Rolling QPS window: `collections.deque` of timestamps, pruned at 60 seconds.
- Latency percentiles: sorted list per outcome, bounded at 10,000 samples.
- Top-N: `collections.Counter` with `.most_common(10)`.

## Security Considerations

1. **Random transaction IDs:** Each upstream query uses a fresh random ID
   from `secrets` (not the client's ID, and not the predictable `random`
   module) to prevent cache-poisoning attacks via ID prediction. Replies
   with the wrong ID are discarded (`test_wrong_id_reply_ignored...`).
2. **Source validation:** UDP responses are checked against the expected
   upstream IP address.
3. **Fresh sockets:** Each upstream query uses a new socket with an
   OS-assigned ephemeral port, adding source-port randomness.
4. **Localhost binding:** By default, the server binds to `127.0.0.1`,
   preventing use as an open resolver.
5. **Resource limits:** Cache has a max-entries cap, TCP connections are
   capped, and TCP connections have an idle timeout.
6. **No port hijacking:** listen sockets use `SO_EXCLUSIVEADDRUSE` where the
   port allows it (see "Binding the listen sockets").

## RFC References

| RFC | Topic | Where Used |
|-----|-------|------------|
| RFC 1035 | DNS protocol, wire format, name compression | wire.py |
| RFC 2308 | Negative caching | cache.py |
| RFC 3596 | AAAA record type (IPv6) | wire.py |
| RFC 6891 | EDNS0 (OPT record, larger UDP) | wire.py, server.py |
