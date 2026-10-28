# Evaluation Guide

## A. Functional Checklist

| # | Check | Command | Pass Criteria |
|---|-------|---------|---------------|
| F1 | Resolves normal names | `nslookup example.com 127.0.0.1` (server on `--port 53`) | Correct A record returned |
| F2 | AAAA works | `nslookup -type=AAAA google.com 127.0.0.1` (server on `--port 53`) | IPv6 address returned |
| F3 | CNAME chain | Query `www.github.com` | Chain followed or passed through |
| F4 | Blocking (exact + subdomain) | Query blocklisted names | Sinkholed responses (0.0.0.0) |
| F5 | NXDOMAIN passthrough | Query random nonexistent name twice | Second is CACHE_HIT |
| F6 | TTL expiry | Use short-TTL domain, wait, re-query | Re-fetched from upstream |
| F7 | TCP | `nslookup -vc example.com 127.0.0.1`; upstream TC fallback: `test_upstream_tc_triggers_tcp_retry` | Answer via TCP |
| F8 | Failover + SERVFAIL | `--upstream 192.0.2.1` (unreachable) | SERVFAIL, server keeps running |
| F9 | Reload + flush | Dashboard buttons | Effect visible immediately |
| F10 | Graceful shutdown | Ctrl+C during load test | No traceback, logs flushed |

## B. Correctness Testing

```powershell
# Run all tests
pytest -v

# Coverage report
pytest --cov=dnssink --cov-report=term-missing -v
```

**Targets:**
- `wire.py`: ≥ 85% coverage
- `cache.py`: ≥ 85% coverage
- `blocklist.py`: ≥ 85% coverage

## C. Performance Evaluation

Run with `tools/loadtest.py`:

| Scenario | Clients | Queries | Command |
|----------|---------|---------|---------|
| All cache hits | 10 | 20,000 | `--clients 10 --queries 2000 --mode cache` |
| All cache hits | 50 | 100,000 | `--clients 50 --queries 2000 --mode cache` |
| All blocked | 50 | 100,000 | `--clients 50 --queries 2000 --mode blocked` |
| Mixed | 50 | 100,000 | `--clients 50 --queries 2000 --mode mixed` |
| Cold misses | 20 | 5,000 | `--clients 20 --queries 250 --mode miss` |

Record QPS, p50, p95, p99 latency, and error count for each.

### Measured results (2026-10-28)

Machine: Windows 11, Python 3.12.3. Server, load generator and upstream all
run on one machine. The upstream was `tools/fake_upstream.py`, so results
don't depend on internet latency. The cache was flushed before each
scenario. Latencies are round-trip times measured by the client, in ms.

| Scenario | Clients | Queries | QPS | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|---|
| All cache hits | 10 | 20,000 | 1989.1 | 4.44 | 10.33 | 11.48 | 0 |
| All cache hits | 50 | 100,000 | 1577.2 | 24.76 | 65.20 | 112.53 | 0 |
| All blocked | 50 | 100,000 | 1619.5 | 22.86 | 79.57 | 132.25 | 0 |
| Mixed (70% cache, 20% blocked, 10% miss) | 50 | 100,000 | 2334.1 | 21.18 | 24.68 | 28.00 | 0 |
| Cold misses (unique names, fake upstream) | 20 | 5,000 | 1938.8 | 10.14 | 12.09 | 13.34 | 0 |

The same 50 × 2,000 mixed test against the real upstream (8.8.8.8):
100,000/100,000 answered, 1614 QPS, p50 26.4 / p95 61.4 / p99 78.8 ms.

**Cache effect** (time spent inside the server, from `query_log.txt`, real
upstream): forwarded `example.org` **42.5 ms**, then a cache hit **0.22 ms**,
about 190× faster.

**Analysis.** Throughput levels off at about 1.5–2.3k QPS whatever the
query type. Even all-blocked queries, which never leave the process, are no
faster than cache hits. The limit is the GIL: the 8 worker threads, the UDP
receive loop *and* the 50 Python load-generator threads all share one core's
worth of Python bytecode. Adding clients therefore mostly adds queueing
delay: p50 rises from 4.4 ms to 25 ms going from 10 to 50 clients, while
the work per query stays the same. Running the load generator on another
machine, or writing the server in C or Go, would raise the ceiling. Using
asyncio would remove the per-query thread hand-off, but packet parsing would
still be bound by the GIL. Treat differences of roughly ±30% between
scenarios as run-to-run noise on a shared desktop.

**Blocklist scale** (synthetic hosts files, `Blocklist.load` timed with
`perf_counter`, 100k lookups, half hits and half misses):

| Entries | Load time | Lookup | Peak memory while loading |
|---|---|---|---|
| 1,000 | 9 ms | 1.9 µs | 1 MB |
| 100,000 | 943 ms | 1.9 µs | 37 MB |
| 500,000 | 4.6 s | 2.1 µs | 154 MB |

The lookup time stays flat as the list grows, as expected for an
O(labels) trie walk. 100k entries load in under the 2 s target.

**Memory:** a full cache (10,000 entries, 2 A records each) holds about
10.5 MB (tracemalloc).

**Real blocklist: StevenBlack unified hosts** (file dated 27 Oct 2026,
2.3 MB, 75,951 unique domains per its header):

| Check | Result |
|---|---|
| Domains loaded | **75,951**, exactly the count the file's header states |
| Load time | 215–233 ms (3 runs); 231 ms at server startup; 321 ms for a live reload via the dashboard API |
| Lookup | 0.73 µs per name |
| Subdomains of listed domains blocked | 20,000 / 20,000 sampled |
| False positives | 0 out of 20,000 clean names |
| Header entries (`localhost`, `local`, `0.0.0.0`, `broadcasthost`) | not blocked (skipped by the loader) |
| Live server | `ad.doubleclick.net`, `googleadservices.com` → `0.0.0.0`; `github.com` resolves normally |

To use it: download `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
into `blocklists/` and add it to `hosts_files` in `config.toml`.

## Cross-validation against 8.8.8.8

`python tools/crossvalidate.py --port 5353` asks the sinkhole and Google
Public DNS the same 13 questions and compares the RCODE and record data.
TTLs are ignored because the sinkhole returns the remaining cache TTL. For
SOA records only the server names are compared, since zone serials change
constantly. Result: **13 / 13 match**. Full table:
[crossvalidation.md](crossvalidation.md).

Types covered: A, AAAA, NS, SOA, MX, TXT, a CNAME chain
(`www.github.com`), NODATA (`does-not-exist-….example.com`) and NXDOMAIN
(`no-such-domain-58213x.com`).

## Packet capture (Wireshark evidence)

### Live capture: [capture_live.pcapng](capture_live.pcapng)

Captured with Wireshark 4.6.9 / Npcap 1.88 (`tshark`) on two interfaces at
once:

- *Adapter for loopback traffic capture*, filter `port 53`: client ↔ sinkhole
- *Wi-Fi*, filter `host 8.8.8.8 and port 53`: sinkhole ↔ upstream

The sinkhole ran on port 53 so Wireshark labels the traffic as DNS (it
treats 5353 as mDNS). The capture has 29 frames and Wireshark reports
**0 malformed or error frames**.

| Frames | What happens | What it shows |
|---|---|---|
| 1 → 2 → 4 → 3 | Client asks `example.com A` (ID `0x5eca`). The sinkhole asks 8.8.8.8 with **ID `0x001b`** from source port 61886, gets the answer, and replies to the client with **`0x5eca` restored** | R6: random upstream ID, fresh socket, client ID restored. Wireshark: "Time: 66.6 ms" |
| 5–6 | Same query again | Cache hit: **no upstream packet**, reply 0.6 ms after the query |
| 7–8 | `ads.example-ads.test A` | Blocked: no upstream packet; reply `0.0.0.0`, TTL 60, flags `0x8580` (AA=1) |
| 9–23 | `github.com A` over **TCP** (handshake, 2-byte length framing, close) | R7a: TCP listener. Upstream query uses ID `0x3ba5` from another fresh port (52854) |
| 24–29 | Real `nslookup ads.example-ads.test 127.0.0.1` | nslookup's PTR query (NXDOMAIN via upstream), then A and AAAA, both sinkholed (`0.0.0.0` / `::`) |

Frame 3, the forwarded reply as Wireshark shows it (DNS part starts at
`5e ca`):

```
0020  5e ca 81 80 00 01 00 02 00 00 00 00 07 65 78 61   ^............exa
0030  6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00   mple.com........
0040  01 00 01 00 00 01 2c 00 04 ac 42 93 f3 c0 0c 00   ......,...B.....
0050  01 00 01 00 00 01 2c 00 04 68 14 17 9a            ......,..h...
```

- `5e ca` ID · `81 80` flags (QR=1, RD=1, RA=1, RCODE=0) · `00 01 00 02 00 00 00 00` = QD 1, AN 2, NS 0, AR 0
- `07 example 03 com 00` is the question name, at DNS offset 12, then type A, class IN
- `c0 0c` is each answer's owner name: a **compression pointer to offset 12**
- `00 00 01 2c` TTL 300 · `00 04` RDLENGTH · `ac 42 93 f3` = 172.66.147.243

**Screenshots for the report:** open `capture_live.pcapng` in Wireshark.
1. Display filter `dns`, select frame 3, and expand *Domain Name System →
   Flags* and *Answers*. Click the answer's *Name* field: the bytes pane
   highlights `c0 0c`.
2. Add the column `dns.id` (right-click Transaction ID → *Apply as Column*)
   to show the ID changing from `0x5eca` to `0x001b` and back across frames
   1 → 2 → 4 → 3.
3. Filter `tcp.port == 53` to show the TCP exchange.

To capture again: start `python -m dnssink --port 53`, then run
```
D:\Wireshark\tshark.exe -i "Adapter for loopback traffic capture" -f "port 53" -i Wi-Fi -f "host 8.8.8.8 and port 53" -a duration:25 -w docs\capture_live.pcapng
```
and in another terminal run `python tools/capture_pcap.py --port 53`.

### Generated capture: [capture.pcap](capture.pcap)

`tools/capture_pcap.py` also writes the bytes it sent and received to
`capture.pcap` on its own. The DNS payload is exactly what went over the
socket; the IPv4 and UDP headers are rebuilt by the script. It is useful on
machines without Npcap. [capture_annotated.txt](capture_annotated.txt)
breaks those same packets down field by field. The live capture above is
the primary evidence.

## Acceptance tests status (2026-10-28)

| # | Result | Evidence |
|---|---|---|
| A1 | Pass | `python -m dnssink --port 5353` starts without admin rights. Needs `pip install -e .` once |
| A2 | Pass* | Valid answer via 8.8.8.8. *Windows 11 nslookup ignores `-port`, so the nslookup check runs with `--port 53`; `tools/dnsclient.py` works on 5353 |
| A3 | Pass | `0.0.0.0`/`::` for `ads.example-ads.test` and `tracker.sub.example-ads.test`; NXDOMAIN mode tested |
| A4 | Pass | Log shows FORWARDED 42.5 ms then CACHE_HIT 0.22 ms; TTL 299 → 285 → 280 |
| A5 | Pass | `test_ttl_expiry_refetches` |
| A6 | Pass | Both upstreams unreachable → SERVFAIL after 6.07 s (3 attempts × 1 s × 2 upstreams); server keeps answering |
| A7 | Pass | `test_big_txt_truncated_over_udp_full_over_tcp` (~2 KB TXT) |
| A8 | Pass | `test_fuzz.py`: 10,000 random/mutated packets, 0 crashes, 0 hangs |
| A9 | Pass | 50 × 2,000 = 100,000 queries, 0 errors (tables above) |
| A10 | Pass | Dashboard totals match `/api/stats` and the `query_log.txt` outcome counts exactly. Reload and flush buttons work |
| A11 | Pass | 114 tests pass. Coverage: wire 90%, cache 96%, blocklist 95% |
| F10 | Pass | Ctrl+Break during a loadtest: clean exit in 1.2 s, exit code 0, no traceback |

## D. Robustness and Security

- **Malformed packets:** Fuzz test (`test_fuzz.py`) sends 10,000 random/mutated packets → zero crashes
- **Upstream spoofing:** Random IDs + source validation (see `upstream.py`)
- **Resource limits:** Cache capped at `max_entries`, TCP connections capped, idle timeout enforced
- **Not an open resolver:** Default bind to `127.0.0.1`

## E. Grading Rubric

| Area | Weight | Full Marks When |
|------|--------|-----------------|
| Protocol correctness | 25% | Matches Wireshark and real DNS tools |
| Networking features | 20% | UDP, TCP, timeouts, retries, EDNS0 all tested |
| Caching and blocking | 15% | TTL decay, negative cache, LRU, suffix matching |
| Concurrency and robustness | 15% | Fuzz clean, thread-safe, graceful shutdown |
| Dashboard and observability | 10% | Live, accurate, matches logs |
| Testing and evidence | 10% | Coverage ≥ 85%, load tables, fuzz results |
| Documentation and demo | 5% | Clear design doc, smooth demo |

## F. Limitations and Future Work

1. **No DNSSEC:** We don't validate DNSSEC signatures
2. **No DoH/DoT:** No DNS-over-HTTPS or DNS-over-TLS
3. **GIL:** Python's GIL limits CPU parallelism; a C or Go implementation would be faster
4. **No recursive resolution:** We forward to an upstream, not resolve iteratively
5. **Simple EDNS0:** We parse OPT and honour payload size, but don't support all options
6. **No query pipelining on upstream TCP:** Each TCP query is sequential

## G. Course Syllabus Mapping

| Topic | Where in Project |
|-------|-----------------|
| UDP sockets | `server.py` (UDPListener), `upstream.py` |
| TCP sockets | `server.py` (TCPListener), `upstream.py` (TCP fallback) |
| Byte order / struct | `wire.py` (all encoding/decoding uses `!` format) |
| Timeouts and retries | `upstream.py` (per-query timeout, retry loop) |
| Concurrency | `server.py` (ThreadPoolExecutor), all `_lock` usage |
| Socket options | `SO_EXCLUSIVEADDRUSE` / `SO_REUSEADDR` fallback, `settimeout`, `select` (server.py) |
| Protocol design | DNS header flags, name compression, resource records |
