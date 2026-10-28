# DNS Sinkhole / Caching Resolver: Antigravity Prompt, Plan, Demo and Evaluation

Target: Windows 11, Python 3.11+, no third-party DNS libraries (the packet code must be hand-written for the course).
Estimated effort: 30-45 hours over 2-3 weeks.

---

## Part 1: How to use this file in Antigravity

1. Create an empty folder, e.g. `dns-sinkhole`, and open it as a workspace in Antigravity.
2. Open the Agent Manager (or the agent side panel) and start a new task.
3. Paste the entire prompt from Part 2 (everything inside the big code block).
4. Set the agent to **Planning mode** (not Fast), so it writes a plan and task list first. Read the plan before approving it.
5. Approve work **one milestone at a time**. After each milestone, run the tests yourself before telling the agent to continue.
6. Keep the agent's generated `README.md` and `docs/` files. They become your report material.

Tips:
- If the agent drifts, reply with: "Stop. Re-read the Requirements and Constraints sections of the original prompt, then continue from Milestone N."
- Ask it to explain any function you can't explain yourself. You will be asked about the code in your viva.
- Do not let it add `dnspython`, `scapy`, or any DNS library. The point is writing the protocol code.

---

## Part 2: The prompt (copy everything in the block)

````text
ROLE
You are a senior network-programming engineer and teaching assistant. Build a complete, well-tested university project for a Network Programming course. Work in milestones, write tests as you go, and explain design decisions in comments and docs.

PROJECT
"DNS Sinkhole / Caching Resolver": a DNS server written from scratch in Python that
(1) blocks unwanted domains (ads, trackers, malware) using a blocklist,
(2) caches everything else with TTL-based expiry,
(3) forwards cache misses to an upstream resolver,
(4) shows live statistics in a small web dashboard.

ENVIRONMENT
- Windows 11, Python 3.11 or newer, run from PowerShell.
- Standard library only for all DNS and socket logic. Allowed extras: pytest (tests only), and nothing else. Do NOT use dnspython, scapy, or any DNS/packet library. The dashboard must use the standard library http.server (no Flask).
- Default listen port is 5353 (UDP and TCP) on 127.0.0.1, configurable. Do not require admin rights. Port 53 must also work if configured.

HARD CONSTRAINTS
- All DNS wire-format parsing and building must be hand-written with the struct module and network byte order ("!" format strings).
- Must support name compression pointers when parsing AND when building responses, with protection against pointer loops and out-of-bounds offsets.
- Must never crash on malformed or hostile packets. Malformed input is logged and dropped, or answered with FORMERR. Add a fuzz-style test.
- Thread-safe cache and stats. Use a bounded ThreadPoolExecutor or asyncio for concurrency (pick one and justify it in docs/DESIGN.md).
- Type hints everywhere, docstrings on public functions, no global mutable state outside a clearly named server context object.
- Everything configurable through config.toml (use tomllib from the standard library) plus command-line flags.

FEATURES (REQUIREMENTS)
R1  UDP DNS server on the configured port, handling concurrent queries.
R2  Parse the 12-byte header (ID, flags QR/Opcode/AA/TC/RD/RA/RCODE, QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT), question section, and resource records (A, AAAA, CNAME, NS, SOA, MX, TXT at minimum for pass-through; fully decode A, AAAA, CNAME).
R3  Blocklist: load domains from a hosts-style file and a plain domain-list file. Match exact domains AND all subdomains (blocking "ads.example.com" blocks "x.ads.example.com"). Use a reversed-label trie or a set with suffix walking so lookups are O(labels). Support runtime reload (command-line flag or dashboard button) without restarting.
R4  Block responses are configurable: "null" (A -> 0.0.0.0, AAAA -> ::) or "nxdomain". Keep a short TTL on blocked answers.
R5  Cache: key = (lowercased name, qtype, qclass). Store the full answer records with absolute expiry computed from the minimum TTL. Honour TTL decrement when serving (return remaining TTL, not the original). Include negative caching for NXDOMAIN/NODATA using the SOA minimum (RFC 2308) with a cap. LRU eviction with a configurable max entries.
R6  Forwarding: on cache miss, query the upstream resolver (default 8.8.8.8, configurable, with an optional second upstream as failover). Per-attempt timeout (default 2 s), up to 2 retries, then answer SERVFAIL. Use a fresh socket and a randomised transaction ID for each upstream query, verify the response ID and source address, and restore the client's original ID in the reply.
R7  TCP support: (a) the server also listens on TCP with the 2-byte length prefix and handles multiple queries per connection; (b) if an upstream UDP answer has the TC bit set, retry that query over TCP; (c) if our own UDP reply would exceed 512 bytes (and the client sent no EDNS0), truncate and set TC.
R8  Basic EDNS0 awareness: parse the OPT record; if present, honour the advertised UDP payload size up to 1232 bytes and echo an OPT record in the reply.
R9  Query logging to a rotating log file with: timestamp, client IP, qname, qtype, outcome (BLOCKED / CACHE_HIT / FORWARDED / NXDOMAIN / SERVFAIL / ERROR), and latency in milliseconds.
R10 Statistics: total queries, queries per second (rolling 60-second window), cache hit rate, blocked count and percentage, average and p95 latency per outcome, top 10 blocked domains, top 10 queried domains, top clients, upstream failures.
R11 Dashboard: an HTTP page on a separate port (default 8080, localhost only) with auto-refreshing charts/tables using plain HTML + JavaScript (no external CDN or build step; draw simple bars with inline SVG or CSS). Provide a JSON endpoint /api/stats, a "reload blocklist" button, a "flush cache" button, and a table of the last 50 queries.
R12 Graceful shutdown on Ctrl+C: stop accepting, drain in-flight queries, close sockets, flush logs.

PROJECT STRUCTURE (create exactly this layout)
dns-sinkhole/
  README.md
  config.toml
  requirements-dev.txt          (pytest only)
  blocklists/sample_hosts.txt   (about 50 harmless sample entries, incl. example-ads.test domains)
  blocklists/sample_domains.txt
  src/dnssink/
    __init__.py
    __main__.py                 (CLI entry: python -m dnssink)
    config.py
    wire.py                     (packet encode/decode, compression)
    blocklist.py
    cache.py
    upstream.py
    server.py                   (UDP + TCP listeners, request pipeline)
    stats.py
    dashboard.py
    logging_setup.py
  tests/
    test_wire.py
    test_blocklist.py
    test_cache.py
    test_upstream.py            (use a fake local upstream server, no real internet)
    test_server_integration.py  (end-to-end over loopback, UDP and TCP)
    test_fuzz.py
  tools/
    dnsclient.py                (tiny test client built on wire.py: python tools/dnsclient.py example.com A --port 5353)
    loadtest.py                 (multithreaded query generator with latency report)
    demo.ps1                    (PowerShell demo script)
  docs/
    DESIGN.md                   (architecture diagram in ASCII/Mermaid, concurrency choice, data structures, RFC references)
    TESTING.md
    DEMO.md
    EVALUATION.md

MILESTONES (stop after each one, run the tests, summarise what was built, and wait for my approval)
M1  Skeleton + config + logging + wire.py with decoding/encoding, compression-safe, plus test_wire.py including real captured-style packets built by hand (A, AAAA, CNAME chains, NXDOMAIN, pointer loop, truncated packet).
M2  blocklist.py + cache.py with unit tests (suffix matching, TTL decay, LRU eviction, negative caching, thread-safety test).
M3  UDP server pipeline: parse -> blocklist -> cache -> upstream -> reply, using a fake upstream in tests; manual test with tools/dnsclient.py.
M4  Real upstream forwarding with timeout/retry/failover/ID and source validation; TCP fallback on TC; TCP listener; EDNS0; truncation.
M5  Stats + logging + dashboard + loadtest.py.
M6  Hardening (fuzz tests, malformed input handling, graceful shutdown), docs (DESIGN, TESTING, DEMO, EVALUATION), README with install/run instructions, demo.ps1.
After M6, run the full test suite and loadtest, then produce a short final report of results with real numbers.

ACCEPTANCE TESTS (must pass before declaring done)
A1  `python -m dnssink --port 5353` starts without admin rights on Windows.
A2  `nslookup -port=5353 example.com 127.0.0.1` returns a valid answer via the upstream.
A3  A blocklisted name returns 0.0.0.0 (or NXDOMAIN in nxdomain mode), and subdomains of a blocked domain are also blocked.
A4  A second identical query is served from cache; log shows CACHE_HIT and latency is lower than the first query; returned TTL is smaller than the original.
A5  Repeated query after TTL expiry goes to upstream again.
A6  Killing the upstream (use an unreachable address) yields SERVFAIL after the timeout/retries, and the server keeps running.
A7  A response larger than 512 bytes works via TCP (test with a fake upstream that returns a big TXT record).
A8  Fuzz test of 10,000 random and mutated packets causes zero crashes and zero hangs.
A9  Loadtest of 50 concurrent clients x 2,000 queries completes with no errors, and the report shows queries/sec and p50/p95/p99 latency.
A10 Dashboard at http://127.0.0.1:8080 shows live numbers that match /api/stats and the log file counts.
A11 pytest passes fully, and coverage on wire.py, cache.py and blocklist.py is at least 85% (report it).

OUTPUT STYLE
- Before each milestone, give a short plan. After each, give: files changed, how to run it, how I can verify it manually, and any known limitations.
- Be honest about anything not working. Do not claim a test passes without running it.
- Do not invent test results. Show real command output.
- Keep code readable for a student who must explain it in a viva. Prefer clarity over cleverness. Add a "Why this design" comment on non-obvious parts.

START NOW with a written plan covering the whole project, then begin Milestone M1.
````

---

## Part 3: Complete step-by-step path to finish the project

### Phase 0: Setup (half a day)
1. Install Python 3.11+ and check with `python --version`.
2. Create the folder, open it in Antigravity, create a virtual environment: `python -m venv .venv` then `.venv\Scripts\Activate.ps1`.
3. Paste the Part 2 prompt, review the plan the agent produces, and approve it.

### Phase 1: Packet layer (M1), about 6-8 hours
- Read the DNS header and name compression sections of RFC 1035 yourself (30 minutes). It will make the agent's code understandable.
- Run `pytest tests/test_wire.py`.
- Check by hand: build a query for `example.com`, print the bytes in hex, and verify they match what Wireshark shows for a real `nslookup` (see Wireshark note below).

### Phase 2: Blocklist and cache (M2), about 4-6 hours
- Check suffix matching and TTL behaviour using the unit tests.
- Download a real blocklist (for example StevenBlack hosts) into `blocklists/` and confirm it loads quickly (target: a 100k+ entry list loaded in under 2 seconds).

### Phase 3: Server pipeline (M3), about 5-6 hours
- Run the server and test with `tools/dnsclient.py` and with `nslookup`.
- Confirm the pipeline order in the log: BLOCKED, CACHE_HIT, FORWARDED.

### Phase 4: Forwarding, TCP, EDNS0 (M4), about 6-8 hours
- Test failover by setting the primary upstream to an unreachable IP.
- Test TCP with `nslookup -vc -port=5353 example.com 127.0.0.1` (the `-vc` flag forces TCP).

### Phase 5: Stats and dashboard (M5), about 4-5 hours
- Run `tools/loadtest.py` while watching the dashboard.
- Compare the dashboard counters to the log file to confirm they agree.

### Phase 6: Hardening and docs (M6), about 5-7 hours
- Run the fuzz test and fix any crash it finds.
- Complete DESIGN.md, TESTING.md and DEMO.md. Read them and correct anything the agent got wrong.

### Phase 7: Rehearsal and report (last 2-3 days)
- Do the demo script three times from a cold start.
- Capture screenshots and Wireshark traces for the report.
- Write the report (see Part 5).

---

## Part 4: Demo plan (5-7 minutes)

### Before the demo
- Start PowerShell in the project folder with the virtual environment active.
- Have three windows ready: (1) server logs, (2) a client terminal, (3) the dashboard in a browser.
- Optional: open Wireshark on the loopback adapter (Npcap loopback) with the filter `udp.port == 5353`.
- Run one warm-up query so Python imports are loaded, then flush the cache from the dashboard.

### Script

| Step | What you do | What to say | Expected result |
|---|---|---|---|
| 1 | `python -m dnssink --port 5353` | "A DNS server written from scratch using only sockets and `struct`." | Startup log shows listening on UDP and TCP, and N blocklist entries loaded. |
| 2 | `nslookup -port=5353 example.com 127.0.0.1` | "Cache miss, so it is forwarded to 8.8.8.8." | Answer returned, log shows `FORWARDED` with latency, e.g. 25 ms. |
| 3 | Run the same command again | "Same query is served from memory. Notice the lower latency and the reduced TTL." | Log shows `CACHE_HIT` with latency under 1 ms, TTL smaller than before. |
| 4 | `nslookup -port=5353 ads.example-ads.test 127.0.0.1` | "This domain is in the blocklist, so it is sinkholed." | `0.0.0.0` returned, log shows `BLOCKED`. |
| 5 | `nslookup -port=5353 tracker.sub.example-ads.test 127.0.0.1` | "Subdomains of blocked domains are blocked too." | Blocked. |
| 6 | Show the dashboard | "Live QPS, cache hit rate, blocked percentage, and top blocked domains." | Numbers match what you just did. |
| 7 | Run `python tools/loadtest.py --clients 50 --queries 2000` | "Now 100,000 queries from 50 concurrent clients." | Report with QPS and p50/p95/p99 latency, dashboard moves live. |
| 8 | Set upstream to an unreachable address and query a new name | "If the upstream fails, we retry and then return SERVFAIL, and the server stays up." | SERVFAIL after about the timeout, server still answers blocked and cached names. |
| 9 | `nslookup -vc -port=5353 example.com 127.0.0.1` | "TCP support, with the 2-byte length framing." | Answer returned over TCP. |
| 10 | Optional: show Wireshark | "Here is the 12-byte header and a compression pointer, `0xC00C`." | Packet fields visible. |

### Backup plan
- If the internet is down, run the fake-upstream mode used in the tests (`python tools/fake_upstream.py`) and point the config at it. State this up front.
- Keep a screen recording of a successful run.

### Likely viva questions to prepare
1. Why does the DNS header use network byte order, and how do you pack it?
2. How does name compression work, and how do you stop pointer loops?
3. Why use a fresh socket and random ID for each upstream query? (Spoofing resistance.)
4. How do you compute the TTL you return from the cache?
5. What is negative caching, and which RFC defines it?
6. When does a UDP answer get truncated, and what does the client do?
7. Why a trie or suffix walk instead of a plain list scan?
8. What happens under concurrency, and where are your locks?

---

## Part 5: How to evaluate the project after completion

### A. Functional checklist

| # | Check | How | Pass criteria |
|---|---|---|---|
| F1 | Resolves normal names | `nslookup -port=5353 example.com 127.0.0.1` | Correct A record |
| F2 | AAAA works | `nslookup -type=AAAA -port=5353 google.com 127.0.0.1` | IPv6 address returned |
| F3 | CNAME chain | Query a known CNAME (e.g. `www.github.com`) | Chain followed or passed through correctly |
| F4 | Blocking, exact and subdomain | Sample blocklist names | Sinkholed responses |
| F5 | NXDOMAIN passthrough and caching | Query a random nonexistent name twice | Second one is a cache hit |
| F6 | TTL expiry | Use a short-TTL fake upstream | Re-fetch after expiry |
| F7 | TCP fallback | Fake upstream returns TC=1 | Server retries via TCP |
| F8 | Failover and SERVFAIL | Break the primary upstream | Failover works, then SERVFAIL when all are down |
| F9 | Reload and flush | Dashboard buttons | Effect visible immediately |
| F10 | Graceful shutdown | Ctrl+C during a loadtest | No traceback, logs flushed |

### B. Correctness testing
- **Unit tests:** `pytest -v`. Target: all pass.
- **Coverage:** `pytest --cov=src/dnssink --cov-report=term-missing` (install `pytest-cov`). Target: at least 85% on `wire.py`, `cache.py`, `blocklist.py`.
- **Cross-validation against real tools:** compare your answers to those of the same queries sent directly to 8.8.8.8 (`nslookup example.com 8.8.8.8`). Records should match (allowing for TTL differences and load-balanced IP sets).
- **Wireshark verification:** capture one query and one response and confirm that header flags, counts and compression pointers match your decoder's output.
- **Fuzzing:** the fuzz test must run clean. Record how many packets it sent.

### C. Performance evaluation
Run `tools/loadtest.py` with several configurations and record a table like this in your report:

| Scenario | Clients | Queries | QPS | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|---|
| All cache hits | 10 | 20,000 | | | | | |
| All cache hits | 50 | 100,000 | | | | | |
| All blocked | 50 | 100,000 | | | | | |
| Mixed (70% cache, 20% blocked, 10% miss) | 50 | 100,000 | | | | | |
| Cold misses (unique names, fake upstream) | 20 | 5,000 | | | | | |

Also report:
- **Cache effect:** average latency of a miss vs a hit (expect tens of milliseconds vs under 1 ms).
- **Blocklist scale:** load time and lookup time with 1k, 100k and 500k entries.
- **Memory:** process memory after filling the cache to its limit (Task Manager or `psutil` in a script).
- Mention honestly that Python's GIL limits throughput, and what a C or async implementation could improve.

### D. Robustness and security evaluation
- Malformed packets: empty datagram, 1-byte packet, header only, huge counts, pointer loop, and over-long labels. Server must survive all of these.
- Upstream spoofing resistance: confirm random IDs and source validation in the code and test.
- Resource limits: cache has a maximum size, TCP idle timeout exists, and concurrent TCP connections are capped.
- Not an open resolver: by default, bind to localhost, or allow only a configured client subnet. Mention this as a security consideration.

### E. Grading rubric (self-assessment)

| Area | Weight | Full marks when |
|---|---|---|
| Protocol correctness (header, names, compression, record types) | 25% | Matches real DNS tools and Wireshark |
| Networking features (UDP, TCP, timeouts, retries, EDNS0) | 20% | All tested, including failure cases |
| Caching and blocking design | 15% | TTL decay, negative cache, LRU, suffix matching |
| Concurrency and robustness | 15% | Fuzz clean, thread-safe, graceful shutdown |
| Dashboard and observability | 10% | Live, accurate, matches logs |
| Testing and evaluation evidence | 10% | Coverage, load tables, Wireshark screenshots |
| Documentation and demo | 5% | Clear design doc, smooth demo |

### F. What to put in the final report
1. Problem statement and goals
2. Architecture diagram and request pipeline
3. Packet format and compression explanation, with a Wireshark screenshot
4. Design choices (concurrency model, cache structure, blocklist structure) and why
5. Testing method and results (unit, integration, fuzz, coverage)
6. Performance tables from Section C and analysis
7. Limitations (no DNSSEC, no DoH/DoT, GIL, no recursive resolution) and future work
8. How the project maps to the course syllabus: UDP, TCP, byte order, timeouts, concurrency, and socket options

---

## Part 6: Quick reference

Run:
```powershell
python -m dnssink --port 5353 --config config.toml
```

Test:
```powershell
nslookup -port=5353 example.com 127.0.0.1
nslookup -vc -port=5353 example.com 127.0.0.1
pytest -v
python tools/loadtest.py --clients 50 --queries 2000
```

Dashboard: `http://127.0.0.1:8080`

Common Windows problems:
- **Port already in use:** change the port or find the process with `netstat -ano | findstr :5353`.
- **Windows Firewall prompt:** allow Python on private networks (only needed if testing from another machine).
- **`nslookup -port` not accepted:** use `nslookup -port=5353 name server` in exactly that order, or use `tools/dnsclient.py`.
- **Wireshark can't see loopback:** install Npcap with loopback support, then capture on "Npcap Loopback Adapter".
