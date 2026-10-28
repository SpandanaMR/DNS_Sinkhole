# Demo Guide

A demo for your guide that runs in about 10–12 minutes. Every command was
tested on the project machine. Run them from `D:\dns_sinkhole`.

## Before your guide arrives (10 minutes)

**1. Open four PowerShell windows in `D:\dns_sinkhole`.** In each one,
activate the virtual environment:

```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run
`Set-ExecutionPolicy -Scope Process Bypass` first. That only affects this
window.

**2. Create a "broken upstream" config for the failure demo.** Copy
`config.toml` to `config_dead.toml` and change only these lines:

```toml
primary = "10.255.255.1"
secondary = "10.255.255.2"
timeout = 1.0
```

**3. Have these open:** your browser, Wireshark, the GitHub repo page, and
VS Code with `src/dnssink/` open.

**4. Warm-up:** do one practice run (Part 1, step 1), then stop it with
Ctrl+C. That way Python is loaded and nothing is slow the first time.

| Window | Used for |
|---|---|
| 1 | The server |
| 2 | A live view of the query log |
| 3 | Client commands |
| 4 | The broken-upstream server, tests, loadtest |

## Part 1: The core features (about 4 minutes)

**Step 1: Start the server (window 1)**

```powershell
python -m dnssink --port 53
```

> Say: "A DNS server written from scratch. All packet parsing uses only
> `socket` and `struct`, with no DNS libraries. I'm using port 53 because
> Windows 11's nslookup ignores `-port`. On 127.0.0.1 this doesn't need
> admin rights."

Point at the startup lines: blocklist loaded, UDP and TCP listeners,
dashboard address.

**Step 2: Watch the log live (window 2)**

```powershell
Get-Content query_log.txt -Tail 5 -Wait
```

**Step 3: A normal lookup is forwarded (window 3)**

```powershell
nslookup example.com 127.0.0.1
```

> Say: "It wasn't in the cache, so it was forwarded to 8.8.8.8." The log
> shows `FORWARDED` at about 40–60 ms.

nslookup first sends a PTR query for `1.0.0.127.in-addr.arpa`, and it asks
for both A and AAAA records. So every lookup appears more than once in the
log; that's normal.

**Step 4: The same lookup again is a cache hit**

```powershell
nslookup example.com 127.0.0.1
```

> Say: "Now it's served from memory." The log shows `CACHE_HIT` at under
> 1 ms.

**Step 5: Show the TTL going down.** Run this, wait about 5 seconds, then
run it again:

```powershell
python tools/dnsclient.py example.com A --port 53
```

> Say: "The TTL drops between the two runs (for example 300 → 295). The
> cache returns the remaining time, not the original TTL."

**Step 6: Blocking, including subdomains**

```powershell
nslookup ads.example-ads.test 127.0.0.1
nslookup tracker.sub.example-ads.test 127.0.0.1
```

> Say: "Blocked names return `0.0.0.0` and `::`. The second name isn't in
> the list, but its parent domain is, so it's blocked too. The lookup walks
> a trie of reversed labels: test → example-ads → match."

**Step 7: TCP**

```powershell
nslookup -vc example.com 127.0.0.1
```

> Say: "`-vc` forces TCP. Over TCP, each message is preceded by a 2-byte
> length."

## Part 2: The dashboard (about 2 minutes)

**Step 8:** Open <http://127.0.0.1:8080> in the browser.

> Say: "It updates live and shows queries per second, cache hit rate,
> blocked percentage, latency per outcome, top domains, and the last 50
> queries." The numbers should match what you just ran.

**Step 9: Load test (window 4).** Watch the dashboard while it runs (about
30 s):

```powershell
python tools/loadtest.py --port 53 --clients 20 --queries 1000 --mode mixed
```

> Say: "20 clients sending 20,000 queries: 70% cache hits, 20% blocked, 10%
> misses." The report shows queries per second, p50/p95/p99 latency, and
> 0 errors.
>
> Mention: "The full test with 50 clients and 100,000 queries had 0 errors
> at about 1,600 queries per second. The tables are in EVALUATION.md."

**Step 10: Flush and reload.**

- Click **Flush Cache**, then run `nslookup example.com 127.0.0.1` again;
  it shows `FORWARDED` again.
- Add `demo-blocked.test` as a new line in `blocklists/sample_domains.txt`.
- Click **Reload Blocklist**. You can also run
  `python -m dnssink --reload-blocklist` from another window.
- Run `nslookup demo-blocked.test 127.0.0.1`. It's now blocked, without
  restarting the server.

## Part 3: Failure handling (about 2 minutes)

**Step 11: Upstream failure gives SERVFAIL (window 4)**

```powershell
python -m dnssink --config config_dead.toml --port 5354 --dashboard-port 8081
```

Then in window 3:

```powershell
python tools/dnsclient.py brand-new-name.com A --port 5354 --timeout 30
```

> Say: "Both upstreams are unreachable. It makes 3 attempts per upstream
> with a 1-second timeout, then answers SERVFAIL after about 6 seconds."

Then show that the server is still alive:

```powershell
python tools/dnsclient.py ads.example-ads.test A --port 5354
```

That answers instantly. Stop this server with Ctrl+C.

Optional: to show failover instead, run the server with only
`--upstream 10.255.255.1`. The primary times out, then the secondary
(8.8.4.4) answers, and the query still succeeds.

**Step 12: Clean shutdown.** Press **Ctrl+C** in window 1.

> Say: "It stops accepting queries, finishes the ones already in progress,
> closes the sockets and flushes the logs. No error trace is printed."

## Part 4: Evidence (about 3 minutes)

**Step 13: Tests (window 4)**

```powershell
pytest -q
```

This takes about 45 seconds; meanwhile, say what it covers. Result:
**114 passed**. That includes 10,000 random and corrupted packets with zero
crashes. Mention coverage: wire.py 90%, cache.py 96%, blocklist.py 95%.

**Step 14: Wireshark.** Open `docs/capture_live.pcapng` and apply the filter
`dns`:

- **Frame 3:** expand *Flags* and *Answers*. Click an answer's *Name* field
  and point at the highlighted `c0 0c`.
  > Say: "This is a compression pointer to offset 12, where the question
  > name is."
- **Frames 1 → 2 → 4 → 3:** point at the transaction IDs. The client sent
  `0x5eca`, the server asked 8.8.8.8 with a random `0x001b`, and the client
  got `0x5eca` back.
  > Say: "The random ID and a fresh socket for every upstream query protect
  > against spoofed answers."

**Step 15: Results documents.** Show `docs/EVALUATION.md`: the performance
tables, 13/13 answers matching 8.8.8.8, and the real StevenBlack list
(75,951 domains, loads in about 230 ms).

## If your guide asks to see the code

Have these open in VS Code:

| Topic | Where to look |
|---|---|
| Packet parsing and the pointer-loop guard | `decode_name` in `wire.py` |
| The order of the pipeline | `handle_query` in `server.py`: parse → block → cache → forward |
| TTL countdown and LRU eviction | `get` / `put` in `cache.py` |
| Subdomain matching | `is_blocked` in `blocklist.py` |
| Random ID, retries, failover, TCP fallback | `forward_query` in `upstream.py` |

## If something goes wrong

- **No internet:** start `python tools/fake_upstream.py --port 5300` and set
  `[upstream]` to `primary = "127.0.0.1"`, `secondary = ""`, `port = 5300`.
  Tell your guide you're using the offline fake upstream.
- **Keep a screen recording** of one successful full run as a last resort.

| Problem | Solution |
|---------|----------|
| nslookup times out | Windows nslookup ignores `-port`; run the server with `--port 53` |
| Port already in use | `netstat -ano \| findstr :53` to find the process, or pick another port |
| "Port 5353 is already shared" warning | Normal: Windows' mDNS service also uses 5353. Queries to 127.0.0.1 still reach the sinkhole |
| `No module named dnssink` | Activate the venv; if needed run `pip install -e .` once |
| `Activate.ps1` blocked | `Set-ExecutionPolicy -Scope Process Bypass`, then activate again |
| Dashboard not loading | Check that port 8080 is free; try `--dashboard-port 8081` |
| Upstream timeout | Check the internet connection; try `--upstream 1.1.1.1` |
| Windows Firewall prompt | Allow Python on private networks |

## Quick automated run

`.\tools\demo.ps1` starts the server on port 5353, runs the main queries
with `tools/dnsclient.py`, does a short load test, and stops the server.
It's handy for a check before the demo, but do the live demo by hand using
the steps above.
