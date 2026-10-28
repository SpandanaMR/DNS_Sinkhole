# Demo Guide

## Prerequisites

1. Python 3.11+ installed
2. `pytest` installed (`pip install pytest pytest-cov`)
3. Working internet connection (for upstream DNS resolution)

## Quick Start

```powershell
# Start the server
python -m dnssink --port 5353 --config config.toml
```

The server will print:
```
DNS Sinkhole starting...
Blocklist loaded: 50 domains in X.Xms
UDP listener started on 127.0.0.1:5353
TCP listener started on 127.0.0.1:5353
Dashboard started at http://127.0.0.1:8080
DNS Sinkhole is ready.
```

## Demo Script (5-7 minutes)

### Setup (before the demo)
- Open three terminals:
  1. Server (running `python -m dnssink --port 5353`)
  2. Client (for sending queries)
  3. Browser with `http://127.0.0.1:8080` (dashboard)

### Step-by-Step

| Step | Command | What Happens |
|------|---------|--------------|
| 1 | `python -m dnssink --port 5353` | Server starts, shows blocklist count |
| 2 | `python tools/dnsclient.py example.com A --port 5353` | Cache miss → FORWARDED (~20-50ms) |
| 3 | `python tools/dnsclient.py example.com A --port 5353` | Cache hit → CACHE_HIT (<1ms), TTL lower |
| 4 | `python tools/dnsclient.py example-ads.test A --port 5353` | BLOCKED → returns 0.0.0.0 |
| 5 | `python tools/dnsclient.py sub.tracker.example-ads.test A --port 5353` | Subdomain also BLOCKED |
| 6 | Open `http://127.0.0.1:8080` in browser | Live dashboard with stats |
| 7 | `python tools/loadtest.py --clients 50 --queries 2000` | Load test, watch dashboard update live |
| 8 | `python tools/dnsclient.py example.com A --port 5353 --tcp` | TCP query works |
| 9 | Press Ctrl+C in server terminal | Graceful shutdown |

### Using nslookup instead

Windows 11's `nslookup` ignores `-port=` and always sends to port 53. For an
nslookup demo, start the server on port 53, which needs no admin rights on
127.0.0.1:

```powershell
python -m dnssink --port 53
nslookup example.com 127.0.0.1
nslookup ads.example-ads.test 127.0.0.1
nslookup tracker.sub.example-ads.test 127.0.0.1
nslookup -vc example.com 127.0.0.1
```

nslookup first sends a PTR query for `1.0.0.127.in-addr.arpa`, which shows
up in the log. It also queries both A and AAAA, so each lookup appears
twice.

### Backup: no internet

```powershell
python tools/fake_upstream.py --port 5300
```
Point `[upstream]` at `127.0.0.1` port `5300` (secondary `""`). Say up front
that the demo is using the offline fake upstream.

### Showing SERVFAIL (step 8 of the plan)

Use a config whose `primary` and `secondary` are both unreachable (for
example `10.255.255.1` and `10.255.255.2`). A new name returns SERVFAIL after
3 attempts × timeout × 2 upstreams (about 6 s with `timeout = 1.0`). Blocked
and cached names keep answering instantly. With only `--upstream
10.255.255.1`, the query fails over to `8.8.4.4` and still succeeds.

## Automated Demo Script

Run the included PowerShell script:
```powershell
.\tools\demo.ps1
```

This automatically starts the server, runs all demo queries, performs a quick
load test, and cleans up.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 5353 in use | `netstat -ano \| findstr :5353` to find the process, or use `--port 5354` |
| Windows Firewall prompt | Allow Python on private networks |
| nslookup times out on 5353 | Windows nslookup ignores `-port`; run the server with `--port 53` |
| "Port 5353 is already shared" warning | Normal: Windows mDNS also uses 5353. Queries to 127.0.0.1 still reach the sinkhole |
| `No module named dnssink` | Run `pip install -e .` once inside the venv |
| Ctrl+C | Stops within ~1 s; logs are flushed |
| Dashboard not loading | Check that port 8080 is free; try `--dashboard-port 8081` |
| Upstream timeout | Check internet connection; try `--upstream 1.1.1.1` |
