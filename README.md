# DNS Sinkhole / Caching Resolver

A DNS server written from scratch in Python that:
1. **Blocks** unwanted domains (ads, trackers, malware) using a configurable blocklist
2. **Caches** DNS responses with TTL-based expiry and LRU eviction
3. **Forwards** cache misses to an upstream resolver (e.g. Google DNS)
4. **Displays** live statistics in a web dashboard

> **No third-party DNS libraries.** All DNS wire-format parsing and building
> is hand-written using Python's `struct` module with network byte order.

## Quick Start

```powershell
# One-time setup: virtual environment + test tools + this package (editable)
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt -e .

# Start the server on port 5353
python -m dnssink --port 5353

# In another terminal, test it with the included client
python tools/dnsclient.py example.com A --port 5353

# Open the dashboard
# http://127.0.0.1:8080
```

`pip install -e .` is what makes `python -m dnssink` work from any folder.
The code lives in `src/`, so Python can't find it otherwise.

### Using nslookup (Windows note)

On current Windows 11 builds, `nslookup` **ignores `-port=` and
`set port=`** and always queries port 53. We confirmed this by capturing its
packets. To demo with nslookup, run the server on port 53. On 127.0.0.1 that
does not need admin rights:

```powershell
python -m dnssink --port 53
nslookup example.com 127.0.0.1
nslookup -vc example.com 127.0.0.1          # -vc forces TCP
nslookup ads.example-ads.test 127.0.0.1     # blocked -> 0.0.0.0 / ::
```

### Offline mode (no internet)

```powershell
python tools/fake_upstream.py --port 5300   # terminal 1: fake resolver (UDP+TCP)
# set [upstream] primary = "127.0.0.1", secondary = "", port = 5300 in config.toml
python -m dnssink --port 5353               # terminal 2
```

### Reload the blocklist without restarting

Click **Reload Blocklist** on the dashboard, or from another terminal run:

```powershell
python -m dnssink --reload-blocklist
```

## Features

| Feature | Description |
|---------|-------------|
| **UDP + TCP** | Listens on both UDP and TCP with proper 2-byte length framing |
| **Blocklist** | Hosts-style and plain domain files, subdomain matching via reversed-label trie |
| **Cache** | LRU eviction, TTL decay, negative caching (RFC 2308) |
| **Upstream** | Configurable primary/secondary with timeout, retry, failover |
| **TC Fallback** | Automatically retries over TCP if upstream response is truncated |
| **EDNS0** | Parses OPT records, honours advertised UDP payload size |
| **Dashboard** | Auto-refreshing HTML page with charts, stats, reload/flush buttons |
| **Logging** | Rotating log files with per-query structured logging |
| **Graceful Shutdown** | Ctrl+C drains in-flight queries and closes sockets cleanly |

## Project Structure

```
dns-sinkhole/
  README.md                     ← you are here
  config.toml                   ← main configuration
  pyproject.toml                ← package metadata (no runtime dependencies)
  requirements-dev.txt          ← pytest only
  blocklists/
    sample_hosts.txt            ← hosts-format blocklist
    sample_domains.txt          ← plain domain-list blocklist
  src/dnssink/
    __init__.py
    __main__.py                 ← CLI entry: python -m dnssink
    config.py                   ← TOML config + CLI argument parsing
    wire.py                     ← DNS packet encode/decode, compression
    blocklist.py                ← Reversed-label trie for domain blocking
    cache.py                    ← LRU cache with TTL decay
    upstream.py                 ← Upstream forwarding with retry/failover
    server.py                   ← UDP + TCP listeners, request pipeline
    stats.py                    ← Thread-safe statistics collector
    dashboard.py                ← HTTP dashboard (http.server)
    logging_setup.py            ← Rotating log file setup
  tests/
    test_wire.py                ← Wire format unit tests
    test_blocklist.py           ← Blocklist unit tests
    test_cache.py               ← Cache unit tests
    test_upstream.py            ← Upstream tests (fake local server)
    test_server_integration.py  ← End-to-end loopback tests
    test_fuzz.py                ← 10,000 random/mutated packet tests
    test_config.py              ← config.toml loading + CLI overrides
  tools/
    dnsclient.py                ← Test client (python tools/dnsclient.py)
    loadtest.py                 ← Multi-threaded load test
    fake_upstream.py            ← Offline fake resolver (UDP + TCP), used by tests
    demo.ps1                    ← PowerShell demo script
  docs/
    DESIGN.md                   ← Architecture and design decisions
    TESTING.md                  ← Test suite documentation
    DEMO.md                     ← Demo script guide
    EVALUATION.md               ← Evaluation criteria and rubric
```

## Configuration

Edit `config.toml` or use command-line flags:

```powershell
# Custom port and upstream
python -m dnssink --port 53 --upstream 1.1.1.1

# NXDOMAIN block mode
python -m dnssink --block-mode nxdomain

# Debug logging
python -m dnssink --log-level DEBUG

# All options
python -m dnssink --help
```

## Testing

```powershell
# Run all tests
pytest -v

# With coverage
pytest --cov=dnssink --cov-report=term-missing -v

# Run specific test file
pytest tests/test_wire.py -v

# Fuzz test only
pytest tests/test_fuzz.py -v
```

## Load Testing

```powershell
# Cache hit performance
python tools/loadtest.py --clients 50 --queries 2000 --mode cache

# Blocked domain performance
python tools/loadtest.py --clients 50 --queries 2000 --mode blocked

# Mixed workload (70% cache, 20% blocked, 10% miss)
python tools/loadtest.py --clients 50 --queries 2000 --mode mixed
```

## Environment

- **OS:** Windows 11
- **Python:** 3.11+
- **Dependencies:** Standard library only (pytest for tests)
- **Default port:** 5353 (UDP + TCP), no admin rights required
- **Dashboard:** http://127.0.0.1:8080

## Documentation

- [Design Document](docs/DESIGN.md) – Architecture, concurrency model, data structures
- [Testing Guide](docs/TESTING.md) – How to run tests, coverage targets
- [Demo Guide](docs/DEMO.md) – Step-by-step demo script
- [Evaluation](docs/EVALUATION.md) – Grading rubric and checklist
