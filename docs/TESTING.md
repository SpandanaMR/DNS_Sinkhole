# Testing Guide

## Test Suite Overview

| Test File | Module Under Test | Key Tests |
|-----------|-------------------|-----------|
| `test_wire.py` | `wire.py` | Header encode/decode, name compression, pointer loops, RR parsing (A, AAAA, CNAME, TXT), message round-trips, blocked/error response building, truncation |
| `test_blocklist.py` | `blocklist.py` | Exact and subdomain matching, hosts and domain file parsing, reload, thread safety, 10k-entry scale test |
| `test_cache.py` | `cache.py` | Put/get, case-insensitive keys, TTL decay, LRU eviction, negative caching (RFC 2308), flush, concurrent thread safety |
| `test_upstream.py` | `upstream.py` | Successful forward, timeout/retry, failover, transaction ID randomisation, error handling (uses a fake local upstream) |
| `test_server_integration.py` | Full server | End-to-end UDP/TCP queries, blocking, caching, NXDOMAIN passthrough, malformed packets, multiple TCP queries, dashboard HTTP |
| `test_fuzz.py` | `wire.py` | 10,000 random + mutated packets, pathological headers, pointer loops – verifies zero crashes and zero hangs |
| `test_config.py` | `config.py` | Loads the shipped `config.toml`, partial files, CLI overrides |

`test_server_integration.py` also runs feature tests against
`tools/fake_upstream.py`, a UDP + TCP fake resolver:

| Test | Requirement |
|------|-------------|
| `test_big_txt_truncated_over_udp_full_over_tcp` | A7, R7a, R7c: >512 B answer sets TC on UDP and arrives whole over TCP |
| `test_upstream_tc_triggers_tcp_retry` | R7b: upstream TC=1 → retried over TCP |
| `test_opt_echoed` / `test_no_opt_without_edns` | R8: OPT echoed on forwarded, cached and blocked answers |
| `test_ttl_expiry_refetches` | A5: expired entry goes upstream again |
| `test_negative_cache_hit_keeps_soa` | R5: NXDOMAIN cached, SOA intact on cache hit |
| `test_wrong_id_reply_ignored_and_client_id_restored` | R6: spoofed ID ignored, client ID restored |
| `test_nxdomain_mode` | R4: NXDOMAIN block mode |
| `test_stop_is_prompt_with_idle_tcp_client` | R12: shutdown not delayed by idle TCP clients |
| `test_idle_tcp_clients_do_not_starve_udp` | R1: TCP clients can't exhaust the UDP worker pool |

Total: **114 tests**. Coverage: wire.py 90%, cache.py 96%, blocklist.py 95%
(85% overall).

## Running Tests

### Quick run
```powershell
pytest -v
```

### With coverage report
```powershell
pytest --cov=dnssink --cov-report=term-missing -v
```

### Run a single test file
```powershell
pytest tests/test_wire.py -v
```

### Run fuzz tests only
```powershell
pytest tests/test_fuzz.py -v
```

### Set a custom fuzz seed
```powershell
$env:FUZZ_SEED = "12345"
pytest tests/test_fuzz.py -v
```

## Coverage Targets

| Module | Target | Rationale |
|--------|--------|-----------|
| `wire.py` | ≥ 85% | Core protocol code; must be thoroughly tested |
| `cache.py` | ≥ 85% | Critical for correctness (TTL, LRU, thread safety) |
| `blocklist.py` | ≥ 85% | Security-relevant (blocking must be reliable) |
| Other modules | ≥ 70% | Integration tests cover the pipeline |

## Testing Strategy

### Unit Tests
Each module (`wire`, `cache`, `blocklist`, `upstream`) has focused unit tests
that exercise the public API in isolation. Fake/mock objects are used for
external dependencies (e.g. `FakeUpstream` in `test_upstream.py`).

### Integration Tests
`test_server_integration.py` starts a real server on a random port with a fake
upstream and sends queries over the loopback interface. This validates the full
pipeline: parse → blocklist → cache → forward → respond.

### Fuzz Tests
`test_fuzz.py` sends 10,000 packets (5,000 random bytes + 5,000 mutated valid
packets) to the parser. Each decode must complete within 100ms. This catches:
- Buffer overflows / index errors
- Infinite loops from pointer chains
- Unhandled exceptions on malformed input

### Thread Safety Tests
Both `test_cache.py` and `test_blocklist.py` include dedicated thread-safety
tests that run concurrent reads and writes to verify no crashes or data
corruption under contention.

## Manual Verification

### With nslookup
Windows 11's nslookup ignores `-port=` (it always uses port 53), so run the
server on port 53 for these:
```powershell
# Start the server
python -m dnssink --port 53

# Normal query
nslookup example.com 127.0.0.1

# TCP query
nslookup -vc example.com 127.0.0.1

# AAAA query
nslookup -type=AAAA google.com 127.0.0.1
```

### With the test client
```powershell
python tools/dnsclient.py example.com A --port 5353
python tools/dnsclient.py example.com AAAA --port 5353
python tools/dnsclient.py example-ads.test A --port 5353  # blocked
python tools/dnsclient.py example.com A --port 5353 --tcp
```

### Load testing
```powershell
python tools/loadtest.py --clients 50 --queries 2000 --mode cache
python tools/loadtest.py --clients 50 --queries 2000 --mode blocked
python tools/loadtest.py --clients 50 --queries 2000 --mode mixed
```
