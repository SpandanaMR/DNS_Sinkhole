"""HTTP dashboard for DNS Sinkhole live statistics.

Serves a single-page HTML dashboard with auto-refreshing charts/tables
using plain HTML + CSS + inline SVG bars.  No external CDN or build step.

Endpoints:
    GET  /             – the dashboard HTML page
    GET  /api/stats    – JSON statistics snapshot
    POST /api/reload   – reload the blocklist
    POST /api/flush    – flush the DNS cache

Uses the standard library ``http.server`` module (no Flask).

Why http.server:
    The project constraints forbid external dependencies for the dashboard.
    http.server is simple, synchronous, and perfectly adequate for a
    localhost-only monitoring page.
"""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Callable, Optional

from .logging_setup import get_logger

if TYPE_CHECKING:
    from .stats import Stats

logger = get_logger("dashboard")


# ---------------------------------------------------------------------------
# HTML template (embedded to avoid external files)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DNS Sinkhole Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

  :root {
    --bg-primary: #0f0f1a;
    --bg-secondary: #1a1a2e;
    --bg-card: #16213e;
    --bg-card-hover: #1c2a4a;
    --text-primary: #e8e8f0;
    --text-secondary: #a0a0c0;
    --accent-blue: #4fc3f7;
    --accent-green: #69f0ae;
    --accent-red: #ff5252;
    --accent-amber: #ffd740;
    --accent-purple: #ce93d8;
    --accent-cyan: #00e5ff;
    --border: rgba(255,255,255,0.06);
    --glass: rgba(255,255,255,0.03);
    --shadow: 0 8px 32px rgba(0,0,0,0.4);
    --radius: 16px;
    --transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
  }

  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Animated background gradient */
  body::before {
    content: '';
    position: fixed;
    top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: radial-gradient(ellipse at 20% 50%, rgba(79,195,247,0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(206,147,216,0.04) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 80%, rgba(105,240,174,0.03) 0%, transparent 50%);
    animation: bgShift 20s ease-in-out infinite alternate;
    z-index: 0;
  }
  @keyframes bgShift {
    0% { transform: translate(0,0) rotate(0deg); }
    100% { transform: translate(-5%,-5%) rotate(3deg); }
  }

  .container {
    position: relative; z-index: 1;
    max-width: 1400px; margin: 0 auto; padding: 24px;
  }

  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 0 32px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 32px;
  }
  header h1 {
    font-size: 1.8rem; font-weight: 700;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  header .status {
    display: flex; align-items: center; gap: 8px;
    font-size: 0.85rem; color: var(--text-secondary);
  }
  header .status .dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--accent-green);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { box-shadow: 0 0 0 0 rgba(105,240,174,0.4); }
    50% { box-shadow: 0 0 0 8px rgba(105,240,174,0); }
  }

  .controls {
    display: flex; gap: 12px; margin-bottom: 28px;
  }
  .btn {
    padding: 10px 20px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
    color: var(--text-primary);
    font-family: inherit; font-size: 0.85rem; font-weight: 500;
    cursor: pointer;
    transition: var(--transition);
  }
  .btn:hover {
    background: var(--bg-card-hover);
    border-color: var(--accent-blue);
    transform: translateY(-1px);
    box-shadow: 0 4px 16px rgba(79,195,247,0.15);
  }
  .btn.danger:hover { border-color: var(--accent-red); box-shadow: 0 4px 16px rgba(255,82,82,0.15); }

  /* Stats cards */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    transition: var(--transition);
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 3px;
    border-radius: var(--radius) var(--radius) 0 0;
  }
  .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan)); }
  .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--accent-green), #b9f6ca); }
  .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--accent-red), #ff8a80); }
  .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--accent-amber), #ffe57f); }
  .stat-card:nth-child(5)::before { background: linear-gradient(90deg, var(--accent-purple), #f8bbd0); }
  .stat-card:nth-child(6)::before { background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue)); }
  .stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow); }
  .stat-card .label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px; }
  .stat-card .value { font-size: 1.8rem; font-weight: 700; line-height: 1; }
  .stat-card .sub { font-size: 0.75rem; color: var(--text-secondary); margin-top: 6px; }

  /* Sections */
  .section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 24px;
    transition: var(--transition);
  }
  .section:hover { box-shadow: var(--shadow); }
  .section h2 {
    font-size: 1rem; font-weight: 600; margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px;
  }
  .section h2 .icon { font-size: 1.2rem; }

  /* Bar chart */
  .bar-chart { display: flex; flex-direction: column; gap: 8px; }
  .bar-row { display: flex; align-items: center; gap: 12px; }
  .bar-label { min-width: 220px; font-size: 0.82rem; color: var(--text-secondary); word-break: break-all; }
  .bar-track { flex: 1; height: 24px; background: var(--glass); border-radius: 6px; overflow: hidden; position: relative; }
  .bar-fill {
    height: 100%; border-radius: 6px;
    transition: width 0.8s cubic-bezier(0.4,0,0.2,1);
    position: relative;
  }
  .bar-fill.blue { background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan)); }
  .bar-fill.red { background: linear-gradient(90deg, var(--accent-red), #ff8a80); }
  .bar-fill.green { background: linear-gradient(90deg, var(--accent-green), #b9f6ca); }
  .bar-fill.purple { background: linear-gradient(90deg, var(--accent-purple), #f8bbd0); }
  .bar-value { min-width: 60px; text-align: right; font-size: 0.82rem; font-weight: 600; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  thead th {
    text-align: left; padding: 10px 12px;
    color: var(--text-secondary); font-weight: 500;
    border-bottom: 1px solid var(--border);
    text-transform: uppercase; letter-spacing: 0.06em; font-size: 0.72rem;
  }
  tbody td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tbody tr { transition: background 0.2s; }
  tbody tr:hover { background: var(--glass); }

  .outcome-badge {
    display: inline-block; padding: 2px 8px; border-radius: 6px;
    font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
  }
  .outcome-BLOCKED { background: rgba(255,82,82,0.15); color: var(--accent-red); }
  .outcome-CACHE_HIT { background: rgba(105,240,174,0.15); color: var(--accent-green); }
  .outcome-FORWARDED { background: rgba(79,195,247,0.15); color: var(--accent-blue); }
  .outcome-NXDOMAIN { background: rgba(255,215,64,0.15); color: var(--accent-amber); }
  .outcome-SERVFAIL { background: rgba(206,147,216,0.15); color: var(--accent-purple); }
  .outcome-ERROR { background: rgba(255,82,82,0.25); color: var(--accent-red); }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
  @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }

  .latency-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap: 12px; }
  .latency-card {
    background: var(--glass); border-radius: 10px; padding: 14px;
    border: 1px solid var(--border);
  }
  .latency-card .lbl { font-size: 0.72rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 6px; }
  .latency-card .vals { display: flex; gap: 12px; flex-wrap: wrap; }
  .latency-card .val { font-size: 0.9rem; font-weight: 600; }
  .latency-card .val span { font-size: 0.65rem; color: var(--text-secondary); font-weight: 400; }

  #toast {
    position: fixed; bottom: 24px; right: 24px;
    background: var(--bg-card); border: 1px solid var(--accent-green);
    color: var(--accent-green); padding: 12px 20px;
    border-radius: 10px; font-size: 0.85rem;
    transform: translateY(100px); opacity: 0;
    transition: all 0.4s cubic-bezier(0.4,0,0.2,1);
    z-index: 100;
  }
  #toast.show { transform: translateY(0); opacity: 1; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>&#x1F6E1; DNS Sinkhole</h1>
    <div class="status"><div class="dot"></div><span id="lastUpdate">Connecting...</span></div>
  </header>

  <div class="controls">
    <button class="btn" onclick="reloadBlocklist()">&#x1F504; Reload Blocklist</button>
    <button class="btn danger" onclick="flushCache()">&#x1F5D1; Flush Cache</button>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="label">Total Queries</div><div class="value" id="totalQueries">0</div></div>
    <div class="stat-card"><div class="label">Queries / sec</div><div class="value" id="qps">0</div></div>
    <div class="stat-card"><div class="label">Cache Hit Rate</div><div class="value" id="cacheHitRate">0%</div><div class="sub" id="cacheHitSub"></div></div>
    <div class="stat-card"><div class="label">Blocked</div><div class="value" id="blocked">0</div><div class="sub" id="blockedSub"></div></div>
    <div class="stat-card"><div class="label">SERVFAIL / Errors</div><div class="value" id="errors">0</div></div>
    <div class="stat-card"><div class="label">Upstream Failures</div><div class="value" id="upstreamFail">0</div></div>
  </div>

  <div class="section">
    <h2><span class="icon">&#x23F1;</span> Latency (ms)</h2>
    <div class="latency-grid" id="latencyGrid"></div>
  </div>

  <div class="two-col">
    <div class="section">
      <h2><span class="icon">&#x1F50D;</span> Top Queried Domains</h2>
      <div class="bar-chart" id="topQueried"></div>
    </div>
    <div class="section">
      <h2><span class="icon">&#x1F6AB;</span> Top Blocked Domains</h2>
      <div class="bar-chart" id="topBlocked"></div>
    </div>
  </div>

  <div class="section">
    <h2><span class="icon">&#x1F4CB;</span> Recent Queries</h2>
    <div style="overflow-x:auto;">
    <table>
      <thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Outcome</th><th>Latency</th></tr></thead>
      <tbody id="recentQueries"></tbody>
    </table>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
const REFRESH_MS = 2000;

function fmt(n) { return typeof n === 'number' ? n.toLocaleString() : n; }

function renderBars(containerId, items, colorClass) {
  const el = document.getElementById(containerId);
  if (!items || !items.length) { el.innerHTML = '<div style="color:var(--text-secondary);font-size:0.82rem;">No data yet</div>'; return; }
  const max = items[0][1] || 1;
  el.innerHTML = items.map(([name, count]) => {
    const pct = Math.max(2, (count / max) * 100);
    return `<div class="bar-row">
      <div class="bar-label">${esc(name)}</div>
      <div class="bar-track"><div class="bar-fill ${colorClass}" style="width:${pct}%"></div></div>
      <div class="bar-value">${fmt(count)}</div>
    </div>`;
  }).join('');
}

function renderLatency(latency) {
  const el = document.getElementById('latencyGrid');
  if (!latency || !Object.keys(latency).length) { el.innerHTML = '<div style="color:var(--text-secondary)">No data yet</div>'; return; }
  el.innerHTML = Object.entries(latency).map(([outcome, v]) => `
    <div class="latency-card">
      <div class="lbl">${esc(outcome)}</div>
      <div class="vals">
        <div class="val">${v.avg.toFixed(2)} <span>avg</span></div>
        <div class="val">${v.p95.toFixed(2)} <span>p95</span></div>
        <div class="val">${v.p99.toFixed(2)} <span>p99</span></div>
      </div>
    </div>`).join('');
}

function renderRecent(queries) {
  const el = document.getElementById('recentQueries');
  if (!queries || !queries.length) { el.innerHTML = '<tr><td colspan="6" style="color:var(--text-secondary)">No queries yet</td></tr>'; return; }
  el.innerHTML = queries.map(q => {
    const t = new Date(q.timestamp * 1000);
    const ts = t.toLocaleTimeString();
    return `<tr>
      <td>${ts}</td><td>${esc(q.client_ip)}</td><td>${esc(q.qname)}</td>
      <td>${esc(q.qtype)}</td>
      <td><span class="outcome-badge outcome-${q.outcome}">${q.outcome}</span></td>
      <td>${q.latency_ms.toFixed(2)} ms</td>
    </tr>`;
  }).join('');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

async function refresh() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('totalQueries').textContent = fmt(d.total_queries);
    document.getElementById('qps').textContent = d.qps.toFixed(1);
    document.getElementById('cacheHitRate').textContent = d.cache_hit_rate.toFixed(1) + '%';
    document.getElementById('cacheHitSub').textContent = `${fmt(d.cache_hits)} hits / ${fmt(d.forwarded)} fwd`;
    document.getElementById('blocked').textContent = fmt(d.blocked);
    document.getElementById('blockedSub').textContent = d.blocked_pct.toFixed(1) + '% of total';
    document.getElementById('errors').textContent = `${fmt(d.servfail)} / ${fmt(d.errors)}`;
    document.getElementById('upstreamFail').textContent = fmt(d.upstream_failures);
    document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
    renderBars('topQueried', d.top_queried, 'blue');
    renderBars('topBlocked', d.top_blocked, 'red');
    renderLatency(d.latency);
    renderRecent(d.recent_queries);
  } catch(e) { document.getElementById('lastUpdate').textContent = 'Error: ' + e.message; }
}

async function reloadBlocklist() {
  try { const r = await fetch('/api/reload', {method:'POST'}); const d = await r.json(); showToast(d.message || 'Blocklist reloaded'); } catch(e) { showToast('Error: '+e.message); }
}

async function flushCache() {
  try { const r = await fetch('/api/flush', {method:'POST'}); const d = await r.json(); showToast(d.message || 'Cache flushed'); } catch(e) { showToast('Error: '+e.message); }
}

setInterval(refresh, REFRESH_MS);
refresh();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests for the dashboard."""

    # Class-level references set by DashboardServer.
    stats: Optional[Stats] = None
    reload_callback: Optional[Callable[[], str]] = None
    flush_callback: Optional[Callable[[], str]] = None

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Suppress default stderr logging; use our logger instead."""
        logger.debug("HTTP %s", format % args)

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/":
            self._send_html(DASHBOARD_HTML)
        elif self.path == "/api/stats":
            self._send_json(self.stats.snapshot() if self.stats else {})
        else:
            self._send_error(404, "Not Found")

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == "/api/reload":
            msg = "No reload callback configured"
            if self.reload_callback:
                msg = self.reload_callback()
            self._send_json({"message": msg})
        elif self.path == "/api/flush":
            msg = "No flush callback configured"
            if self.flush_callback:
                msg = self.flush_callback()
            self._send_json({"message": msg})
        else:
            self._send_error(404, "Not Found")

    # Helpers
    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: object) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int, message: str) -> None:
        self.send_response(code)
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Dashboard Server
# ---------------------------------------------------------------------------

class DashboardServer:
    """Manage the HTTP dashboard server in a background thread."""

    def __init__(self, host: str, port: int, stats: Stats,
                 reload_callback: Optional[Callable[[], str]] = None,
                 flush_callback: Optional[Callable[[], str]] = None) -> None:
        self._host = host
        self._port = port
        self._stats = stats
        self._reload_callback = reload_callback
        self._flush_callback = flush_callback
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the dashboard HTTP server in a daemon thread."""
        # Set class-level state on the handler.
        DashboardHandler.stats = self._stats
        DashboardHandler.reload_callback = self._reload_callback
        DashboardHandler.flush_callback = self._flush_callback

        self._httpd = HTTPServer((self._host, self._port), DashboardHandler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="dashboard-http",
            daemon=True,
        )
        self._thread.start()
        logger.info("Dashboard started at http://%s:%d", self._host, self._port)

    def stop(self) -> None:
        """Shutdown the HTTP server."""
        if self._httpd:
            self._httpd.shutdown()
            logger.info("Dashboard stopped")
