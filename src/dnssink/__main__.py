"""CLI entry point: ``python -m dnssink``."""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.error
import urllib.request

from .config import apply_cli_overrides, build_argparser, load_config, SinkholeConfig
from .server import DNSSinkholeServer


def main() -> None:
    """Parse arguments, load config, and start the server."""
    parser = build_argparser()
    args = parser.parse_args()

    # Load config.
    config_path: pathlib.Path = args.config
    if config_path.exists():
        cfg = load_config(config_path)
    else:
        print(f"Config file not found: {config_path}. Using defaults.", file=sys.stderr)
        cfg = SinkholeConfig()

    # Apply CLI overrides.
    cfg = apply_cli_overrides(cfg, args)

    if args.reload_blocklist:
        sys.exit(_request_reload(cfg.server.listen_address, cfg.server.dashboard_port))

    # Determine base path (project root) for resolving relative paths.
    base_path = config_path.resolve().parent if config_path.exists() else pathlib.Path.cwd()

    # Start server.
    server = DNSSinkholeServer(cfg, base_path)
    server.start()
    server.run_forever()


def _request_reload(host: str, dashboard_port: int) -> int:
    """Ask an already-running server to reload its blocklist; returns exit code.

    Why over HTTP: the dashboard already exposes POST /api/reload, and Windows
    has no SIGHUP, so this is the simplest portable "signal" to a running server.
    """
    url = f"http://{host}:{dashboard_port}/api/reload"
    try:
        req = urllib.request.Request(url, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(json.loads(resp.read().decode()).get("message", "Reloaded"))
        return 0
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"Could not reach a running server at {url}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main()
