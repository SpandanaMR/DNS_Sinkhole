"""Configuration management for DNS Sinkhole.

Loads settings from a TOML config file (using tomllib from the standard
library) and merges with command-line overrides.  All configuration lives
in a single immutable-ish dataclass so there is no global mutable state.

Why dataclasses:
    They give us type hints, sensible __repr__, and immutability intent
    without pulling in any third-party library.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import tomllib
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ServerConfig:
    """Network listener settings."""
    listen_address: str = "127.0.0.1"
    listen_port: int = 5353
    dashboard_port: int = 8080
    worker_threads: int = 8
    tcp_idle_timeout: int = 30
    max_tcp_connections: int = 50


@dataclasses.dataclass(frozen=True)
class UpstreamConfig:
    """Upstream resolver settings."""
    primary: str = "8.8.8.8"
    secondary: Optional[str] = "8.8.4.4"
    port: int = 53
    timeout: float = 2.0
    retries: int = 2


@dataclasses.dataclass(frozen=True)
class CacheConfig:
    """Cache behaviour settings."""
    max_entries: int = 10000
    max_negative_ttl: int = 300
    min_ttl: int = 0


@dataclasses.dataclass(frozen=True)
class BlocklistConfig:
    """Blocklist file paths and response mode."""
    hosts_files: List[str] = dataclasses.field(
        default_factory=lambda: ["blocklists/sample_hosts.txt"]
    )
    domain_files: List[str] = dataclasses.field(
        default_factory=lambda: ["blocklists/sample_domains.txt"]
    )
    block_mode: str = "null"   # "null" or "nxdomain"
    block_ttl: int = 60


@dataclasses.dataclass(frozen=True)
class LoggingConfig:
    """Logging settings."""
    log_file: str = "dns_sinkhole.log"
    max_bytes: int = 10_485_760
    backup_count: int = 5
    level: str = "INFO"


@dataclasses.dataclass(frozen=True)
class EdnsConfig:
    """EDNS0 settings."""
    max_udp_payload: int = 1232


@dataclasses.dataclass(frozen=True)
class SinkholeConfig:
    """Top-level configuration container.

    This is the *only* object that the rest of the application receives.
    There is no global mutable state – every component is handed a reference
    to this frozen dataclass at construction time.
    """
    server: ServerConfig = dataclasses.field(default_factory=ServerConfig)
    upstream: UpstreamConfig = dataclasses.field(default_factory=UpstreamConfig)
    cache: CacheConfig = dataclasses.field(default_factory=CacheConfig)
    blocklist: BlocklistConfig = dataclasses.field(default_factory=BlocklistConfig)
    logging: LoggingConfig = dataclasses.field(default_factory=LoggingConfig)
    edns: EdnsConfig = dataclasses.field(default_factory=EdnsConfig)


# ---------------------------------------------------------------------------
# TOML loader
# ---------------------------------------------------------------------------

def _merge_section(dc_class: type, toml_dict: dict) -> dict:
    """Return a dict of keyword arguments for *dc_class*, taking only keys
    that actually belong to the dataclass and ignoring unknown ones."""
    valid = {f.name for f in dataclasses.fields(dc_class)}
    return {k: v for k, v in toml_dict.items() if k in valid}


def load_config(path: pathlib.Path) -> SinkholeConfig:
    """Load configuration from a TOML file and return a SinkholeConfig."""
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    sections = {}
    field_map = {f.name: f for f in dataclasses.fields(SinkholeConfig)}

    for name, field in field_map.items():
        # Why default_factory and not field.type: with
        # "from __future__ import annotations", field.type is the *string*
        # "ServerConfig", not the class.  default_factory is the class itself.
        section_cls = field.default_factory
        if name in raw and isinstance(raw[name], dict):
            sections[name] = section_cls(**_merge_section(section_cls, raw[name]))
        else:
            sections[name] = section_cls()

    return SinkholeConfig(**sections)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_argparser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    p = argparse.ArgumentParser(
        prog="dnssink",
        description="DNS Sinkhole / Caching Resolver",
    )
    p.add_argument(
        "--config", "-c",
        type=pathlib.Path,
        default=pathlib.Path("config.toml"),
        help="Path to TOML configuration file (default: config.toml)",
    )
    p.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override listen port",
    )
    p.add_argument(
        "--address", "-a",
        type=str,
        default=None,
        help="Override listen address",
    )
    p.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Override dashboard HTTP port",
    )
    p.add_argument(
        "--upstream",
        type=str,
        default=None,
        help="Override primary upstream resolver IP",
    )
    p.add_argument(
        "--block-mode",
        choices=["null", "nxdomain"],
        default=None,
        help="Override block response mode",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level",
    )
    p.add_argument(
        "--reload-blocklist",
        action="store_true",
        help="Ask a running server (via its dashboard port) to reload the blocklist, then exit",
    )
    return p


def apply_cli_overrides(cfg: SinkholeConfig, args: argparse.Namespace) -> SinkholeConfig:
    """Return a *new* SinkholeConfig with CLI overrides applied."""
    replacements: dict = {}

    if args.port is not None:
        replacements["server"] = dataclasses.replace(
            cfg.server, listen_port=args.port
        )
    if args.address is not None:
        srv = replacements.get("server", cfg.server)
        replacements["server"] = dataclasses.replace(srv, listen_address=args.address)
    if args.dashboard_port is not None:
        srv = replacements.get("server", cfg.server)
        replacements["server"] = dataclasses.replace(srv, dashboard_port=args.dashboard_port)
    if args.upstream is not None:
        replacements["upstream"] = dataclasses.replace(
            cfg.upstream, primary=args.upstream
        )
    if args.block_mode is not None:
        replacements["blocklist"] = dataclasses.replace(
            cfg.blocklist, block_mode=args.block_mode
        )
    if args.log_level is not None:
        replacements["logging"] = dataclasses.replace(
            cfg.logging, level=args.log_level
        )

    if replacements:
        return dataclasses.replace(cfg, **replacements)
    return cfg
