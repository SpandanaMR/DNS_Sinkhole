"""Tests for config.py: loading the real config.toml and CLI overrides."""

from __future__ import annotations

import pathlib

from dnssink.config import (
    BlocklistConfig,
    ServerConfig,
    SinkholeConfig,
    apply_cli_overrides,
    build_argparser,
    load_config,
)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_load_shipped_config_toml() -> None:
    """The config.toml shipped with the project must load without errors."""
    cfg = load_config(PROJECT_ROOT / "config.toml")
    assert isinstance(cfg, SinkholeConfig)
    assert isinstance(cfg.server, ServerConfig)
    assert isinstance(cfg.blocklist, BlocklistConfig)
    assert cfg.server.listen_address == "127.0.0.1"


def test_partial_toml_uses_defaults(tmp_path: pathlib.Path) -> None:
    """Missing sections and unknown keys fall back to defaults / are ignored."""
    path = tmp_path / "c.toml"
    path.write_text('[server]\nlisten_port = 5400\nbogus_key = 1\n', encoding="utf-8")
    cfg = load_config(path)
    assert cfg.server.listen_port == 5400
    assert cfg.upstream.primary == "8.8.8.8"


def test_cli_overrides() -> None:
    """Command-line flags override values from the file."""
    args = build_argparser().parse_args(
        ["--port", "5400", "--upstream", "1.1.1.1", "--block-mode", "nxdomain"]
    )
    cfg = apply_cli_overrides(SinkholeConfig(), args)
    assert cfg.server.listen_port == 5400
    assert cfg.upstream.primary == "1.1.1.1"
    assert cfg.blocklist.block_mode == "nxdomain"
