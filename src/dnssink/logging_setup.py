"""Logging setup with rotating file handler.

Uses the standard library ``logging`` and ``logging.handlers`` modules.
Provides both a structured query logger (for the per-query log with
timestamp, client IP, qname, qtype, outcome, latency) and the standard
application logger.
"""

from __future__ import annotations

import logging
import logging.handlers
import pathlib
from typing import Optional

from .config import LoggingConfig


# The application-wide logger name.
APP_LOGGER_NAME = "dnssink"
QUERY_LOGGER_NAME = "dnssink.queries"


def setup_logging(cfg: LoggingConfig, base_path: Optional[pathlib.Path] = None) -> None:
    """Configure application and query loggers.

    - Application log goes to both the console (INFO+) and a rotating file.
    - Query log goes to a separate rotating file with a structured format.
    """
    level = getattr(logging, cfg.level.upper(), logging.INFO)

    log_path = pathlib.Path(cfg.log_file)
    if not log_path.is_absolute() and base_path:
        log_path = base_path / log_path

    # Ensure the log directory exists.
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Application logger
    # ------------------------------------------------------------------
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    app_logger.setLevel(level)
    app_logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler.
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(fmt)
    app_logger.addHandler(console)

    # Rotating file handler.
    file_handler = logging.handlers.RotatingFileHandler(
        str(log_path),
        maxBytes=cfg.max_bytes,
        backupCount=cfg.backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(fmt)
    app_logger.addHandler(file_handler)

    # ------------------------------------------------------------------
    # Query logger (structured, for analysis and dashboard)
    # ------------------------------------------------------------------
    query_logger = logging.getLogger(QUERY_LOGGER_NAME)
    query_logger.setLevel(logging.INFO)
    query_logger.handlers.clear()
    query_logger.propagate = False   # don't duplicate into the app log

    query_fmt = logging.Formatter(
        "%(asctime)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    query_log_path = log_path.with_name("query_log.txt")
    query_handler = logging.handlers.RotatingFileHandler(
        str(query_log_path),
        maxBytes=cfg.max_bytes,
        backupCount=cfg.backup_count,
        encoding="utf-8",
    )
    query_handler.setLevel(logging.INFO)
    query_handler.setFormatter(query_fmt)
    query_logger.addHandler(query_handler)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a child logger under the application namespace."""
    if name:
        return logging.getLogger(f"{APP_LOGGER_NAME}.{name}")
    return logging.getLogger(APP_LOGGER_NAME)


def get_query_logger() -> logging.Logger:
    """Return the structured query logger."""
    return logging.getLogger(QUERY_LOGGER_NAME)


def log_query(client_ip: str, qname: str, qtype: str,
              outcome: str, latency_ms: float) -> None:
    """Log a single query to the query log file.

    Format: ``client_ip qname qtype outcome latency_ms``
    """
    logger = get_query_logger()
    logger.info(
        "%s %s %s %s %.3fms",
        client_ip, qname, qtype, outcome, latency_ms,
    )


def flush_logs() -> None:
    """Flush every handler on the app and query loggers (used at shutdown)."""
    for name in (APP_LOGGER_NAME, QUERY_LOGGER_NAME):
        for handler in logging.getLogger(name).handlers:
            handler.flush()
