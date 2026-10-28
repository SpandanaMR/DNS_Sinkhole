"""Blocklist manager with suffix-matching via reversed-label trie.

Supports two file formats:
    1. Hosts-style: ``0.0.0.0 domain.example`` (or ``127.0.0.1 ...``)
    2. Plain domain list: one domain per line

Matching semantics:
    Blocking ``ads.example.com`` also blocks ``x.ads.example.com``
    (subdomain matching).  This is implemented with a reversed-label
    trie so lookups are O(number of labels in the query).

Why a reversed-label trie:
    A naive set with suffix walking is O(labels), but the constant factor
    is higher because you create substrings.  A trie stored with labels
    reversed is a natural tree walk that stops as soon as a match is found.
    It also supports efficient insertion of large (100 k+) blocklists.

Thread safety:
    The trie is replaced atomically (single reference swap) on reload,
    so no lock is needed for reads.  The reload method is protected by
    a threading.Lock to prevent concurrent reloads.
"""

from __future__ import annotations

import pathlib
import threading
import time
from typing import Dict, List, Optional, Set


# Names that real hosts files (e.g. StevenBlack) list in their header for the
# local machine.  Blocking them would break localhost or, for "local",
# sinkhole every *.local (mDNS) name, so they are skipped when loading.
_HOSTS_FILE_SPECIAL_NAMES = frozenset({
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
})


class _TrieNode:
    """A single node in the reversed-label trie."""
    __slots__ = ("children", "is_terminal")

    def __init__(self) -> None:
        self.children: Dict[str, _TrieNode] = {}
        self.is_terminal: bool = False


class Blocklist:
    """Thread-safe domain blocklist with subdomain matching."""

    def __init__(self) -> None:
        self._root = _TrieNode()
        self._count: int = 0
        self._reload_lock = threading.Lock()
        self._load_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def count(self) -> int:
        """Number of blocked domains currently loaded."""
        return self._count

    @property
    def load_time_ms(self) -> float:
        """Time in milliseconds taken by the last load/reload."""
        return self._load_time

    def is_blocked(self, domain: str) -> bool:
        """Return True if *domain* (or any parent) is in the blocklist.

        The lookup walks the trie from the TLD towards the subdomain,
        stopping as soon as a terminal node is found.

        Example: if ``ads.example.com`` is blocked, then both
        ``ads.example.com`` and ``x.y.ads.example.com`` match.
        """
        labels = domain.lower().rstrip(".").split(".")
        node = self._root
        # Walk labels in reverse (TLD first).
        for label in reversed(labels):
            if label not in node.children:
                return False
            node = node.children[label]
            if node.is_terminal:
                return True
        return node.is_terminal

    def load(self, hosts_files: Optional[List[str]] = None,
             domain_files: Optional[List[str]] = None,
             base_path: Optional[pathlib.Path] = None) -> int:
        """Load blocklist files and rebuild the trie.

        Returns the total number of unique domains loaded.
        This method is thread-safe; concurrent calls are serialised.
        """
        with self._reload_lock:
            start = time.perf_counter()
            domains: Set[str] = set()

            for path_str in (hosts_files or []):
                p = self._resolve_path(path_str, base_path)
                if p.exists():
                    domains.update(self._parse_hosts_file(p))

            for path_str in (domain_files or []):
                p = self._resolve_path(path_str, base_path)
                if p.exists():
                    domains.update(self._parse_domain_file(p))

            # Build a new trie and swap it in atomically.
            new_root = _TrieNode()
            count = 0
            for domain in domains:
                d = domain.lower().rstrip(".")
                if d:
                    self._insert(new_root, d)
                    count += 1

            # Atomic swap – readers see either the old or new trie, never
            # a half-built one.
            self._root = new_root
            self._count = count
            self._load_time = (time.perf_counter() - start) * 1000.0
            return count

    # ------------------------------------------------------------------
    # File parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_path(path_str: str, base_path: Optional[pathlib.Path]) -> pathlib.Path:
        """Resolve a possibly-relative path against *base_path*."""
        p = pathlib.Path(path_str)
        if not p.is_absolute() and base_path:
            p = base_path / p
        return p

    @staticmethod
    def _parse_hosts_file(path: pathlib.Path) -> List[str]:
        """Parse a hosts-style file, extracting domain names.

        Format: ``<ip> <domain> [aliases...]``
        Lines starting with '#' are comments.
        """
        domains: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        # parts[0] is the IP, parts[1:] are domains.
                        for d in parts[1:]:
                            d = d.strip().lower()
                            if d.startswith("#"):
                                break   # inline comment: rest of line ignored
                            if d and d not in _HOSTS_FILE_SPECIAL_NAMES:
                                domains.append(d)
        except OSError:
            pass
        return domains

    @staticmethod
    def _parse_domain_file(path: pathlib.Path) -> List[str]:
        """Parse a plain domain list file (one domain per line)."""
        domains: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    domains.append(line.lower())
        except OSError:
            pass
        return domains

    # ------------------------------------------------------------------
    # Trie operations
    # ------------------------------------------------------------------

    @staticmethod
    def _insert(root: _TrieNode, domain: str) -> None:
        """Insert a domain into the trie (labels reversed)."""
        labels = domain.split(".")
        node = root
        for label in reversed(labels):
            if label not in node.children:
                node.children[label] = _TrieNode()
            node = node.children[label]
        node.is_terminal = True
