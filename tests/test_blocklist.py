"""Unit tests for blocklist.py: domain blocking with subdomain matching."""

from __future__ import annotations

import pathlib
import tempfile
import threading
import time

import pytest

import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dnssink.blocklist import Blocklist


# ---------------------------------------------------------------------------
# Basic matching
# ---------------------------------------------------------------------------

class TestBlocklistMatching:
    def _loaded(self, domains: list[str]) -> Blocklist:
        """Create a blocklist from a list of domains."""
        bl = Blocklist()
        # Write a temp domain file.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for d in domains:
                f.write(d + "\n")
            f.flush()
            bl.load(domain_files=[f.name])
        return bl

    def test_exact_match(self) -> None:
        bl = self._loaded(["ads.example.com"])
        assert bl.is_blocked("ads.example.com") is True
        assert bl.is_blocked("example.com") is False
        assert bl.is_blocked("other.com") is False

    def test_subdomain_match(self) -> None:
        bl = self._loaded(["ads.example.com"])
        assert bl.is_blocked("x.ads.example.com") is True
        assert bl.is_blocked("y.x.ads.example.com") is True

    def test_parent_not_blocked(self) -> None:
        bl = self._loaded(["ads.example.com"])
        assert bl.is_blocked("example.com") is False

    def test_tld_block(self) -> None:
        bl = self._loaded(["test"])
        assert bl.is_blocked("test") is True
        assert bl.is_blocked("anything.test") is True
        assert bl.is_blocked("deep.sub.test") is True

    def test_case_insensitive(self) -> None:
        bl = self._loaded(["ADS.Example.COM"])
        assert bl.is_blocked("ads.example.com") is True
        assert bl.is_blocked("ADS.EXAMPLE.COM") is True

    def test_trailing_dot(self) -> None:
        bl = self._loaded(["ads.example.com."])
        assert bl.is_blocked("ads.example.com") is True
        assert bl.is_blocked("ads.example.com.") is True

    def test_not_blocked(self) -> None:
        bl = self._loaded(["ads.example.com"])
        assert bl.is_blocked("safe.example.com") is False
        assert bl.is_blocked("google.com") is False

    def test_multiple_domains(self) -> None:
        bl = self._loaded(["ads.com", "tracker.net", "malware.org"])
        assert bl.is_blocked("ads.com") is True
        assert bl.is_blocked("sub.tracker.net") is True
        assert bl.is_blocked("malware.org") is True
        assert bl.is_blocked("safe.org") is False

    def test_count(self) -> None:
        bl = self._loaded(["a.com", "b.com", "c.com"])
        assert bl.count == 3


# ---------------------------------------------------------------------------
# File parsing
# ---------------------------------------------------------------------------

class TestBlocklistFiles:
    def test_hosts_file(self, tmp_path: pathlib.Path) -> None:
        hosts_file = tmp_path / "hosts.txt"
        hosts_file.write_text(
            "# comment\n"
            "0.0.0.0 ads.example.com\n"
            "127.0.0.1 tracker.example.com extra.example.com\n"
            "\n"
            "0.0.0.0 malware.test\n"
        )
        bl = Blocklist()
        bl.load(hosts_files=[str(hosts_file)])
        assert bl.count == 4
        assert bl.is_blocked("ads.example.com") is True
        assert bl.is_blocked("tracker.example.com") is True
        assert bl.is_blocked("extra.example.com") is True
        assert bl.is_blocked("malware.test") is True

    def test_hosts_file_header_entries_skipped(self, tmp_path: pathlib.Path) -> None:
        """StevenBlack-style header lines must not block localhost or *.local."""
        hosts_file = tmp_path / "hosts.txt"
        hosts_file.write_text(
            "127.0.0.1 localhost\n127.0.0.1 local\n0.0.0.0 0.0.0.0\n"
            "::1 ip6-localhost ip6-loopback\n"
            "0.0.0.0 ads.example.test # inline comment.test\n"
        )
        bl = Blocklist()
        assert bl.load(hosts_files=[str(hosts_file)]) == 1
        assert bl.is_blocked("ads.example.test")
        assert not bl.is_blocked("localhost")
        assert not bl.is_blocked("printer.local")
        assert not bl.is_blocked("comment.test")

    def test_domain_file(self, tmp_path: pathlib.Path) -> None:
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("# blocked domains\nads.test\ntracker.test\n")
        bl = Blocklist()
        bl.load(domain_files=[str(domain_file)])
        assert bl.count == 2
        assert bl.is_blocked("ads.test") is True
        assert bl.is_blocked("sub.tracker.test") is True

    def test_missing_file(self) -> None:
        bl = Blocklist()
        count = bl.load(domain_files=["nonexistent_file_12345.txt"])
        assert count == 0

    def test_combined_files(self, tmp_path: pathlib.Path) -> None:
        hosts_file = tmp_path / "hosts.txt"
        hosts_file.write_text("0.0.0.0 ads.test\n")
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("tracker.test\n")
        bl = Blocklist()
        bl.load(hosts_files=[str(hosts_file)], domain_files=[str(domain_file)])
        assert bl.count == 2
        assert bl.is_blocked("ads.test") is True
        assert bl.is_blocked("tracker.test") is True


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------

class TestBlocklistReload:
    def test_reload_replaces(self, tmp_path: pathlib.Path) -> None:
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("ads.test\n")
        bl = Blocklist()
        bl.load(domain_files=[str(domain_file)])
        assert bl.is_blocked("ads.test") is True

        # Overwrite with different content.
        domain_file.write_text("tracker.test\n")
        bl.load(domain_files=[str(domain_file)])
        assert bl.is_blocked("ads.test") is False
        assert bl.is_blocked("tracker.test") is True

    def test_load_time_is_positive(self, tmp_path: pathlib.Path) -> None:
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("a.test\nb.test\n")
        bl = Blocklist()
        bl.load(domain_files=[str(domain_file)])
        assert bl.load_time_ms >= 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestBlocklistThreadSafety:
    def test_concurrent_reads_during_reload(self, tmp_path: pathlib.Path) -> None:
        """Verify reads don't crash during a reload."""
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("\n".join(f"domain{i}.test" for i in range(1000)))
        bl = Blocklist()
        bl.load(domain_files=[str(domain_file)])

        errors: list[Exception] = []
        stop = threading.Event()

        def reader() -> None:
            while not stop.is_set():
                try:
                    bl.is_blocked("domain500.test")
                    bl.is_blocked("notblocked.example.com")
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()

        # Reload several times while readers are running.
        for _ in range(5):
            domain_file.write_text("\n".join(f"newdomain{i}.test" for i in range(500)))
            bl.load(domain_files=[str(domain_file)])
            time.sleep(0.01)

        stop.set()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Errors during concurrent access: {errors}"


# ---------------------------------------------------------------------------
# Scale test (quick)
# ---------------------------------------------------------------------------

class TestBlocklistScale:
    def test_large_blocklist_load(self, tmp_path: pathlib.Path) -> None:
        """Load 10,000 domains and verify performance is acceptable."""
        domain_file = tmp_path / "large.txt"
        domains = [f"subdomain{i}.example-{i % 100}.test" for i in range(10000)]
        domain_file.write_text("\n".join(domains))
        bl = Blocklist()
        bl.load(domain_files=[str(domain_file)])
        assert bl.count == 10000
        # Spot-check some lookups.
        assert bl.is_blocked("subdomain0.example-0.test") is True
        assert bl.is_blocked("deep.subdomain5000.example-0.test") is True
        assert bl.is_blocked("notblocked.com") is False
        # Load time should be reasonable (< 5 seconds).
        assert bl.load_time_ms < 5000
