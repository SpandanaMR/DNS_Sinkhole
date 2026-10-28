"""Upstream DNS resolver with timeout, retry, failover, and TCP fallback.

Design decisions:
    - Each query uses a *fresh* UDP socket and a randomised transaction ID
      (for spoofing resistance – if an attacker can predict the ID and
      source port, they can inject forged responses).
    - We verify that the response ID matches the one we sent, and that
      the response came from the expected upstream address.
    - On TC (truncation) bit in the upstream response, we automatically
      retry the query over TCP.
    - Failover: if the primary upstream fails all retries, we try the
      secondary upstream.

Why a fresh socket per query:
    Re-using sockets means an attacker only needs to guess the fixed source
    port.  A fresh socket with an OS-assigned port increases entropy.
"""

from __future__ import annotations

import secrets
import socket
import struct
import time
from typing import Optional, Tuple

from . import wire
from .config import UpstreamConfig


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def forward_query(query_data: bytes, config: UpstreamConfig) -> Tuple[bytes, float]:
    """Forward a DNS query to the upstream resolver.

    Returns (response_bytes, latency_ms).
    Raises UpstreamError if all attempts fail.

    The query's transaction ID is replaced with a random one for the
    upstream request, and the original ID is restored in the response.
    """
    if len(query_data) < wire.HEADER_SIZE:
        raise UpstreamError("Query too short to forward")

    original_id = struct.unpack_from("!H", query_data, 0)[0]
    # Use a random transaction ID for the upstream query.  Why secrets and not
    # random: random (Mersenne Twister) is predictable, which helps spoofers.
    upstream_id = secrets.randbelow(0x10000)
    upstream_query = struct.pack("!H", upstream_id) + query_data[2:]

    start_time = time.perf_counter()

    # Try primary, then secondary.
    upstreams = [config.primary]
    if config.secondary:
        upstreams.append(config.secondary)

    last_error: Optional[Exception] = None

    for upstream_ip in upstreams:
        try:
            response = _query_with_retries(
                upstream_query, upstream_id, upstream_ip,
                config.port, config.timeout, config.retries
            )
            # Check for truncation – retry over TCP if needed.
            if len(response) >= wire.HEADER_SIZE:
                flags = struct.unpack_from("!H", response, 2)[0]
                if flags & wire.FLAG_TC:
                    try:
                        response = _query_tcp(
                            upstream_query, upstream_id, upstream_ip,
                            config.port, config.timeout
                        )
                    except UpstreamError:
                        pass  # Use the truncated UDP response.

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            # Restore the original transaction ID.
            response = struct.pack("!H", original_id) + response[2:]
            return response, elapsed_ms

        except UpstreamError as e:
            last_error = e
            continue

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    raise UpstreamError(
        f"All upstreams failed after {elapsed_ms:.1f}ms: {last_error}"
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _query_with_retries(query: bytes, expected_id: int,
                        upstream_ip: str, port: int,
                        timeout: float, retries: int) -> bytes:
    """Send a UDP query with retries. Returns the response bytes."""
    last_error: Optional[Exception] = None

    for attempt in range(1 + retries):
        try:
            return _query_udp(query, expected_id, upstream_ip, port, timeout)
        except UpstreamError as e:
            last_error = e
            continue

    raise UpstreamError(
        f"UDP query to {upstream_ip}:{port} failed after "
        f"{1 + retries} attempts: {last_error}"
    )


def _query_udp(query: bytes, expected_id: int,
               upstream_ip: str, port: int, timeout: float) -> bytes:
    """Send a single UDP query and return the response.

    Validates that the response transaction ID and source address match.
    """
    # Determine address family from the upstream IP.
    af = _detect_address_family(upstream_ip)
    sock = socket.socket(af, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (upstream_ip, port))

        # We may receive stale responses from a previous query on
        # this port, so loop until we get a matching ID or time out.
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpstreamError(f"Timeout waiting for response from {upstream_ip}:{port}")
            sock.settimeout(remaining)
            data, addr = sock.recvfrom(4096)

            # Validate source address.
            if addr[0] != upstream_ip:
                continue  # Spoofed source, discard.

            # Validate transaction ID.
            if len(data) >= 2:
                resp_id = struct.unpack_from("!H", data, 0)[0]
                if resp_id == expected_id:
                    return data
            # Mismatch – keep waiting.
    except socket.timeout:
        raise UpstreamError(f"Timeout from {upstream_ip}:{port}")
    except OSError as e:
        raise UpstreamError(f"Socket error querying {upstream_ip}:{port}: {e}")
    finally:
        sock.close()


def _query_tcp(query: bytes, expected_id: int,
               upstream_ip: str, port: int, timeout: float) -> bytes:
    """Send a query over TCP (with the 2-byte length prefix).

    TCP DNS uses a two-byte big-endian length prefix before each message
    so the receiver knows where one message ends and the next begins.
    """
    af = _detect_address_family(upstream_ip)
    sock = socket.socket(af, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((upstream_ip, port))

        # Send: 2-byte length prefix + query.
        length_prefix = struct.pack("!H", len(query))
        sock.sendall(length_prefix + query)

        # Receive: 2-byte length prefix + response.
        resp_len_data = _recv_exact(sock, 2, timeout)
        resp_len = struct.unpack("!H", resp_len_data)[0]
        if resp_len < wire.HEADER_SIZE:
            raise UpstreamError(f"TCP response too short: {resp_len}")
        response = _recv_exact(sock, resp_len, timeout)

        # Validate transaction ID.
        resp_id = struct.unpack_from("!H", response, 0)[0]
        if resp_id != expected_id:
            raise UpstreamError(
                f"TCP response ID mismatch: expected {expected_id}, got {resp_id}"
            )
        return response

    except socket.timeout:
        raise UpstreamError(f"TCP timeout from {upstream_ip}:{port}")
    except OSError as e:
        raise UpstreamError(f"TCP error querying {upstream_ip}:{port}: {e}")
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, nbytes: int, timeout: float) -> bytes:
    """Receive exactly *nbytes* from a TCP socket."""
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < nbytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UpstreamError("Timeout receiving TCP data")
        sock.settimeout(remaining)
        chunk = sock.recv(nbytes - len(buf))
        if not chunk:
            raise UpstreamError("Connection closed by upstream")
        buf.extend(chunk)
    return bytes(buf)


def _detect_address_family(ip: str) -> socket.AddressFamily:
    """Detect whether *ip* is IPv4 or IPv6."""
    if ":" in ip:
        return socket.AF_INET6
    return socket.AF_INET


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class UpstreamError(Exception):
    """Raised when upstream resolution fails."""
