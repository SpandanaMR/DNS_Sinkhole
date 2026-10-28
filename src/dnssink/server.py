"""DNS server: UDP + TCP listeners and the query-processing pipeline.

Architecture:
    We use a bounded ThreadPoolExecutor for concurrency.

    Why ThreadPoolExecutor (not asyncio):
        1. The standard-library socket API is inherently blocking, and
           wrapping every call in asyncio would add complexity without
           a clear benefit for a project that processes ~10k QPS.
        2. A thread pool is easy to reason about for a student who must
           explain the code in a viva.
        3. The GIL limits CPU-bound parallelism, but DNS query handling
           is I/O-bound (network waits), so threads work fine.

    Pipeline per query:
        1. Parse the raw packet (wire.decode_message).
        2. Check the blocklist → if blocked, return a sinkhole response.
        3. Check the cache → if hit, return the cached response.
        4. Forward to the upstream resolver.
        5. Cache the upstream response.
        6. Return the response to the client.

    Each step is timed; the outcome and latency are recorded by the stats
    collector and written to the query log.
"""

from __future__ import annotations

import dataclasses
import pathlib
import select
import signal
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Set, Tuple

from . import wire
from .blocklist import Blocklist
from .cache import DNSCache
from .config import SinkholeConfig
from .dashboard import DashboardServer
from .logging_setup import flush_logs, get_logger, log_query, setup_logging
from .stats import (
    OUTCOME_BLOCKED,
    OUTCOME_CACHE_HIT,
    OUTCOME_ERROR,
    OUTCOME_FORWARDED,
    OUTCOME_NXDOMAIN,
    OUTCOME_SERVFAIL,
    Stats,
)
from .upstream import UpstreamError, forward_query

logger = get_logger("server")


class ServerContext:
    """Central server context object holding all shared state.

    This is the *only* mutable shared state in the application.
    Every component receives a reference to this context.
    """

    def __init__(self, config: SinkholeConfig, base_path: pathlib.Path) -> None:
        self.config = config
        self.base_path = base_path
        self.blocklist = Blocklist()
        self.cache = DNSCache(
            max_entries=config.cache.max_entries,
            max_negative_ttl=config.cache.max_negative_ttl,
            min_ttl=config.cache.min_ttl,
        )
        self.stats = Stats()
        self._shutdown_event = threading.Event()

    @property
    def should_stop(self) -> bool:
        return self._shutdown_event.is_set()

    def request_shutdown(self) -> None:
        self._shutdown_event.set()

    def wait_for_shutdown(self, timeout: float = None) -> bool:
        return self._shutdown_event.wait(timeout)


# ---------------------------------------------------------------------------
# Request pipeline
# ---------------------------------------------------------------------------

def handle_query(data: bytes, client_addr: Tuple[str, int],
                 ctx: ServerContext) -> bytes:
    """Process a single DNS query through the full pipeline.

    Returns the response bytes to send back to the client.
    """
    start = time.perf_counter()  # Why perf_counter: monotonic() ticks only every ~15.6 ms on Windows
    client_ip = client_addr[0]
    qname = "<unknown>"
    qtype_str = "?"
    outcome = OUTCOME_ERROR

    try:
        # Step 1: Parse.
        try:
            msg = wire.decode_message(data)
        except wire.DNSDecodeError as e:
            logger.warning("Malformed packet from %s: %s", client_ip, e)
            return wire.build_error_response(data, wire.RCODE_FORMERR)

        if not msg.questions:
            return wire.build_error_response(data, wire.RCODE_FORMERR)

        q = msg.questions[0]
        qname = q.qname
        qtype_str = wire.qtype_to_str(q.qtype)

        # Step 2: Blocklist check.
        if ctx.blocklist.is_blocked(qname):
            outcome = OUTCOME_BLOCKED
            return _echo_opt(msg, wire.build_blocked_response(
                msg,
                block_mode=ctx.config.blocklist.block_mode,
                block_ttl=ctx.config.blocklist.block_ttl,
            ), ctx)

        # Step 3: Cache lookup.
        cached = ctx.cache.get(qname, q.qtype, q.qclass)
        if cached is not None:
            outcome = OUTCOME_CACHE_HIT
            return _echo_opt(msg, _build_cached_response(msg, cached), ctx)

        # Step 4: Forward to upstream.
        try:
            resp_data, fwd_latency = forward_query(data, ctx.config.upstream)
        except UpstreamError as e:
            logger.warning("Upstream failed for %s %s: %s", qname, qtype_str, e)
            outcome = OUTCOME_SERVFAIL
            return wire.build_error_response(data, wire.RCODE_SERVFAIL)

        # Step 5: Parse upstream response and cache it.
        try:
            resp_msg = wire.decode_message(resp_data)
            if resp_msg.header.rcode == wire.RCODE_NXDOMAIN:
                outcome = OUTCOME_NXDOMAIN
            else:
                outcome = OUTCOME_FORWARDED
            ctx.cache.put(qname, q.qtype, q.qclass, resp_msg)
        except wire.DNSDecodeError:
            outcome = OUTCOME_FORWARDED
            # Can't parse the upstream response – just forward it as-is.

        # Step 6: Return the response (with an OPT record if the client used EDNS0).
        return _echo_opt(msg, resp_data, ctx)

    except Exception as e:
        logger.exception("Unhandled error processing query from %s: %s", client_ip, e)
        outcome = OUTCOME_ERROR
        return wire.build_error_response(data, wire.RCODE_SERVFAIL)

    finally:
        elapsed = (time.perf_counter() - start) * 1000.0
        ctx.stats.record_query(client_ip, qname, qtype_str, outcome, elapsed)
        log_query(client_ip, qname, qtype_str, outcome, elapsed)


def _echo_opt(query: wire.DNSMessage, resp_data: bytes, ctx: ServerContext) -> bytes:
    """Add an OPT record to *resp_data* if the client's query carried one (R8).

    Why a single helper: blocked and cached answers are built locally and
    the cache strips OPT records, so every answer path must add it back.
    """
    if not query.edns:
        return resp_data
    try:
        resp = wire.decode_message(resp_data)
    except wire.DNSDecodeError:
        return resp_data
    if any(r.rtype == wire.QTYPE_OPT for r in resp.additionals):
        return resp_data
    resp.additionals.append(wire.build_opt_record(ctx.config.edns.max_udp_payload))
    resp.header = dataclasses.replace(resp.header, arcount=len(resp.additionals))
    return wire.encode_message(resp)


def _udp_limit(query_data: bytes, ctx: ServerContext) -> int:
    """Return the largest UDP reply we may send for this query.

    512 bytes without EDNS0; otherwise the client's advertised size, capped
    at our configured maximum and never below 512 (RFC 6891 section 6.2.5).
    """
    try:
        msg = wire.decode_message(query_data)
    except wire.DNSDecodeError:
        return wire.MAX_UDP_PLAIN
    if not msg.edns:
        return wire.MAX_UDP_PLAIN
    return max(wire.MAX_UDP_PLAIN,
               min(msg.edns.udp_payload_size, ctx.config.edns.max_udp_payload))


def _bind_socket(kind: int, addr: str, port: int) -> socket.socket:
    """Create a socket of *kind* and bind it to (addr, port).

    Why not just SO_REUSEADDR: on Windows it lets a *second* process bind
    the same port and silently steal queries, so we first try
    SO_EXCLUSIVEADDRUSE (a clear "in use" error instead).

    Why the fallback: 5353 is also the mDNS port.  Windows and browsers
    already hold 0.0.0.0:5353 in shared mode, so an exclusive (or plain)
    bind fails with WinError 10013 and only a shared bind works there.
    """
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        sock = socket.socket(socket.AF_INET, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            sock.bind((addr, port))
            return sock
        except PermissionError:
            sock.close()
            logger.warning("Port %d is already shared by another program (on 5353 "
                           "this is usually mDNS); binding in shared mode.", port)
    sock = socket.socket(socket.AF_INET, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((addr, port))
    return sock


def _build_cached_response(query: wire.DNSMessage, cached: 'CacheEntry') -> bytes:
    """Build a response from a cache entry, preserving the query's ID."""
    from .cache import CacheEntry  # local import to avoid circular

    resp_header = wire.build_response_header(
        query.header, rcode=cached.rcode, ra=True
    )
    resp = wire.DNSMessage(
        header=resp_header,
        questions=query.questions,
        answers=cached.answers,
        authorities=cached.authorities,
        additionals=cached.additionals,
    )
    resp.header = dataclasses.replace(
        resp.header,
        qdcount=len(resp.questions),
        ancount=len(resp.answers),
        nscount=len(resp.authorities),
        arcount=len(resp.additionals),
    )
    return wire.encode_message(resp)


# ---------------------------------------------------------------------------
# UDP Listener
# ---------------------------------------------------------------------------

class UDPListener:
    """UDP DNS listener."""

    def __init__(self, ctx: ServerContext, executor: ThreadPoolExecutor) -> None:
        self._ctx = ctx
        self._executor = executor
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        """Bind and start the UDP listener in a daemon thread."""
        addr = self._ctx.config.server.listen_address
        port = self._ctx.config.server.listen_port
        self._sock = _bind_socket(socket.SOCK_DGRAM, addr, port)
        self._sock.settimeout(1.0)  # so we can check shutdown
        logger.info("UDP listener started on %s:%d", addr, port)

        self._thread = threading.Thread(
            target=self._listen_loop,
            name="udp-listener",
            daemon=True,
        )
        self._thread.start()

    def _listen_loop(self) -> None:
        """Main UDP receive loop."""
        while not self._ctx.should_stop:
            try:
                data, client_addr = self._sock.recvfrom(4096)
                if data:
                    self._executor.submit(self._handle_udp, data, client_addr)
            except socket.timeout:
                continue
            except OSError:
                if self._ctx.should_stop:
                    break
                logger.exception("UDP socket error")
                break

    def _handle_udp(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        """Handle a single UDP query."""
        try:
            response = handle_query(data, client_addr, self._ctx)
            # Truncation check for UDP (R7c).
            max_size = _udp_limit(data, self._ctx)
            if len(response) > max_size:
                response = wire.truncate_response(response, max_size)

            self._sock.sendto(response, client_addr)
        except Exception as e:
            logger.exception("Error handling UDP query from %s: %s", client_addr, e)

    def stop_accepting(self) -> None:
        """Wait for the receive loop to exit (it polls should_stop every 1 s).

        The socket stays open so queries already queued in the worker pool
        can still send their replies while the pool drains.
        """
        if self._thread:
            self._thread.join(timeout=3)

    def stop(self) -> None:
        """Close the UDP socket (call after the worker pool has drained)."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# TCP Listener
# ---------------------------------------------------------------------------

class TCPListener:
    """TCP DNS listener with connection management."""

    def __init__(self, ctx: ServerContext, executor: ThreadPoolExecutor) -> None:
        self._ctx = ctx
        self._executor = executor   # unused for TCP; see _accept_loop
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._active_connections = 0
        self._conn_threads: Set[threading.Thread] = set()
        self._conn_lock = threading.Lock()

    def start(self) -> None:
        """Bind and start the TCP listener in a daemon thread."""
        addr = self._ctx.config.server.listen_address
        port = self._ctx.config.server.listen_port
        self._sock = _bind_socket(socket.SOCK_STREAM, addr, port)
        self._sock.listen(self._ctx.config.server.max_tcp_connections)
        self._sock.settimeout(1.0)
        logger.info("TCP listener started on %s:%d", addr, port)

        self._thread = threading.Thread(
            target=self._accept_loop,
            name="tcp-listener",
            daemon=True,
        )
        self._thread.start()

    def _accept_loop(self) -> None:
        """Accept TCP connections."""
        while not self._ctx.should_stop:
            try:
                conn, client_addr = self._sock.accept()
                with self._conn_lock:
                    if self._active_connections >= self._ctx.config.server.max_tcp_connections:
                        conn.close()
                        continue
                    self._active_connections += 1
                # Why a dedicated thread instead of the worker pool: a TCP
                # client may sit idle for tcp_idle_timeout seconds.  If it held
                # a pool worker, a few idle TCP clients could starve every UDP
                # query.  The thread count is still bounded by max_tcp_connections.
                t = threading.Thread(target=self._handle_tcp_connection,
                                     args=(conn, client_addr),
                                     name="tcp-conn", daemon=True)
                with self._conn_lock:
                    self._conn_threads.add(t)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if self._ctx.should_stop:
                    break
                logger.exception("TCP accept error")
                break

    def _handle_tcp_connection(self, conn: socket.socket,
                               client_addr: Tuple[str, int]) -> None:
        """Handle a TCP connection, processing multiple queries per connection."""
        idle_timeout = self._ctx.config.server.tcp_idle_timeout
        try:
            conn.settimeout(idle_timeout)
            while not self._ctx.should_stop:
                # Wait for the next query, waking every second to notice shutdown.
                if not self._wait_readable(conn, idle_timeout):
                    break
                # Read the 2-byte length prefix.
                try:
                    len_data = self._recv_exact(conn, 2)
                except (ConnectionError, socket.timeout, OSError):
                    break
                if not len_data:
                    break
                msg_len = struct.unpack("!H", len_data)[0]
                if msg_len < wire.HEADER_SIZE or msg_len > 65535:
                    break

                try:
                    query_data = self._recv_exact(conn, msg_len)
                except (ConnectionError, socket.timeout, OSError):
                    break
                if not query_data:
                    break

                response = handle_query(query_data, client_addr, self._ctx)
                # Send response with 2-byte length prefix.
                resp_frame = struct.pack("!H", len(response)) + response
                try:
                    conn.sendall(resp_frame)
                except (ConnectionError, OSError):
                    break
        except Exception as e:
            logger.debug("TCP connection error from %s: %s", client_addr, e)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._conn_lock:
                self._active_connections -= 1
                self._conn_threads.discard(threading.current_thread())

    def _wait_readable(self, conn: socket.socket, idle_timeout: float) -> bool:
        """Block until *conn* has data; False on idle timeout or shutdown."""
        deadline = time.monotonic() + idle_timeout
        while not self._ctx.should_stop:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            readable, _, _ = select.select([conn], [], [], min(1.0, remaining))
            if readable:
                return True
        return False

    @staticmethod
    def _recv_exact(conn: socket.socket, nbytes: int) -> bytes:
        """Receive exactly *nbytes* from a TCP connection."""
        buf = bytearray()
        while len(buf) < nbytes:
            chunk = conn.recv(nbytes - len(buf))
            if not chunk:
                return b""
            buf.extend(chunk)
        return bytes(buf)

    def stop(self) -> None:
        """Stop accepting, let open connections finish their query, close."""
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._conn_lock:
            threads = list(self._conn_threads)
        for t in threads:
            t.join(timeout=5)


# ---------------------------------------------------------------------------
# Main server
# ---------------------------------------------------------------------------

class DNSSinkholeServer:
    """Top-level server that coordinates all components."""

    def __init__(self, config: SinkholeConfig,
                 base_path: Optional[pathlib.Path] = None) -> None:
        self._base_path = base_path or pathlib.Path(".")
        self._ctx = ServerContext(config, self._base_path)
        self._executor = ThreadPoolExecutor(
            max_workers=config.server.worker_threads,
            thread_name_prefix="dns-worker",
        )
        self._udp: Optional[UDPListener] = None
        self._tcp: Optional[TCPListener] = None
        self._dashboard: Optional[DashboardServer] = None

    @property
    def context(self) -> ServerContext:
        """Access the server context (for testing)."""
        return self._ctx

    def start(self) -> None:
        """Start all server components."""
        cfg = self._ctx.config

        # Setup logging.
        setup_logging(cfg.logging, self._base_path)
        logger.info("DNS Sinkhole starting...")
        logger.info("Config: listen=%s:%d, upstream=%s, block_mode=%s",
                     cfg.server.listen_address, cfg.server.listen_port,
                     cfg.upstream.primary, cfg.blocklist.block_mode)

        # Load blocklist.
        count = self._ctx.blocklist.load(
            hosts_files=cfg.blocklist.hosts_files,
            domain_files=cfg.blocklist.domain_files,
            base_path=self._base_path,
        )
        logger.info("Blocklist loaded: %d domains in %.1fms",
                     count, self._ctx.blocklist.load_time_ms)

        # Start listeners.
        self._udp = UDPListener(self._ctx, self._executor)
        self._udp.start()

        self._tcp = TCPListener(self._ctx, self._executor)
        self._tcp.start()

        # Start dashboard.
        self._dashboard = DashboardServer(
            host=cfg.server.listen_address,
            port=cfg.server.dashboard_port,
            stats=self._ctx.stats,
            reload_callback=self._reload_blocklist,
            flush_callback=self._flush_cache,
        )
        self._dashboard.start()

        logger.info("DNS Sinkhole is ready.")

    def run_forever(self) -> None:
        """Block until shutdown is requested (Ctrl+C)."""
        # Install signal handlers for graceful shutdown.
        original_sigint = signal.getsignal(signal.SIGINT)

        def _handle_signal(signum: int, frame: object) -> None:
            logger.info("Received signal %d, shutting down...", signum)
            self._ctx.request_shutdown()

        signal.signal(signal.SIGINT, _handle_signal)
        try:
            signal.signal(signal.SIGBREAK, _handle_signal)  # Windows Ctrl+Break
        except (AttributeError, OSError):
            pass

        try:
            # Why a loop with a short timeout: on Windows a blocking
            # Event.wait() cannot be interrupted, so the Ctrl+C handler would
            # never get a chance to run.  Waking every 0.5 s lets it run.
            while not self._ctx.wait_for_shutdown(timeout=0.5):
                pass
        finally:
            signal.signal(signal.SIGINT, original_sigint)

        self.stop()

    def stop(self) -> None:
        """Graceful shutdown: stop listeners, drain workers, close sockets."""
        logger.info("Shutting down...")
        # 1. Stop accepting: listener loops see the flag within 1 s.
        self._ctx.request_shutdown()
        if self._dashboard:
            self._dashboard.stop()
        if self._udp:
            self._udp.stop_accepting()
        if self._tcp:
            self._tcp.stop()        # finishes in-flight TCP queries, then closes
        # 2. Drain: queued UDP queries still complete (no cancel_futures),
        #    because their replies need the UDP socket that is still open.
        self._executor.shutdown(wait=True)
        # 3. Close sockets, then 4. flush logs.
        if self._udp:
            self._udp.stop()
        logger.info("DNS Sinkhole stopped.")
        flush_logs()

    def _reload_blocklist(self) -> str:
        """Reload the blocklist (called from dashboard)."""
        cfg = self._ctx.config
        count = self._ctx.blocklist.load(
            hosts_files=cfg.blocklist.hosts_files,
            domain_files=cfg.blocklist.domain_files,
            base_path=self._base_path,
        )
        msg = f"Blocklist reloaded: {count} domains in {self._ctx.blocklist.load_time_ms:.1f}ms"
        logger.info(msg)
        return msg

    def _flush_cache(self) -> str:
        """Flush the DNS cache (called from dashboard)."""
        removed = self._ctx.cache.flush()
        msg = f"Cache flushed: {removed} entries removed"
        logger.info(msg)
        return msg
