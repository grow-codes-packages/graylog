"""GELF transports (UDP chunked, TCP null-framed with TLS and reconnect, HTTP bulk) and the
log exporters that plug them into the shared batching log clients.

Every transport is synchronous and thread-safe; :meth:`asend` runs :meth:`send` in a worker
thread for asyncio code.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import gzip as _gzip
import os
import select
import socket
import ssl
import threading
import time
import zlib
from collections.abc import Callable, Mapping, Sequence
from typing import Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx

from ._core import (
    BaseConfig,
    CancelledError,
    CancelToken,
    ConfigError,
    HttpTransport,
    Request,
    RetryPolicy,
    ServiceError,
    TimeoutError,
    TlsConfig,
    UnavailableError,
    ValidationError,
)
from ._logging import ExportResult, LogExporter, LogRecord
from .config import DEFAULT_GELF_PORT, GelfProtocol, bare_host
from .gelf import GelfMessage

__all__ = [
    "DEFAULT_UDP_CHUNK_SIZE",
    "GELF_CHUNK_HEADER_SIZE",
    "GELF_CHUNK_MAGIC",
    "GELF_MAX_CHUNKS",
    "GelfCompression",
    "GelfHttpTransport",
    "GelfLogExporter",
    "GelfSendResult",
    "GelfTcpTransport",
    "GelfTransport",
    "GelfUdpTransport",
    "ThreadedAsyncLogExporter",
    "encode_gelf_udp",
    "tls_context",
]

GelfCompression = Literal["gzip", "zlib", "none"]
"""Payload compression of :class:`GelfUdpTransport`."""

#: GELF chunk magic bytes.
GELF_CHUNK_MAGIC = b"\x1e\x0f"
#: Bytes of a chunk header: magic (2) + message id (8) + sequence (1) + count (1).
GELF_CHUNK_HEADER_SIZE = 12
#: Most chunks Graylog reassembles for one message.
GELF_MAX_CHUNKS = 128
#: Default chunk size (bytes per datagram, header included), safe for a 1500-byte MTU.
DEFAULT_UDP_CHUNK_SIZE = 1420


@dataclasses.dataclass(frozen=True)
class GelfSendResult:
    """Outcome of :meth:`GelfTransport.send`."""

    #: Messages handed to the network.
    sent: int
    #: Messages rejected client side (e.g. too large for UDP).
    rejected: int = 0
    #: Why messages were rejected.
    error: ServiceError | None = None


@runtime_checkable
class GelfTransport(Protocol):
    """Sends GELF messages to a Graylog input."""

    #: ``udp``, ``tcp`` or ``http``.
    protocol: GelfProtocol

    def send(
        self,
        messages: Sequence[GelfMessage],
        *,
        gzip: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> GelfSendResult:
        """Send the messages.

        Network failures raise (:class:`UnavailableError`, :class:`TimeoutError`,
        :class:`CancelledError`); client-side rejections are counted in the result.
        """
        ...

    async def asend(
        self, messages: Sequence[GelfMessage], *, gzip: bool | None = None
    ) -> GelfSendResult:
        """:meth:`send` in a worker thread."""
        ...

    def close(self) -> None:
        """Release sockets; idempotent. Later sends raise :class:`ConfigError`."""
        ...


class _TransportBase:
    protocol: GelfProtocol

    def send(
        self,
        messages: Sequence[GelfMessage],
        *,
        gzip: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> GelfSendResult:
        raise NotImplementedError

    async def asend(
        self, messages: Sequence[GelfMessage], *, gzip: bool | None = None
    ) -> GelfSendResult:
        """:meth:`send` in a worker thread (cancel the task to stop waiting)."""
        return await asyncio.to_thread(self.send, messages, gzip=gzip)

    def close(self) -> None:
        raise NotImplementedError

    async def aclose(self) -> None:
        """:meth:`close` in a worker thread."""
        await asyncio.to_thread(self.close)

    def __enter__(self) -> _TransportBase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _check_host(host: str, op: str) -> None:
    if not isinstance(host, str) or not host.strip():
        raise ConfigError(f"{op}: host must not be blank")


def _check_port(port: int, op: str) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError(f"{op}: port must be an integer 1..65535")


def _network_error(op: str, exc: BaseException) -> ServiceError:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TimeoutError(f"{op}: timed out")
    name = type(exc).__name__
    errno = getattr(exc, "errno", None)
    detail = f"{name}, errno {errno}" if errno else name
    return UnavailableError(f"{op}: network error ({detail})")


def _check_cancel(cancel: CancelToken | None, op: str) -> None:
    if cancel is not None and cancel.cancelled:
        raise CancelledError(f"{op}: cancelled")


# --------------------------------------------------------------------------- UDP


def encode_gelf_udp(
    payload: bytes,
    *,
    compression: GelfCompression = "gzip",
    chunk_size: int = DEFAULT_UDP_CHUNK_SIZE,
    message_id: bytes | None = None,
) -> list[bytes]:
    """Compress (optional) and split a GELF payload into datagrams.

    One datagram when it fits ``chunk_size``, else chunks ``0x1e 0x0f | id(8) | seq | count |
    data``. Raises :class:`ValidationError` when more than 128 chunks would be needed.
    """
    if compression == "gzip":
        data = _gzip.compress(payload)
    elif compression == "zlib":
        data = zlib.compress(payload)
    else:
        data = bytes(payload)
    if len(data) <= chunk_size:
        return [data]
    per = chunk_size - GELF_CHUNK_HEADER_SIZE
    count = -(-len(data) // per)
    if count > GELF_MAX_CHUNKS:
        raise ValidationError(
            f"gelf.udp: message needs {count} chunks (max {GELF_MAX_CHUNKS}); "
            "use TCP or HTTP for large messages"
        )
    msg_id = (message_id or os.urandom(8))[:8].ljust(8, b"\0")
    return [
        GELF_CHUNK_MAGIC + msg_id + bytes((seq, count)) + data[seq * per : (seq + 1) * per]
        for seq in range(count)
    ]


class GelfUdpTransport(_TransportBase):
    """GELF over UDP: fire-and-forget datagrams, compressed, chunked up to 128 chunks.

    Args:
        host: Graylog host.
        port: GELF UDP port (default 12201).
        compression: ``gzip`` (default), ``zlib`` or ``none``.
        chunk_size: bytes per datagram including the 12-byte chunk header (64..65507).
    """

    protocol: GelfProtocol = "udp"

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_GELF_PORT,
        *,
        compression: GelfCompression = "gzip",
        chunk_size: int = DEFAULT_UDP_CHUNK_SIZE,
    ) -> None:
        _check_host(host, "gelf.udp")
        _check_port(port, "gelf.udp")
        if compression not in ("gzip", "zlib", "none"):
            raise ConfigError("gelf.udp: compression must be gzip, zlib or none")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
            raise ConfigError("gelf.udp: chunk_size must be an integer 64..65507")
        if not 64 <= chunk_size <= 65507:
            raise ConfigError("gelf.udp: chunk_size must be an integer 64..65507")
        self.host = bare_host(host)
        self.port = port
        self.compression: GelfCompression = compression
        self.chunk_size = chunk_size
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._addr: tuple[str, int] | None = None
        self._closed = False

    def _socket(self) -> tuple[socket.socket, tuple[str, int]]:
        if self._sock is None or self._addr is None:
            family, _, _, _, addr = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_DGRAM
            )[0]
            self._sock = socket.socket(family, socket.SOCK_DGRAM)
            self._addr = (str(addr[0]), int(addr[1]))
        return self._sock, self._addr

    def send(
        self,
        messages: Sequence[GelfMessage],
        *,
        gzip: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> GelfSendResult:
        """Send each message as one datagram or a chunk sequence (``gzip`` is ignored)."""
        sent = rejected = 0
        error: ServiceError | None = None
        with self._lock:
            if self._closed:
                raise ConfigError("gelf.udp: transport is closed")
            for message in messages:
                _check_cancel(cancel, "gelf.udp")
                try:
                    datagrams = encode_gelf_udp(
                        message.encode(), compression=self.compression, chunk_size=self.chunk_size
                    )
                except ValidationError as exc:
                    rejected += 1
                    error = exc
                    continue
                try:
                    sock, addr = self._socket()
                    for datagram in datagrams:
                        sock.sendto(datagram, addr)
                except OSError as exc:
                    raise _network_error("gelf.udp", exc) from exc
                sent += 1
        return GelfSendResult(sent, rejected, error)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._sock is not None:
                self._sock.close()
                self._sock = None


# --------------------------------------------------------------------------- TCP


def tls_context(tls: TlsConfig) -> ssl.SSLContext:
    """An :class:`ssl.SSLContext` for the GELF TCP transport (CA bundle, client cert, skip)."""
    try:
        ctx = ssl.create_default_context(cafile=tls.ca_cert_path, cadata=tls.ca_cert_pem)
        if tls.client_cert_path and tls.client_key_path:
            ctx.load_cert_chain(tls.client_cert_path, tls.client_key_path)
    except (OSError, ssl.SSLError, ValueError):
        raise ConfigError("gelf.tcp: TLS certificate files could not be loaded") from None
    if tls.insecure_skip_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _is_ip(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
        except OSError:
            continue
        return True
    return False


class GelfTcpTransport(_TransportBase):
    """GELF over TCP: one persistent connection, each message JSON + one NUL byte, optional TLS.

    A failed connect or write closes the connection and retries the whole batch on a new one
    with backoff (at-least-once: a batch may be delivered twice after a broken connection).

    Args:
        host: Graylog host.
        port: GELF TCP port (default 12201).
        tls: ``True`` or a :class:`TlsConfig` to connect with TLS (default plain TCP).
        server_hostname: SNI / certificate host name (default ``host`` unless it is an IP).
        connect_timeout_s: connection setup timeout (default 10 s).
        write_timeout_s: deadline for writing one batch (default 30 s).
        retry: reconnect policy (default ``RetryPolicy()``, 3 retries).
    """

    protocol: GelfProtocol = "tcp"

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_GELF_PORT,
        *,
        tls: bool | TlsConfig = False,
        server_hostname: str | None = None,
        connect_timeout_s: float = 10.0,
        write_timeout_s: float = 30.0,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        _check_host(host, "gelf.tcp")
        _check_port(port, "gelf.tcp")
        if not connect_timeout_s > 0 or not write_timeout_s > 0:
            raise ConfigError("gelf.tcp: timeouts must be positive")
        self.host = bare_host(host)
        self.port = port
        self.connect_timeout_s = float(connect_timeout_s)
        self.write_timeout_s = float(write_timeout_s)
        self.retry = retry or RetryPolicy()
        self._sleep = sleep
        self._ssl: ssl.SSLContext | None = None
        if tls is not False:
            self._ssl = tls_context(TlsConfig() if tls is True else tls)
        if server_hostname is not None:
            self._server_hostname: str | None = server_hostname
        else:
            self._server_hostname = None if _is_ip(self.host) else self.host
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._closed = False
        #: Connections opened so far (diagnostics, tests).
        self.connections = 0

    @property
    def secure(self) -> bool:
        """Whether the transport uses TLS."""
        return self._ssl is not None

    @staticmethod
    def frame(messages: Sequence[GelfMessage]) -> bytes:
        """Encode messages as NUL-terminated JSON frames."""
        return b"".join(m.encode() + b"\0" for m in messages)

    def _connect(self) -> socket.socket:
        if self._sock is not None and not self._peer_closed(self._sock):
            return self._sock
        self._drop()
        sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout_s)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self._ssl is not None:
                sock = self._ssl.wrap_socket(sock, server_hostname=self._server_hostname)
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        self.connections += 1
        return sock

    @staticmethod
    def _peer_closed(sock: socket.socket) -> bool:
        """True when the server closed the connection (readable with EOF) or it errored."""
        try:
            readable, _, errored = select.select([sock], [], [sock], 0)
            if errored:
                return True
            if readable:
                return sock.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True
        return False

    def _drop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _wait(self, delay: float, cancel: CancelToken | None) -> None:
        if self._sleep is not None:
            self._sleep(delay)
        elif cancel is not None:
            cancel.wait(delay)
        else:
            time.sleep(delay)

    def send(
        self,
        messages: Sequence[GelfMessage],
        *,
        gzip: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> GelfSendResult:
        """Write all messages on the connection (``gzip`` is ignored: GELF TCP is uncompressed)."""
        with self._lock:
            if self._closed:
                raise ConfigError("gelf.tcp: transport is closed")
            if not messages:
                return GelfSendResult(0)
            data = self.frame(messages)
            attempt = 0
            while True:
                _check_cancel(cancel, "gelf.tcp")
                try:
                    sock = self._connect()
                    sock.settimeout(self.write_timeout_s)
                    sock.sendall(data)
                    return GelfSendResult(len(messages))
                except (OSError, ValueError) as exc:
                    self._drop()
                    error = _network_error("gelf.tcp", exc)
                    if attempt >= self.retry.max_retries:
                        raise error from exc
                self._wait(self.retry.backoff(attempt), cancel)
                attempt += 1

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._sock is not None:
                with contextlib.suppress(OSError):
                    self._sock.shutdown(socket.SHUT_RDWR)
                self._drop()


# --------------------------------------------------------------------------- HTTP


class GelfHttpTransport(_TransportBase):
    """GELF over HTTP: ``POST <url>`` with JSON bodies, bulk and gzip by default.

    Bulk bodies are newline-delimited and **every** message ends with ``\\n`` (Graylog 7.0 drops
    the first message of a later request on a kept-alive connection otherwise). Graylog answers
    202 even for messages it drops, so messages are validated client side. Retries, timeouts,
    TLS, proxy and hooks come from the shared HTTP transport.

    Args:
        url: full endpoint, e.g. ``http://graylog:12202/gelf``.
        gzip: gzip request bodies (``Content-Encoding: gzip``); default True.
        bulk: all messages of a batch in one request (input option ``enable_bulk_receiving``);
            when False, one request per message. Default True.
        headers: extra headers, e.g. the input's ``authorization_header_name``/``value``.
        config: timeouts, retry, TLS, proxy, hooks and logger (e.g. a ``GraylogConfig``); its
            ``url`` and ``headers`` are ignored.
        http_transport: test seam (an ``httpx`` transport).
    """

    protocol: GelfProtocol = "http"

    def __init__(
        self,
        url: str,
        *,
        gzip: bool = True,
        bulk: bool = True,
        headers: Mapping[str, str] | None = None,
        config: BaseConfig | None = None,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        try:
            parts = urlsplit(url)
        except ValueError:
            parts = None
        if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConfigError("gelf.http: url must be an http(s) URL")
        self.url = url
        self.gzip = gzip
        self.bulk = bulk
        self._headers = dict(headers or {})
        self._path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        base = config or BaseConfig(url=url)
        http_config = BaseConfig(
            url=f"{parts.scheme}://{parts.netloc}",
            connect_timeout=base.connect_timeout,
            request_timeout=base.request_timeout,
            total_timeout=base.total_timeout,
            retry=base.retry,
            tls=base.tls,
            proxy=base.proxy,
            user_agent_suffix=base.user_agent_suffix,
            hooks=base.hooks,
            logger=base.logger,
        )
        secrets = [v for v in self._headers.values() if len(v) >= 4]
        self._http = HttpTransport(
            http_config, known_secrets=lambda: secrets, http_transport=http_transport
        )

    def send(
        self,
        messages: Sequence[GelfMessage],
        *,
        gzip: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> GelfSendResult:
        """POST the messages (one bulk request, or one request each with ``bulk=False``)."""
        if not messages:
            return GelfSendResult(0)
        use_gzip = self.gzip if gzip is None else gzip
        groups = [list(messages)] if self.bulk else [[m] for m in messages]
        sent = 0
        for group in groups:
            body = "".join(m.to_json_str() + "\n" for m in group).encode("utf-8")
            headers = {**self._headers, "Content-Type": "application/json"}
            if use_gzip:
                body = _gzip.compress(body)
                headers["Content-Encoding"] = "gzip"
            self._http.request(
                Request("POST", self._path, operation="gelf.http", content=body, headers=headers),
                cancel=cancel,
            )
            sent += len(group)
        return GelfSendResult(sent)

    def close(self) -> None:
        self._http.close()


# --------------------------------------------------------------------------- exporters


class GelfLogExporter:
    """:class:`LogExporter` that converts records with :meth:`GelfMessage.from_log_record` and
    sends them through a :class:`GelfTransport`. Use it with ``BatchingLogClient`` (or
    ``client.log_client()``).

    Args:
        transport: the GELF transport (closed by :meth:`shutdown`).
        host: GELF ``host`` for records without ``resource["host.name"]``.
    """

    def __init__(self, transport: GelfTransport, *, host: str | None = None) -> None:
        self.transport = transport
        self.host = host

    def export(self, records: Sequence[LogRecord], *, gzip: bool, timeout_s: float) -> ExportResult:
        messages = [GelfMessage.from_log_record(r, host=self.host) for r in records]
        result = self.transport.send(messages, gzip=gzip)
        return ExportResult(accepted=result.sent, rejected=result.rejected, error=result.error)

    def shutdown(self) -> None:
        self.transport.close()


class ThreadedAsyncLogExporter:
    """``AsyncLogExporter`` that runs a synchronous :class:`LogExporter` in worker threads."""

    def __init__(self, exporter: LogExporter) -> None:
        self.exporter = exporter

    async def export(
        self, records: Sequence[LogRecord], *, gzip: bool, timeout_s: float
    ) -> ExportResult:
        return await asyncio.to_thread(
            self.exporter.export, list(records), gzip=gzip, timeout_s=timeout_s
        )

    async def shutdown(self) -> None:
        await asyncio.to_thread(self.exporter.shutdown)
