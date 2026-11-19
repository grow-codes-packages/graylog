"""GELF transports (UDP chunking/compression, TCP framing/reconnect/TLS, HTTP bulk/gzip) and the
exporters, against local sockets and respx."""

from __future__ import annotations

import asyncio
import gzip
import json
import socket
import ssl
import threading
import time
import zlib
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

import grow_graylog as sdk
from _fixtures import response
from _support import fast_retry


def msg(text: str = "hello", **fields: Any) -> sdk.GelfMessage:
    return sdk.GelfMessage("h", text, fields=fields)


# --------------------------------------------------------------------------- UDP


def test_encode_udp_single_and_compression() -> None:
    payload = msg().encode()
    assert sdk.encode_gelf_udp(payload, compression="none") == [payload]
    (gz,) = sdk.encode_gelf_udp(payload)
    assert gz[:2] == b"\x1f\x8b" and gzip.decompress(gz) == payload
    (zl,) = sdk.encode_gelf_udp(payload, compression="zlib")
    assert zl[:1] == b"\x78" and zlib.decompress(zl) == payload


def test_encode_udp_chunks() -> None:
    payload = bytes(range(256)) * 20  # 5120 bytes, incompressible enough with none
    chunks = sdk.encode_gelf_udp(
        payload, compression="none", chunk_size=1000, message_id=b"12345678"
    )
    per = 1000 - sdk.GELF_CHUNK_HEADER_SIZE
    assert len(chunks) == -(-len(payload) // per)
    for seq, chunk in enumerate(chunks):
        assert chunk[:2] == sdk.GELF_CHUNK_MAGIC
        assert chunk[2:10] == b"12345678"
        assert chunk[10] == seq and chunk[11] == len(chunks)
        assert len(chunk) <= 1000
    assert b"".join(c[12:] for c in chunks) == payload
    short_id = sdk.encode_gelf_udp(payload, compression="none", chunk_size=1000, message_id=b"ab")
    assert short_id[0][2:10] == b"ab\0\0\0\0\0\0"


def test_encode_udp_chunk_limit() -> None:
    exact = b"x" * ((64 - 12) * 128)
    assert len(sdk.encode_gelf_udp(exact, compression="none", chunk_size=64)) == 128
    with pytest.raises(sdk.ValidationError, match="128"):
        sdk.encode_gelf_udp(exact + b"x", compression="none", chunk_size=64)


@pytest.fixture
def udp_server() -> Iterator[socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2)
    yield sock
    sock.close()


def test_udp_transport_sends(udp_server: socket.socket) -> None:
    port = udp_server.getsockname()[1]
    t = sdk.GelfUdpTransport("127.0.0.1", port, compression="none", chunk_size=200)
    big = msg("big", data="y" * 500)
    huge = sdk.GelfMessage("h", "z" * 40_000)
    result = t.send([msg("one"), big, huge])
    assert (result.sent, result.rejected) == (2, 1)
    assert isinstance(result.error, sdk.ValidationError)
    first = udp_server.recv(65535)
    assert json.loads(first)["short_message"] == "one"
    chunks = [udp_server.recv(65535) for _ in range(-(-len(big.encode()) // 188))]
    assert all(c[:2] == sdk.GELF_CHUNK_MAGIC for c in chunks)
    assert json.loads(b"".join(c[12:] for c in chunks))["_data"] == "y" * 500
    assert asyncio.run(t.asend([msg("async")])).sent == 1
    assert json.loads(udp_server.recv(65535))["short_message"] == "async"
    token = sdk.CancelToken()
    token.cancel()
    with pytest.raises(sdk.CancelledError):
        t.send([msg()], cancel=token)
    t.close()
    t.close()
    with pytest.raises(sdk.ConfigError):
        t.send([msg()])


def test_udp_transport_network_error() -> None:
    t = sdk.GelfUdpTransport("no-such-host.invalid", 12201)
    with pytest.raises(sdk.UnavailableError):
        t.send([msg()])
    t.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": ""},
        {"host": "h", "port": 0},
        {"host": "h", "port": True},
        {"host": "h", "compression": "lz4"},
        {"host": "h", "chunk_size": 10},
        {"host": "h", "chunk_size": 1.5},
    ],
)
def test_udp_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(sdk.ConfigError):
        sdk.GelfUdpTransport(**kwargs)


# --------------------------------------------------------------------------- TCP


class TcpServer:
    """Accepts connections, records every byte; optionally closes after the first read."""

    def __init__(self, close_after_read: bool = False) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.data = bytearray()
        self.connections = 0
        self.close_after_read = close_after_read
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._read, args=(conn,), daemon=True).start()

    def _read(self, conn: socket.socket) -> None:
        with conn:
            while True:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                with self.lock:
                    self.data.extend(chunk)
                if self.close_after_read:
                    return

    def frames(self, count: int, timeout: float = 3.0) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                parts = bytes(self.data).split(b"\0")
            if len(parts) - 1 >= count:
                return [json.loads(p) for p in parts[:-1]]
            time.sleep(0.01)
        raise AssertionError(f"expected {count} frames, got {bytes(self.data)!r}")

    def stop(self) -> None:
        self.sock.close()


@pytest.fixture
def tcp_server() -> Iterator[TcpServer]:
    srv = TcpServer()
    yield srv
    srv.stop()


def test_tcp_transport_frames_one_connection(tcp_server: TcpServer) -> None:
    t = sdk.GelfTcpTransport("127.0.0.1", tcp_server.port)
    assert not t.secure
    assert t.send([]).sent == 0
    assert t.send([msg("a"), msg("b")]) == sdk.GelfSendResult(2)
    assert t.send([msg("c")], gzip=True).sent == 1
    assert asyncio.run(t.asend([msg("d")])).sent == 1
    frames = tcp_server.frames(4)
    assert [f["short_message"] for f in frames] == ["a", "b", "c", "d"]
    assert t.connections == 1
    assert sdk.GelfTcpTransport.frame([msg("x")]).endswith(b"}\0")
    asyncio.run(t.aclose())
    t.close()
    with pytest.raises(sdk.ConfigError):
        t.send([msg()])


def test_tcp_transport_reconnects_after_server_close() -> None:
    srv = TcpServer(close_after_read=True)
    try:
        with sdk.GelfTcpTransport("127.0.0.1", srv.port, retry=fast_retry()) as t:
            t.send([msg("first")])
            srv.frames(1)
            time.sleep(0.05)  # the server has closed its side
            t.send([msg("second")])
            frames = srv.frames(2)
            assert [f["short_message"] for f in frames] == ["first", "second"]
            assert t.connections == 2
    finally:
        srv.stop()


def test_tcp_transport_retries_then_fails() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    sleeps: list[float] = []
    t = sdk.GelfTcpTransport(
        "127.0.0.1", port, retry=sdk.RetryPolicy(max_retries=2), sleep=sleeps.append
    )
    with pytest.raises(sdk.UnavailableError, match=r"gelf\.tcp"):
        t.send([msg()])
    assert len(sleeps) == 2
    t2 = sdk.GelfTcpTransport("127.0.0.1", port, retry=fast_retry(max_retries=1))
    with pytest.raises(sdk.UnavailableError):
        t2.send([msg()])
    token = sdk.CancelToken()
    t3 = sdk.GelfTcpTransport("127.0.0.1", port, retry=sdk.RetryPolicy(max_retries=5))
    threading.Timer(0.05, token.cancel).start()
    with pytest.raises(sdk.CancelledError):
        t3.send([msg()], cancel=token)


def test_tcp_transport_tls_handshake_failure(tcp_server: TcpServer) -> None:
    t = sdk.GelfTcpTransport(
        "127.0.0.1",
        tcp_server.port,
        tls=True,
        connect_timeout_s=0.5,
        write_timeout_s=0.5,
        retry=fast_retry(max_retries=0),
    )
    assert t.secure
    tcp_server.close_after_read = True
    with pytest.raises((sdk.UnavailableError, sdk.TimeoutError)):
        t.send([msg()])


def test_tls_context_options(tmp_path: Any) -> None:
    ctx = sdk.tls_context(sdk.TlsConfig(insecure_skip_verify=True))
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname
    strict = sdk.tls_context(sdk.TlsConfig())
    assert strict.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises(sdk.ConfigError):
        sdk.tls_context(sdk.TlsConfig(ca_cert_path=str(tmp_path / "missing.pem")))
    with pytest.raises(sdk.ConfigError):
        sdk.tls_context(
            sdk.TlsConfig(client_cert_path=str(tmp_path / "c"), client_key_path=str(tmp_path / "k"))
        )


def test_tcp_server_hostname_defaults() -> None:
    named = sdk.GelfTcpTransport("graylog.example", tls=True)
    assert named._server_hostname == "graylog.example"
    ip = sdk.GelfTcpTransport("[::1]", tls=sdk.TlsConfig())
    assert ip.host == "::1" and ip._server_hostname is None
    explicit = sdk.GelfTcpTransport("10.0.0.1", tls=True, server_hostname="sni")
    assert explicit._server_hostname == "sni"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": " "},
        {"host": "h", "port": 70000},
        {"host": "h", "connect_timeout_s": 0},
        {"host": "h", "write_timeout_s": -1},
    ],
)
def test_tcp_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(sdk.ConfigError):
        sdk.GelfTcpTransport(**kwargs)


# --------------------------------------------------------------------------- HTTP


def test_http_transport_bulk_gzip_newlines() -> None:
    with respx.mock(base_url="http://gl:12202") as mock:
        route = mock.post("/gelf").mock(return_value=response("gelfHttp.bulk_gzip_accepted"))
        t = sdk.GelfHttpTransport("http://gl:12202/gelf", headers={"X-Input-Auth": "s3cret-hdr"})
        assert t.send([]).sent == 0
        assert t.send([msg("a"), msg("b"), msg("c")]) == sdk.GelfSendResult(3)
        request = route.calls[0].request
        assert request.headers["content-encoding"] == "gzip"
        assert request.headers["content-type"] == "application/json"
        assert request.headers["x-input-auth"] == "s3cret-hdr"
        text = gzip.decompress(request.content).decode()
        assert text.endswith("\n") and text.count("\n") == 3
        assert [json.loads(line)["short_message"] for line in text.splitlines()] == ["a", "b", "c"]
        t.send([msg("plain")], gzip=False)
        assert route.calls[-1].request.content.endswith(b'"plain"}\n')
        assert "content-encoding" not in route.calls[-1].request.headers
        t.close()


def test_http_transport_single_requests_and_errors() -> None:
    with respx.mock(base_url="https://gl:8443") as mock:
        route = mock.post("/in/gelf").mock(
            side_effect=[
                response("gelfHttp.single_accepted"),
                response("gelfHttp.single_accepted"),
                httpx.Response(401),
            ]
        )
        cfg = sdk.GraylogConfig(retry=fast_retry(max_retries=0))
        t = sdk.GelfHttpTransport("https://gl:8443/in/gelf?x=1", gzip=False, bulk=False, config=cfg)
        assert t.send([msg("1"), msg("2")]).sent == 2
        assert route.call_count == 2
        assert route.calls[0].request.url.params["x"] == "1"
        assert route.calls[1].request.content.endswith(b"\n")
        with pytest.raises(sdk.AuthenticationError):
            t.send([msg("3")])
        assert asyncio.run(t.asend([])).sent == 0
        t.close()


@pytest.mark.parametrize("url", ["ftp://x/gelf", "http://", "http://[::1/gelf", "nothing"])
def test_http_validation(url: str) -> None:
    with pytest.raises(sdk.ConfigError):
        sdk.GelfHttpTransport(url)


# --------------------------------------------------------------------------- exporters


class FakeTransport:
    protocol = "tcp"

    def __init__(self) -> None:
        self.sent: list[list[sdk.GelfMessage]] = []
        self.gzip: list[bool | None] = []
        self.closed = False

    def send(self, messages: Any, *, gzip: bool | None = None, cancel: Any = None) -> Any:
        self.sent.append(list(messages))
        self.gzip.append(gzip)
        return sdk.GelfSendResult(len(messages) - 1, 1, sdk.ValidationError("too big"))

    async def asend(self, messages: Any, *, gzip: bool | None = None) -> Any:
        raise NotImplementedError

    def close(self) -> None:
        self.closed = True


def test_gelf_log_exporter() -> None:
    transport = FakeTransport()
    exporter = sdk.GelfLogExporter(transport, host="fallback")
    records = [sdk.LogRecord(body="a"), sdk.LogRecord(body="b", resource={"host.name": "rh"})]
    result = exporter.export(records, gzip=True, timeout_s=5)
    assert (result.accepted, result.rejected) == (1, 1)
    assert isinstance(result.error, sdk.ValidationError)
    assert [m.host for m in transport.sent[0]] == ["fallback", "rh"]
    assert transport.gzip == [True]
    exporter.shutdown()
    assert transport.closed


async def test_threaded_async_exporter() -> None:
    transport = FakeTransport()
    exporter = sdk.ThreadedAsyncLogExporter(sdk.GelfLogExporter(transport))
    result = await exporter.export([sdk.LogRecord(body="a")], gzip=False, timeout_s=1)
    assert result.accepted == 0 and result.rejected == 1
    await exporter.shutdown()
    assert transport.closed


def test_batching_client_over_tcp(tcp_server: TcpServer) -> None:
    transport = sdk.GelfTcpTransport("127.0.0.1", tcp_server.port)
    client = sdk.BatchingLogClient(
        sdk.GelfLogExporter(transport),
        resource={"service.name": "svc"},
        options=sdk.BatchOptions(flush_interval_s=0.05),
    )
    client.logger("t").warn("hello", {"password": "hunter2", "n": 1})
    client.flush(5)
    client.close()
    (frame,) = tcp_server.frames(1)
    assert frame["short_message"] == "hello"
    assert frame["level"] == 4
    assert frame["_service.name"] == "svc"
    assert frame["_password"] != "hunter2"
    assert frame["_n"] == 1
    assert frame["_logger.name"] == "t"
