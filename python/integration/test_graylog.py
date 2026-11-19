"""Integration tests against the real Graylog Open stack (docker/compose.yml): every public
function of the clients is called at least once with a round-trip assertion."""

from __future__ import annotations

import asyncio
import os
import random
import secrets
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from factories import async_core_client, core_client

import grow_graylog as sdk

RUN = f"py{secrets.token_hex(5)}"


@pytest.fixture
def make(env: dict[str, str]) -> Iterator[Any]:
    made: list[sdk.GraylogClient] = []

    def factory(**overrides: Any) -> sdk.GraylogClient:
        c = core_client(env, **overrides)
        made.append(c)
        return c

    yield factory
    for c in made:
        c.close()


def need(env: dict[str, str], name: str) -> str:
    value = env.get(name)
    assert value, f"{name} must be set (bootstrap env)"
    return value


def search_until(
    client: sdk.GraylogClient, query: str, min_count: int = 1, timeout_s: float = 30.0
) -> list[sdk.GraylogMessage]:
    """Poll ``search`` until ``min_count`` messages match (ingest takes 1-2 s)."""
    deadline = time.monotonic() + timeout_s
    while True:
        res = client.search(query, range_s=600, limit=100)
        if len(res.messages) >= min_count:
            return res.messages
        if time.monotonic() > deadline:
            pytest.fail(f"search {query!r}: {len(res.messages)} < {min_count} messages")
        time.sleep(0.5)


def test_print_run() -> None:
    print(f"run {os.environ.get('GROW_TEST_RUN_ID', 'local')}/{RUN}")


def test_ping_with_password_and_bad_token(make: Any, env: dict[str, str]) -> None:
    url = make().config.url
    with sdk.GraylogClient(
        sdk.GraylogConfig(
            url=url, username=need(env, "GRAYLOG_USER"), password=need(env, "GRAYLOG_PASSWORD")
        )
    ) as password_only:
        assert password_only.ping() >= 0
    wrong = "wrong-token-for-integration"
    with sdk.GraylogClient(sdk.GraylogConfig(url=url, api_token=wrong)) as c:
        with pytest.raises(sdk.AuthenticationError) as info:
            c.ping()
    assert info.value.http_status == 401
    assert wrong not in str(info.value)


def test_server_version_and_system_info(make: Any) -> None:
    client = make()
    version = client.server_version()
    info = client.system_info()
    assert info.version == version
    assert info.is_processing is True
    assert info.node_id


def test_inputs_read(make: Any, env: dict[str, str]) -> None:
    client = make()
    types = client.list_input_types()
    assert types[sdk.GELF_INPUT_TYPES["tcp"]] == "GELF TCP"
    tcp_id = need(env, "GRAYLOG_INPUT_ID_GELF_TCP")
    tcp = next(i for i in client.list_inputs() if i.id == tcp_id)
    assert tcp.type == sdk.GELF_INPUT_TYPES["tcp"]
    assert tcp.port == 12201
    assert client.get_input(tcp_id).title == tcp.title
    state = client.get_input_state(tcp_id)
    assert state.state == "RUNNING"
    assert state.input is not None and state.input.id == tcp_id


def test_inputs_create_delete(make: Any) -> None:
    client = make()
    port = random.randint(20_000, 29_999)
    input_id = client.create_input(
        sdk.GELF_INPUT_TYPES["udp"],
        {"bind_address": "0.0.0.0", "port": port, "recv_buffer_size": 262_144},
        title=f"grow-sdk py {RUN}",
    )
    assert len(input_id) == 24
    created = client.get_input(input_id)
    assert created.title == f"grow-sdk py {RUN}"
    assert created.port == port
    client.delete_input(input_id)
    with pytest.raises(sdk.NotFoundError):
        client.get_input(input_id)
    with pytest.raises(sdk.NotFoundError):
        client.create_input("org.example.NoSuchInput", {})


def test_ensure_gelf_input(make: Any, env: dict[str, str]) -> None:
    client = make()
    existing = client.ensure_gelf_input("tcp", 12201)
    assert existing.created is False
    assert existing.id == need(env, "GRAYLOG_INPUT_ID_GELF_TCP")
    port = random.randint(30_000, 39_999)
    fresh = client.ensure_gelf_input("http", port, title=f"grow-sdk py http {RUN}")
    try:
        assert fresh.created is True
        assert fresh.port == port
        assert client.get_input_state(fresh.id).state == "RUNNING"
        again = client.ensure_gelf_input("http", port)
        assert again.created is False and again.id == fresh.id
    finally:
        client.delete_input(fresh.id)


def test_streams_index_sets_and_stream_search(make: Any, env: dict[str, str]) -> None:
    client = make()
    default = next(s for s in client.list_index_sets() if s.is_default)
    assert default.id == need(env, "GRAYLOG_DEFAULT_INDEX_SET_ID")
    title = f"grow-sdk py {RUN}"
    stream_id = client.create_stream(
        title,
        description="Python integration",
        rules=[sdk.StreamRule(field="stream_marker", type=1, value=RUN)],
    )
    try:
        stream = client.get_stream(stream_id)
        assert stream.title == title
        assert stream.disabled is False, "create_stream resumes the stream"
        assert stream.index_set_id == default.id
        assert stream.rules[0].value == RUN
        page = client.list_streams(query=RUN)
        assert any(s.id == stream_id for s in page.streams) and page.total >= 1
        paused = client.create_stream(f"{title} paused", start=False, index_set_id=default.id)
        try:
            assert client.get_stream(paused).disabled is True
            client.resume_stream(paused)
            assert client.get_stream(paused).disabled is False
        finally:
            client.delete_stream(paused)
        with client.gelf_transport("tcp") as transport:
            transport.send(
                [
                    sdk.GelfMessage("it", f"routed {RUN}").set_field("stream_marker", RUN),
                    sdk.GelfMessage("it", f"not routed {RUN}"),
                ]
            )
        search_until(client, f'"{RUN}"', 2)
        in_stream = client.search(f'"{RUN}"', range_s=600, streams=[stream_id])
        assert [m.fields["message"] for m in in_stream.messages] == [f"routed {RUN}"]
    finally:
        client.delete_stream(stream_id)
    with pytest.raises(sdk.NotFoundError):
        client.get_stream(stream_id)


def test_tcp_transport_search_and_messages(make: Any, env: dict[str, str]) -> None:
    client = make()
    ts = datetime.now(timezone.utc) - timedelta(seconds=1)
    with sdk.GelfTcpTransport(
        need(env, "GRAYLOG_GELF_HOST"), int(need(env, "GRAYLOG_GELF_TCP_PORT"))
    ) as tcp:
        result = tcp.send(
            [
                sdk.GelfMessage(
                    "py-tcp",
                    f"tcp one {RUN}",
                    full_message="line1\nline2",
                    timestamp=ts,
                    level=sdk.GelfLevel.WARNING,
                    fields={"marker": f"tcp{RUN}", "seq": 1, "ok": True, "nested": {"a": 1}},
                ),
                sdk.GelfMessage(
                    "py-tcp", f"tcp two {RUN}", fields={"marker": f"tcp{RUN}", "seq": 2}
                ),
            ]
        )
        assert result == sdk.GelfSendResult(2)
        assert tcp.connections == 1
    hits = search_until(client, f"marker:tcp{RUN}", 2)
    one = next(m for m in hits if m.fields.get("seq") == 1)
    assert one.fields["source"] == "py-tcp"
    assert one.fields["full_message"] == "line1\nline2"
    assert one.fields["level"] == 4
    assert one.fields["ok"] == "true"
    assert one.fields["nested"] == '{"a":1}'
    assert one.timestamp is not None
    assert abs((one.timestamp - ts).total_seconds()) < 0.002

    now = datetime.now(timezone.utc)
    page1 = client.search(
        f"marker:tcp{RUN}",
        from_=now - timedelta(minutes=10),
        to=now + timedelta(minutes=1),
        sort=sdk.SearchSort("seq", "asc"),
        fields=["message", "seq"],
        limit=1,
    )
    assert page1.total == 2
    assert page1.messages[0].fields["seq"] == 1
    assert page1.next_offset == 1
    assert "source" not in page1.messages[0].fields, "fields projection"
    page2 = client.search(
        f"marker:tcp{RUN}",
        keyword="last ten minutes",
        sort=sdk.SearchSort("seq", "asc"),
        limit=1,
        offset=1,
    )
    assert page2.messages[0].fields["seq"] == 2
    assert page2.next_offset is None
    relative = client.search_relative(f"marker:tcp{RUN}", 600)
    assert relative.total == 2
    assert relative.from_ is not None and relative.to is not None
    message = client.get_message(one.index, one.id)
    assert message.id == one.id
    assert message.fields["message"] == f"tcp one {RUN}"
    with pytest.raises(sdk.NotFoundError):
        client.get_message(one.index, "00000000-0000-0000-0000-000000000000")
    with pytest.raises(sdk.ValidationError):
        client.search("marker:((")
    fields = client.list_fields()
    assert "marker" in fields and "seq" in fields


def test_udp_transport_retried_on_search(make: Any, env: dict[str, str]) -> None:
    client = make()
    host = need(env, "GRAYLOG_GELF_HOST")
    port = int(need(env, "GRAYLOG_GELF_UDP_PORT"))
    big = secrets.token_urlsafe(9000)  # ~12 KB: several chunks even gzipped
    want = {f"udp {c} {RUN}" for c in ("none", "zlib", "gzip", "chunked")}
    deadline = time.monotonic() + 45
    attempt = 0
    while True:
        attempt += 1
        for compression in ("none", "zlib", "gzip"):
            with sdk.GelfUdpTransport(host, port, compression=compression) as udp:  # type: ignore[arg-type]
                res = udp.send(
                    [
                        sdk.GelfMessage(
                            "py-udp", f"udp {compression} {RUN}", fields={"marker": f"udp{RUN}"}
                        )
                    ]
                )
                assert res.sent == 1
        with sdk.GelfUdpTransport(host, port, chunk_size=1420) as chunked:
            chunked.send(
                [
                    sdk.GelfMessage(
                        "py-udp",
                        f"udp chunked {RUN}",
                        full_message=big,
                        fields={"marker": f"udp{RUN}"},
                    )
                ]
            )
        time.sleep(2.5)
        res = client.search(f"marker:udp{RUN}", range_s=600)
        bodies = {m.fields.get("message") for m in res.messages}
        if want <= bodies:
            hit = next(m for m in res.messages if m.fields["message"] == f"udp chunked {RUN}")
            assert hit.fields["full_message"] == big
            return
        if time.monotonic() > deadline:
            pytest.fail(f"UDP: got {bodies} after {attempt} attempts")


def test_http_transport_bulk_and_single(make: Any, env: dict[str, str]) -> None:
    client = make()
    url = need(env, "GRAYLOG_GELF_HTTP_URL")
    with sdk.GelfHttpTransport(url) as bulk:
        msgs = [
            sdk.GelfMessage("py-http", f"http bulk {i} {RUN}", fields={"marker": f"http{RUN}"})
            for i in (1, 2, 3)
        ]
        assert bulk.send(msgs) == sdk.GelfSendResult(3)
    # one request per message on a kept-alive connection (every message ends with "\n")
    with sdk.GelfHttpTransport(url, gzip=False, bulk=False) as single:
        singles = [
            sdk.GelfMessage("py-http", f"http single {x} {RUN}", fields={"marker": f"http{RUN}"})
            for x in "abcd"
        ]
        assert single.send(singles) == sdk.GelfSendResult(4)
        assert single.send(singles[:1]) == sdk.GelfSendResult(1)
    assert len(search_until(client, f"marker:http{RUN}", 8)) == 8


@pytest.mark.parametrize("protocol", ["tcp", "udp", "http", "otlp"])
def test_log_client_round_trip(make: Any, protocol: sdk.LogProtocol) -> None:
    client = make()
    service = f"sdk-py-{protocol}-{RUN}"
    logs = client.log_client(
        protocol,
        resource={
            "service.name": service,
            "deployment.environment": "test",
            "host.name": "py-host",
        },
        options=sdk.BatchOptions(flush_interval_s=0.1),
    )
    query = client.log_query_client()
    log = logs.logger("integration", {"component": "it"})
    t0 = datetime.now(timezone.utc)
    log.warn(
        f"hello {protocol} {RUN}",
        {"request_id": f"r-{RUN}", "password": f"hunter2-{RUN}", "id": "x1", "n": 7},
    )
    logs.send(
        sdk.LogRecord(
            body=f"traced {protocol} {RUN}",
            severity=sdk.Severity.ERROR,
            timestamp=t0 + timedelta(milliseconds=5),
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            span_id="00f067aa0ba902b7",
            trace_flags=1,
        )
    )
    logs.flush(30)
    assert logs.stats() == sdk.BatchStats(queued=0, sent=2, dropped=0, failed=0, retries=0)

    look_for = (
        f'otel_resource_attributes_service_name:"{service}"'
        if protocol == "otlp"
        else f'service_name:"{service}"'
    )
    deadline = time.monotonic() + (45 if protocol == "udp" else 30)
    resent = False
    while True:
        records = query.search(look_for, order="asc", limit=10).records
        if len(records) >= 2 or time.monotonic() > deadline:
            break
        if protocol == "udp" and not records and not resent and time.monotonic() - deadline > -35:
            # UDP is best effort: send once more
            log.warn(f"hello {protocol} {RUN}", {"request_id": f"r-{RUN}", "id": "x1", "n": 7})
            logs.flush(10)
            resent = True
        time.sleep(0.5)
    hello = next((r for r in records if r.body == f"hello {protocol} {RUN}"), None)
    traced = next((r for r in records if r.body == f"traced {protocol} {RUN}"), None)
    assert hello is not None, records
    assert traced is not None, records
    assert hello.severity == sdk.Severity.WARN
    assert hello.attributes["request_id"] == f"r-{RUN}"
    assert hello.attributes["n"] == 7
    assert hello.resource["service.name"] == service
    if protocol != "otlp":
        assert hello.attributes["id"] == "x1", "id attribute round-trips through _attr_id"
        assert hello.resource["host.name"] == "py-host"
        assert hello.resource["deployment.environment"] == "test"
    assert f"hunter2-{RUN}" not in repr(records), "password must be redacted"
    assert traced.severity == sdk.Severity.ERROR
    assert traced.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert traced.span_id == "00f067aa0ba902b7"

    waited = query.wait_for_log(
        look_for, predicate=lambda r: r.trace_id is not None, timeout_s=10, interval_s=0.25
    )
    assert waited.body == f"traced {protocol} {RUN}"
    if protocol != "udp":
        page1 = query.search(look_for, limit=1, order="asc")
        assert page1.records[0].body == f"hello {protocol} {RUN}"
        assert page1.next_cursor == "1"
        assert page1.total == 2
        page2 = query.search(look_for, limit=1, order="asc", cursor=page1.next_cursor)
        assert page2.records[0].body == f"traced {protocol} {RUN}"
        assert page2.next_cursor is None
    logs.close()


def test_tail_streams_labels(make: Any) -> None:
    client = make()
    query = client.log_query_client()
    logs = client.log_client("tcp", options=sdk.BatchOptions(flush_interval_s=0.1))
    got: list[sdk.LogRecord] = []
    errors: list[Exception] = []
    handle = query.tail(f"tailmark:{RUN}", got.append, interval_s=0.5, on_error=errors.append)
    time.sleep(0.3)
    logs.send(sdk.LogInput(message=f"live {RUN}", attributes={"tailmark": RUN, "n": 1}))
    logs.flush(10)
    deadline = time.monotonic() + 20
    while not got and time.monotonic() < deadline:
        time.sleep(0.2)
    handle.stop()
    assert errors == []
    assert got and got[0].body == f"live {RUN}"
    assert got[0].attributes["n"] == 1
    assert "Default Stream" in query.list_streams()
    assert "tailmark" in query.list_labels()


def test_async_client_round_trip(env: dict[str, str]) -> None:
    async def run() -> None:
        async with async_core_client(env) as c:
            assert (await c.health()).healthy
            assert await c.ping() >= 0
            assert (await c.system_info()).version == await c.server_version()
            assert await c.list_input_types()
            tcp_id = need(env, "GRAYLOG_INPUT_ID_GELF_TCP")
            assert any(i.id == tcp_id for i in await c.list_inputs())
            assert (await c.get_input(tcp_id)).id == tcp_id
            assert (await c.get_input_state(tcp_id)).state == "RUNNING"
            port = random.randint(40_000, 44_999)
            created = await c.ensure_gelf_input("udp", port, title=f"grow-sdk py async {RUN}")
            assert created.created
            await c.delete_input(created.id)
            input_id = await c.create_input(
                sdk.GELF_INPUT_TYPES["udp"], {"bind_address": "0.0.0.0", "port": port + 1}
            )
            await c.delete_input(input_id)
            with pytest.raises(sdk.NotFoundError):
                await c.get_input(input_id)
            assert await c.list_index_sets()
            stream_id = await c.create_stream(f"grow-sdk py async {RUN}", start=False)
            assert (await c.get_stream(stream_id)).disabled is True
            await c.resume_stream(stream_id)
            assert (await c.get_stream(stream_id)).disabled is False
            assert any(s.id == stream_id for s in (await c.list_streams(query=RUN)).streams)
            await c.delete_stream(stream_id)

            logs = c.log_client("http", options=sdk.BatchOptions(flush_interval_s=0.1))
            logs.send(sdk.LogInput(message=f"async {RUN}", attributes={"amark": RUN}))
            await logs.flush(30)
            query = c.log_query_client()
            record = await query.wait_for_log(f"amark:{RUN}", timeout_s=30, interval_s=0.5)
            assert record.body == f"async {RUN}"
            hits = await c.search(f"amark:{RUN}", range_s=600)
            assert hits.total == 1
            relative = await c.search_relative(f"amark:{RUN}", 600)
            message = await c.get_message(relative.messages[0].index, relative.messages[0].id)
            assert message.fields["message"] == f"async {RUN}"
            assert "amark" in await c.list_fields()
            assert "amark" in await query.list_labels()
            assert "Default Stream" in await query.list_streams()
            got: list[sdk.LogRecord] = []
            handle = await query.tail(f"atail:{RUN}", got.append, interval_s=0.5)
            await asyncio.sleep(0.3)
            logs.send(sdk.LogInput(message=f"atail {RUN}", attributes={"atail": RUN}))
            await logs.flush(10)
            for _ in range(100):
                if got:
                    break
                await asyncio.sleep(0.2)
            await handle.stop()
            assert got and got[0].body == f"atail {RUN}"

    asyncio.run(run())
