"""GraylogLogQueryClient / AsyncGraylogLogQueryClient: search, cursors, tail, streams, labels."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
import respx

import grow_graylog as sdk
from _fixtures import URL, config, response


def hits(*messages: dict[str, Any], total: int | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "execution": {"done": True, "completed_exceptionally": False},
            "results": {
                "q1": {
                    "errors": [],
                    "search_types": {
                        "st1": {
                            "messages": [{"message": m, "index": "graylog_0"} for m in messages],
                            "total_results": len(messages) if total is None else total,
                        }
                    },
                }
            },
            "errors": [],
        },
    )


def gelf_hit(text: str, ts: datetime, **fields: Any) -> dict[str, Any]:
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    return {"_id": text, "message": text, "timestamp": stamp, "level": 6, **fields}


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=URL, assert_all_called=False) as router:
        yield router


def test_search_window_sort_cursor(mock: respx.MockRouter) -> None:
    now = datetime.now(timezone.utc)
    route = mock.post("/api/views/search/sync").mock(
        side_effect=[
            hits(gelf_hit("a", now, service_name="svc"), total=3),
            hits(gelf_hit("b", now), total=3),
        ]
    )
    with sdk.GraylogClient(config()) as c:
        query = c.log_query_client(streams=["s1"], default_window_s=timedelta(minutes=10))
        page = query.search("x", limit=1, order="asc")
        assert page.records[0].body == "a"
        assert page.records[0].resource["service.name"] == "svc"
        assert page.next_cursor == "1" and page.total == 3
        sent = json.loads(route.calls[0].request.content)["queries"][0]
        tr = sent["timerange"]
        span = datetime.fromisoformat(tr["to"].replace("Z", "+00:00")) - datetime.fromisoformat(
            tr["from"].replace("Z", "+00:00")
        )
        assert span == timedelta(minutes=10)
        assert sent["search_types"][0]["sort"] == [
            {"field": "timestamp", "order": "ASC"},
            {"field": "gl2_message_id", "order": "ASC"},
        ]
        assert sent["filter"]["filters"] == [{"type": "stream", "id": "s1"}]
        start = now - timedelta(hours=2)
        page2 = query.search("x", start=start, end=now, cursor=page.next_cursor, limit=1)
        assert page2.records[0].body == "b"
        sent2 = json.loads(route.calls[1].request.content)["queries"][0]
        assert sent2["search_types"][0]["offset"] == 1
        with pytest.raises(sdk.ValidationError):
            query.search("x", cursor="abc")
        with pytest.raises(sdk.ValidationError):
            query.search("x", cursor="١")
    with pytest.raises(sdk.ValidationError):
        sdk.GraylogLogQueryClient(c, default_window_s=0)


def test_wait_for_log_and_labels_and_streams(mock: respx.MockRouter) -> None:
    now = datetime.now(timezone.utc)
    mock.post("/api/views/search/sync").mock(
        side_effect=[
            hits(),
            hits(gelf_hit("t", now, trace_id="4bf92f3577b34da6a3ce929d0e0e4736")),
        ]
    )
    mock.get("/api/system/fields").mock(return_value=response("listLabels.ok"))
    pages = mock.get("/api/streams/paginated").mock(
        side_effect=[
            httpx.Response(
                200,
                json={"elements": [{"title": "A"}, {"title": "B"}], "pagination": {"total": 3}},
            ),
            httpx.Response(200, json={"elements": [{"title": "C"}], "pagination": {"total": 3}}),
            httpx.Response(200, json={"elements": [], "pagination": {"total": 9}}),
        ]
    )
    with sdk.GraylogClient(config()) as c:
        query = c.log_query_client()
        found = query.wait_for_log("x", timeout_s=5, interval_s=0.01)
        assert found.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert "message" in query.list_labels()
        assert query.list_streams() == ["A", "B", "C"]
        assert pages.calls[1].request.url.params["page"] == "2"
        assert query.list_streams() == []


def test_tail_polls(mock: respx.MockRouter) -> None:
    later = datetime.now(timezone.utc) + timedelta(seconds=1)
    mock.post("/api/views/search/sync").mock(
        side_effect=[
            httpx.Response(500),
            hits(gelf_hit("live", later, tailmark="x")),
            hits(gelf_hit("live", later, tailmark="x")),
        ]
        + [hits()] * 50
    )
    got: list[sdk.LogRecord] = []
    errors: list[Exception] = []
    with sdk.GraylogClient(config(retry=sdk.RetryPolicy(max_retries=0))) as c:
        handle = c.log_query_client().tail(
            "tailmark:x", got.append, interval_s=0.02, on_error=errors.append
        )
        deadline = time.monotonic() + 5
        while not got and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.1)
        handle.stop()
    assert [r.body for r in got] == ["live"]
    assert errors and isinstance(errors[0], sdk.UnavailableError)


async def test_async_query_client(mock: respx.MockRouter) -> None:
    now = datetime.now(timezone.utc)
    later = now + timedelta(seconds=1)
    route = mock.post("/api/views/search/sync").mock(
        side_effect=[hits(gelf_hit("a", now), total=2), hits(gelf_hit("live", later))]
        + [hits()] * 100
    )
    mock.get("/api/system/fields").mock(return_value=response("listLabels.ok"))
    mock.get("/api/streams/paginated").mock(
        side_effect=[
            httpx.Response(200, json={"elements": [{"title": "A"}], "pagination": {"total": 2}}),
            httpx.Response(200, json={"elements": [], "pagination": {"total": 2}}),
        ]
    )
    async with sdk.AsyncGraylogClient(config()) as c:
        query = c.log_query_client(streams=["s"])
        page = await query.search("x", limit=1)
        assert page.records[0].body == "a" and page.next_cursor == "1"
        assert json.loads(route.calls[0].request.content)["queries"][0]["filter"]
        got: list[sdk.LogRecord] = []
        handle = await query.tail("x", got.append, interval_s=0.02)
        for _ in range(200):
            if got:
                break
            await asyncio.sleep(0.01)
        await handle.stop()
        assert [r.body for r in got] == ["live"]
        assert "message" in await query.list_labels()
        assert await query.list_streams() == ["A"]
