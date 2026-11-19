"""GraylogClient / AsyncGraylogClient against recorded responses (respx)."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
import respx

import grow_graylog as sdk
from _fixtures import TOKEN, URL, body, config, response
from _support import closed_port_url

INPUT_ID = "6afe0a6607ba3acebff1891c"
STREAM_ID = "6afe0a6607ba3acebff1894e"


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
def client() -> Iterator[sdk.GraylogClient]:
    with sdk.GraylogClient(config()) as c:
        yield c


def sent_json(route: respx.Route, index: int = -1) -> Any:
    return json.loads(route.calls[index].request.content)


# --------------------------------------------------------------------------- client surface


def test_health_states(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    route = mock.get("/api/system/lbstatus").mock(
        side_effect=[
            response("health.ok"),
            httpx.Response(429, text="THROTTLED"),
            httpx.Response(503, text="DEAD"),
            httpx.Response(200, text="STARTING"),
            response("health.json_accept_406"),
            httpx.ConnectError("refused"),
        ]
    )
    ok = client.health()
    assert ok == sdk.HealthStatus(True, "ok", {"lb_status": "ALIVE"})
    assert route.calls[0].request.headers["accept"] == "text/plain"
    assert client.health() == sdk.HealthStatus(False, "degraded", {"lb_status": "THROTTLED"})
    assert client.health() == sdk.HealthStatus(False, "unhealthy", {"lb_status": "DEAD"})
    assert client.health() == sdk.HealthStatus(False, "unhealthy", {"lb_status": "STARTING"})
    assert client.health() == sdk.HealthStatus(False, "unhealthy", {"httpStatus": "406"})
    down = client.health()
    assert (down.healthy, down.status) == (False, "unreachable")


def test_health_raises_cancelled(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    token = sdk.CancelToken()
    token.cancel()
    with pytest.raises(sdk.CancelledError):
        client.health(cancel=token)


def test_ping_version_system_info_and_auth(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    route = mock.get("/api/system").mock(return_value=response("ping.ok_token"))
    assert client.ping() >= 0
    request = route.calls[0].request
    expected = base64.b64encode(f"{TOKEN}:token".encode()).decode()
    assert request.headers["authorization"] == f"Basic {expected}"
    assert request.headers["x-requested-by"] == sdk.DEFAULT_REQUESTED_BY
    assert request.headers["user-agent"].startswith("grow-codes-graylog/")
    assert client.server_version() == "7.0.16+58e0f6e"
    info = client.system_info()
    assert info.version == "7.0.16+58e0f6e"
    assert info.is_processing is True
    assert info.node_id
    assert isinstance(info.started_at, datetime)


def test_password_auth_and_unauthorized(mock: respx.MockRouter) -> None:
    route = mock.get("/api/system").mock(
        side_effect=[response("ping.ok_password"), response("ping.unauthorized")]
    )
    cfg = config(api_token=None, username="admin", password="pw-secret-1234")
    with sdk.GraylogClient(cfg) as c:
        c.ping()
        expected = base64.b64encode(b"admin:pw-secret-1234").decode()
        assert route.calls[0].request.headers["authorization"] == f"Basic {expected}"
        with pytest.raises(sdk.AuthenticationError) as info:
            c.ping()
    assert info.value.http_status == 401
    assert "pw-secret-1234" not in str(info.value)


def test_no_auth_sends_no_authorization(mock: respx.MockRouter) -> None:
    route = mock.get("/api/system").mock(return_value=response("ping.no_auth"))
    with sdk.GraylogClient(config(api_token=None)) as c, pytest.raises(sdk.AuthenticationError):
        c.ping()
    assert "authorization" not in route.calls[0].request.headers


def test_server_version_missing_and_bad_body(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    mock.get("/api/system").mock(
        side_effect=[
            httpx.Response(200, json={"facility": "x"}),
            httpx.Response(200, json=[1, 2]),
            httpx.Response(200, text="<html>"),
        ]
    )
    with pytest.raises(sdk.UnsupportedError):
        client.server_version()
    with pytest.raises(sdk.UnavailableError) as info:
        client.system_info()
    assert info.value.retryable is False
    with pytest.raises(sdk.UnavailableError):
        client.system_info()


def test_html_500_is_unavailable(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.get("/api/system/inputs").mock(
        return_value=httpx.Response(500, html="<html>MongoTimeoutException</html>")
    )
    with pytest.raises(sdk.UnavailableError) as info:
        client.list_inputs()
    assert info.value.http_status == 500
    assert "<html>" not in str(info.value)


# --------------------------------------------------------------------------- inputs


def test_list_get_state_types(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.get("/api/system/inputs").mock(return_value=response("listInputs.ok"))
    mock.get(f"/api/system/inputs/{INPUT_ID}").mock(return_value=response("getInput.ok"))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        return_value=response("getInputState.running")
    )
    mock.get("/api/system/inputs/types").mock(return_value=response("listInputTypes.ok"))
    inputs = client.list_inputs()
    assert inputs
    tcp = next(i for i in inputs if i.type == sdk.GELF_INPUT_TYPES["tcp"])
    assert tcp.port == 12201
    assert tcp.global_ is True
    assert isinstance(tcp.attributes, dict)
    one = client.get_input(INPUT_ID)
    assert one.id == INPUT_ID
    state = client.get_input_state(INPUT_ID)
    assert state.state == "RUNNING"
    assert state.input is not None and state.input.id == INPUT_ID
    types = client.list_input_types()
    assert types[sdk.GELF_INPUT_TYPES["tcp"]] == "GELF TCP"


def test_empty_list_shapes(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.get("/api/system/inputs").mock(return_value=httpx.Response(200, json={}))
    mock.get("/api/system/inputs/types").mock(return_value=httpx.Response(200, json={}))
    mock.get("/api/system/indices/index_sets").mock(return_value=httpx.Response(200, json={}))
    mock.get("/api/system/fields").mock(return_value=httpx.Response(200, json={}))
    assert client.list_inputs() == []
    assert client.list_input_types() == {}
    assert client.list_index_sets() == []
    assert client.list_fields() == []


def test_create_and_delete_input(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    create = mock.post("/api/system/inputs").mock(
        side_effect=[
            response("createInput.created"),
            response("createInput.bad_type"),
            response("createInput.missing_requested_by"),
            httpx.Response(201, json={}),
        ]
    )
    new_id = client.create_input(sdk.GELF_INPUT_TYPES["http"], {"port": 12299}, title="t")
    assert new_id == INPUT_ID
    assert sent_json(create) == {
        "title": "t",
        "type": sdk.GELF_INPUT_TYPES["http"],
        "global": True,
        "configuration": {"port": 12299},
    }
    assert create.calls[0].request.headers["x-requested-by"] == sdk.DEFAULT_REQUESTED_BY
    with pytest.raises(sdk.NotFoundError):
        client.create_input("org.example.Nope", {}, global_=False, node="n1")
    assert sent_json(create)["node"] == "n1"
    assert sent_json(create)["title"] == "Nope (grow-codes)"
    with pytest.raises(sdk.ValidationError):
        client.create_input("org.example.Nope", {})
    with pytest.raises(sdk.ValidationError, match="without id"):
        client.create_input("org.example.Nope", {})
    with pytest.raises(sdk.ValidationError):
        client.create_input(" ", {})
    delete = mock.delete(f"/api/system/inputs/{INPUT_ID}").mock(
        side_effect=[response("deleteInput.deleted"), response("deleteInput.not_found")]
    )
    client.delete_input(INPUT_ID)
    with pytest.raises(sdk.NotFoundError):
        client.delete_input(INPUT_ID)
    assert delete.call_count == 2
    mock.get(f"/api/system/inputs/{INPUT_ID}").mock(return_value=response("getInput.not_found"))
    with pytest.raises(sdk.NotFoundError):
        client.get_input(INPUT_ID)
    with pytest.raises(sdk.ValidationError):
        client.get_input("")


def _inputs_with(port: int, input_id: str = INPUT_ID, kind: str = "http") -> dict[str, Any]:
    return {
        "inputs": [
            {
                "id": input_id,
                "title": "x",
                "type": sdk.GELF_INPUT_TYPES[kind],
                "global": True,
                "attributes": {"port": port, "bind_address": "0.0.0.0"},
            }
        ],
        "total": 1,
    }


def test_ensure_gelf_input_reuses_existing(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    mock.get("/api/system/inputs").mock(return_value=response("listInputs.ok"))
    tcp = next(
        i for i in body("listInputs.ok")["inputs"] if i["type"] == sdk.GELF_INPUT_TYPES["tcp"]
    )
    mock.get(f"/api/system/inputstates/{tcp['id']}").mock(
        return_value=httpx.Response(200, json={"id": tcp["id"], "state": "RUNNING"})
    )
    create = mock.post("/api/system/inputs")
    ensured = client.ensure_gelf_input("tcp", 12201)
    assert ensured.created is False
    assert ensured.id == tcp["id"]
    assert not create.called


def test_ensure_gelf_input_creates_and_waits(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    mock.get("/api/system/inputs").mock(
        side_effect=[httpx.Response(200, json={"inputs": []}), httpx.Response(200, json={})]
    )
    create = mock.post("/api/system/inputs").mock(return_value=response("createInput.created"))
    mock.get(f"/api/system/inputs/{INPUT_ID}").mock(return_value=response("getInput.ok"))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        side_effect=[
            httpx.Response(404, json={"message": "not yet"}),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
            response("getInputState.running"),
        ]
    )
    ensured = client.ensure_gelf_input(
        "http", 12299, configuration={"enable_cors": False}, interval_s=0.01
    )
    assert ensured.created is True
    assert ensured.id == INPUT_ID
    sent = sent_json(create)
    assert sent["title"] == "grow-codes GELF HTTP 12299"
    assert sent["configuration"]["enable_bulk_receiving"] is True
    assert sent["configuration"]["enable_cors"] is False


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_ensure_gelf_input_configurations(
    mock: respx.MockRouter, client: sdk.GraylogClient, protocol: str
) -> None:
    new_id = "aaaaaaaaaaaaaaaaaaaaaaaa"
    mock.get("/api/system/inputs").mock(
        side_effect=[
            httpx.Response(200, json={"inputs": []}),
            httpx.Response(200, json=_inputs_with(1234, new_id, protocol)),
        ]
    )
    create = mock.post("/api/system/inputs").mock(
        return_value=httpx.Response(201, json={"id": new_id})
    )
    mock.get(f"/api/system/inputstates/{new_id}").mock(
        return_value=httpx.Response(200, json={"id": new_id, "state": "RUNNING"})
    )
    ensured = client.ensure_gelf_input(protocol, 1234, title="mine")  # type: ignore[arg-type]
    assert ensured.port == 1234
    sent = sent_json(create)
    assert sent["title"] == "mine"
    if protocol == "tcp":
        assert sent["configuration"]["use_null_delimiter"] is True
    else:
        assert sent["configuration"]["recv_buffer_size"] == 262_144


def test_ensure_gelf_input_failed_deletes(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    collision_id = "6afe0a6607ba3acebff1892e"
    mock.get("/api/system/inputs").mock(
        side_effect=[
            httpx.Response(200, json={"inputs": []}),
            httpx.Response(200, json=_inputs_with(12201, collision_id)),
        ]
    )
    mock.post("/api/system/inputs").mock(return_value=response("createInput.port_collision"))
    mock.get(f"/api/system/inputstates/{collision_id}").mock(
        return_value=response("getInputState.port_collision")
    )
    delete = mock.delete(f"/api/system/inputs/{collision_id}").mock(
        return_value=httpx.Response(204)
    )
    with pytest.raises(sdk.ConflictError, match="failed to start"):
        client.ensure_gelf_input("http", 12201)
    assert delete.called


def test_ensure_gelf_input_failed_existing_is_kept(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    mock.get("/api/system/inputs").mock(return_value=httpx.Response(200, json=_inputs_with(5)))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        return_value=httpx.Response(200, json={"id": INPUT_ID, "state": "FAILED"})
    )
    delete = mock.delete(f"/api/system/inputs/{INPUT_ID}")
    with pytest.raises(sdk.ConflictError):
        client.ensure_gelf_input("http", 5)
    assert not delete.called


def test_ensure_gelf_input_timeout(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.get("/api/system/inputs").mock(
        side_effect=[
            httpx.Response(200, json={"inputs": []}),
            httpx.Response(200, json=_inputs_with(7)),
        ]
    )
    mock.post("/api/system/inputs").mock(return_value=httpx.Response(201, json={"id": INPUT_ID}))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        return_value=httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"})
    )
    delete = mock.delete(f"/api/system/inputs/{INPUT_ID}").mock(
        return_value=httpx.Response(404, json={"message": "gone"})
    )
    with pytest.raises(sdk.TimeoutError):
        client.ensure_gelf_input("http", 7, timeout_s=timedelta(seconds=0.05), interval_s=0.01)
    assert delete.called


def test_ensure_gelf_input_validation(client: sdk.GraylogClient) -> None:
    with pytest.raises(sdk.ValidationError):
        client.ensure_gelf_input("smtp", 1)  # type: ignore[arg-type]
    with pytest.raises(sdk.ValidationError):
        client.ensure_gelf_input("tcp", 0)


# --------------------------------------------------------------------------- streams


def test_streams_and_index_sets(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    listed = mock.get("/api/streams/paginated").mock(return_value=response("listStreams.ok"))
    page = client.list_streams(query="abc", order="desc")
    params = listed.calls[0].request.url.params
    assert params["page"] == "1" and params["per_page"] == "50" and params["query"] == "abc"
    assert params["order"] == "desc"
    assert any(s.title == "Default Stream" for s in page.streams)
    assert page.total >= 3
    assert page.page == 1
    client.list_streams()
    assert "query" not in listed.calls[-1].request.url.params
    with pytest.raises(sdk.ValidationError):
        client.list_streams(page=0)
    with pytest.raises(sdk.ValidationError):
        client.list_streams(per_page=True)  # type: ignore[arg-type]

    sets_route = mock.get("/api/system/indices/index_sets").mock(
        return_value=response("listIndexSets.ok")
    )
    sets = client.list_index_sets()
    assert sets_route.calls[0].request.url.params["skip_stats"] == "true"
    default = next(s for s in sets if s.is_default)
    assert default.index_prefix

    create = mock.post("/api/streams").mock(return_value=response("createStream.created"))
    resume = mock.post(f"/api/streams/{STREAM_ID}/resume").mock(
        return_value=response("resumeStream.ok")
    )
    rule = sdk.StreamRule(field="marker", type=1, value="x")
    stream_id = client.create_stream("t", description="d", rules=[rule])
    assert stream_id == STREAM_ID
    entity = sent_json(create)["entity"]
    assert entity["index_set_id"] == default.id
    assert entity["rules"] == [
        {"field": "marker", "type": 1, "value": "x", "inverted": False, "description": ""}
    ]
    assert entity["matching_type"] == "AND"
    assert resume.call_count == 1
    client.create_stream("t2", index_set_id="explicit", start=False, matching_type="OR")
    assert sent_json(create)["entity"]["index_set_id"] == "explicit"
    assert resume.call_count == 1

    mock.get(f"/api/streams/{STREAM_ID}").mock(
        side_effect=[response("getStream.ok"), response("getStream.created_disabled")]
    )
    stream = client.get_stream(STREAM_ID)
    assert stream.id == STREAM_ID
    assert stream.disabled is False
    assert stream.rules and stream.rules[0].field
    assert client.get_stream(STREAM_ID).disabled is True
    mock.delete(f"/api/streams/{STREAM_ID}").mock(
        side_effect=[response("deleteStream.deleted"), response("deleteStream.not_found")]
    )
    client.delete_stream(STREAM_ID)
    with pytest.raises(sdk.NotFoundError):
        client.delete_stream(STREAM_ID)


def test_create_stream_errors(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    with pytest.raises(sdk.ValidationError):
        client.create_stream(" ")
    mock.get("/api/system/indices/index_sets").mock(
        side_effect=[
            httpx.Response(200, json={"index_sets": []}),
            httpx.Response(200, json={"index_sets": [{"id": "only", "default": False}]}),
        ]
    )
    with pytest.raises(sdk.ValidationError, match="no index set"):
        client.create_stream("t")
    mock.post("/api/streams").mock(
        side_effect=[response("createStream.missing_index_set"), httpx.Response(201, json={})]
    )
    with pytest.raises(sdk.ValidationError):
        client.create_stream("t", index_set_id="x")
    with pytest.raises(sdk.ValidationError, match="stream_id"):
        client.create_stream("t", index_set_id="x")


def test_stream_rule_value_decoding() -> None:
    from grow_graylog.models import decode_stream_rule

    assert decode_stream_rule({"value": True}).value == "true"
    assert decode_stream_rule({"value": 3}).value == "3"
    assert decode_stream_rule({"value": None, "type": 2.0}).type == 2
    assert decode_stream_rule("junk").field == ""


# --------------------------------------------------------------------------- search


def test_search_absolute_body_and_decoding(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    route = mock.post("/api/views/search/sync").mock(
        return_value=response("search.absolute_sorted_fields")
    )
    start = datetime(2026, 11, 18, 20, 28, 15, 935000, tzinfo=timezone.utc)
    result = client.search(
        "marker:x",
        from_=start,
        to=start + timedelta(seconds=9),
        sort=sdk.SearchSort("seq", "asc"),
        fields=["message", "seq"],
        limit=10,
        streams=[STREAM_ID],
    )
    sent = sent_json(route)["queries"][0]
    assert sent["timerange"] == {
        "type": "absolute",
        "from": "2026-11-18T20:28:15.935Z",
        "to": "2026-11-18T20:28:24.935Z",
    }
    assert sent["query"] == {"type": "elasticsearch", "query_string": "marker:x"}
    assert sent["filter"] == {"type": "or", "filters": [{"type": "stream", "id": STREAM_ID}]}
    st = sent["search_types"][0]
    assert st["sort"] == [{"field": "seq", "order": "ASC"}]
    assert st["fields"] == ["message", "seq"]
    assert (st["limit"], st["offset"]) == (10, 0)
    assert route.calls[0].request.headers["x-requested-by"]
    assert result.messages[0].fields["seq"] == 0
    assert result.messages[0].index == "graylog_0"
    assert result.messages[0].id
    assert result.from_ is not None and result.to is not None
    assert result.total >= len(result.messages)


def test_search_ranges_and_defaults(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    route = mock.post("/api/views/search/sync").mock(return_value=response("search.empty"))
    empty = client.search("")
    sent = sent_json(route)["queries"][0]
    assert sent["timerange"] == {"type": "relative", "range": 300}
    assert sent["query"]["query_string"] == "*"
    assert sent["search_types"][0]["sort"] == [{"field": "timestamp", "order": "DESC"}]
    assert "filter" not in sent and "fields" not in sent["search_types"][0]
    assert empty.messages == [] and empty.next_offset is None
    client.search("x", keyword="last five minutes")
    assert sent_json(route)["queries"][0]["timerange"]["type"] == "keyword"
    client.search_relative("x", 60, sort=[sdk.SearchSort("a"), sdk.SearchSort("b", "asc")])
    q = sent_json(route)["queries"][0]
    assert q["timerange"] == {"type": "relative", "range": 60}
    assert [s["order"] for s in q["search_types"][0]["sort"]] == ["DESC", "ASC"]
    naive_to = datetime(2026, 1, 1, 12, 0, 0)
    client.search("x", to=naive_to)
    tr = sent_json(route)["queries"][0]["timerange"]
    assert tr == {
        "type": "absolute",
        "from": "2026-01-01T11:55:00.000Z",
        "to": "2026-01-01T12:00:00.000Z",
    }
    client.search("x", from_=datetime(2026, 1, 1, 11, 0, 0))
    assert sent_json(route)["queries"][0]["timerange"]["from"] == "2026-01-01T11:00:00.000Z"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"range_s": 10, "keyword": "x"},
        {"range_s": 0},
        {"keyword": " "},
        {"limit": 0},
        {"offset": -1},
        {
            "from_": datetime(2026, 1, 2, tzinfo=timezone.utc),
            "to": datetime(2026, 1, 1, tzinfo=timezone.utc),
        },
    ],
)
def test_search_validation(client: sdk.GraylogClient, kwargs: dict[str, Any]) -> None:
    with pytest.raises(sdk.ValidationError):
        client.search("x", **kwargs)


def test_search_pagination_and_errors(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.post("/api/views/search/sync").mock(
        side_effect=[
            response("search.desc_limit_offset"),
            response("search.invalid_query"),
            response("search.bad_request"),
            response("search.unauthorized"),
            httpx.Response(200, json={"errors": [{"description": f"bad {TOKEN}"}]}),
            httpx.Response(200, json={"execution": {"completed_exceptionally": True}}),
        ]
    )
    page = client.search("x", limit=2, offset=0)
    if page.total > len(page.messages):
        assert page.next_offset == len(page.messages)
    with pytest.raises(sdk.ValidationError, match="search: "):
        client.search("marker:((")
    with pytest.raises(sdk.ValidationError):
        client.search("x")
    with pytest.raises(sdk.AuthenticationError):
        client.search("x")
    with pytest.raises(sdk.ValidationError) as info:
        client.search("x")
    assert TOKEN not in str(info.value)
    with pytest.raises(sdk.ValidationError, match="query failed"):
        client.search("x")


def test_search_stream_filter_fixture_and_keyword(
    mock: respx.MockRouter, client: sdk.GraylogClient
) -> None:
    mock.post("/api/views/search/sync").mock(
        side_effect=[
            response("search.stream_filter"),
            response("search.keyword_range"),
            response("searchRelative.ok"),
        ]
    )
    assert client.search("x", streams=[STREAM_ID]).messages
    assert client.search("x", keyword="last five minutes").total >= 0
    rel = client.search_relative("x", 600)
    assert rel.total == rel.total and rel.from_ is not None


def test_get_message_and_fields(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mid = "99c65855-e38e-11f1-8dde-020650dd320d"
    mock.get(f"/api/messages/graylog_0/{mid}").mock(return_value=response("getMessage.ok"))
    mock.get("/api/messages/graylog_0/00000000-0000-0000-0000-000000000000").mock(
        return_value=response("getMessage.not_found")
    )
    message = client.get_message("graylog_0", mid)
    assert message.id == mid
    assert message.index == "graylog_0"
    assert message.timestamp is not None
    assert "message" in message.fields
    with pytest.raises(sdk.NotFoundError):
        client.get_message("graylog_0", "00000000-0000-0000-0000-000000000000")
    with pytest.raises(sdk.ValidationError):
        client.get_message("graylog_0", "")
    mock.get("/api/system/fields").mock(return_value=response("listLabels.ok"))
    fields = client.list_fields()
    assert fields == sorted(fields) and "message" in fields


def test_get_message_tolerates_odd_body(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.get("/api/messages/i/m").mock(return_value=httpx.Response(200, json={"message": 1}))
    assert client.get_message("i", "m").fields == {}


def test_raw_request_and_repr(mock: respx.MockRouter, client: sdk.GraylogClient) -> None:
    mock.get("/api/system").mock(return_value=response("ping.ok_token"))
    assert client.request(sdk.Request("GET", "/api/system")).status == 200
    assert TOKEN not in repr(client)
    assert client.resources is not None


# --------------------------------------------------------------------------- logging factories


def test_gelf_transport_factory() -> None:
    cfg = config(url="http://gl.example:9000", gelf_tls=False)
    with sdk.GraylogClient(cfg) as c:
        udp = c.gelf_transport("udp", compression="zlib", chunk_size=512)
        assert isinstance(udp, sdk.GelfUdpTransport)
        assert (udp.host, udp.port, udp.compression, udp.chunk_size) == (
            "gl.example",
            12201,
            "zlib",
            512,
        )
        assert isinstance(c.gelf_transport("udp"), sdk.GelfUdpTransport)
        tcp = c.gelf_transport()
        assert isinstance(tcp, sdk.GelfTcpTransport) and not tcp.secure
        http = c.gelf_transport("http", bulk=False, headers={"X-Auth": "abcd1234"})
        assert isinstance(http, sdk.GelfHttpTransport)
        assert http.url == "http://gl.example:12202/gelf" and http.bulk is False
        for t in (udp, tcp, http):
            t.close()
        with pytest.raises(sdk.ValidationError):
            c.gelf_transport("smtp")  # type: ignore[arg-type]
    tls = sdk.GraylogConfig(gelf_tls=True, tls=sdk.TlsConfig(insecure_skip_verify=True))
    with sdk.GraylogClient(tls) as c:
        secure = c.gelf_transport("tcp")
        assert isinstance(secure, sdk.GelfTcpTransport) and secure.secure


def test_log_client_factory_and_close() -> None:
    with sdk.GraylogClient(config()) as c:
        tcp = c.log_client()
        exporter = tcp.processor._exporter
        assert isinstance(exporter, sdk.GelfLogExporter)
        assert isinstance(exporter.transport, sdk.GelfTcpTransport)
        udp = c.log_client("udp", host="h", redaction=None, resource={"service.name": "s"})
        assert udp.redaction is None and udp.resource == {"service.name": "s"}
        own = sdk.GelfUdpTransport("127.0.0.1", 9)
        custom = c.log_client(transport=own)
        assert custom.processor._exporter.transport is own  # type: ignore[attr-defined]
        otlp = c.log_client("otlp", bearer_token="b-token-1234")
        assert isinstance(otlp.processor._exporter, sdk.OtlpGrpcLogExporter)
        assert otlp.processor._exporter.target == "graylog.test:4317"  # type: ignore[attr-defined]
        query = c.log_query_client(streams=["s1"])
        assert isinstance(query, sdk.GraylogLogQueryClient) and query.streams == ["s1"]
    c.close()
    with pytest.raises(sdk.CancelledError):
        c.log_client()


def test_close_flushes_log_clients() -> None:
    sent: list[int] = []

    class Recorder:
        protocol = "tcp"

        def send(self, messages: Any, *, gzip: Any = None, cancel: Any = None) -> Any:
            sent.append(len(messages))
            return sdk.GelfSendResult(len(messages))

        async def asend(self, messages: Any, *, gzip: Any = None) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            sent.append(-1)

    c = sdk.GraylogClient(config())
    logs = c.log_client(transport=Recorder())
    logs.logger("t").info("hello")
    c.close()
    assert sent == [1, -1]


def test_client_from_env_and_default_config(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {"GRAYLOG_URL": "http://from-env:9000", "GRAYLOG_API_TOKEN": "env-token-1234"}
    with sdk.GraylogClient.from_env(env) as c:
        assert c.config.url == "http://from-env:9000"
        assert c.config.gelf_host == "from-env"
    monkeypatch.setenv("GROW_GRAYLOG_URL", "http://process-env:9000")
    with sdk.GraylogClient() as c2:
        assert c2.config.url == "http://process-env:9000"
    with pytest.raises(sdk.ConfigError):
        sdk.GraylogClient.from_env({"GROW_GRAYLOG_URL": "nope://x"})


def test_network_error_is_unavailable() -> None:
    with sdk.GraylogClient(config(url=closed_port_url())) as c:
        with pytest.raises(sdk.UnavailableError):
            c.ping()
        assert c.health().status == "unreachable"


# --------------------------------------------------------------------------- async


async def test_async_client_round_trip(mock: respx.MockRouter) -> None:
    mock.get("/api/system/lbstatus").mock(
        side_effect=[response("health.ok"), httpx.ConnectError("x")]
    )
    mock.get("/api/system").mock(return_value=response("ping.ok_token"))
    mock.get("/api/system/inputs").mock(return_value=response("listInputs.ok"))
    mock.get(f"/api/system/inputs/{INPUT_ID}").mock(return_value=response("getInput.ok"))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        return_value=response("getInputState.running")
    )
    mock.get("/api/system/inputs/types").mock(return_value=response("listInputTypes.ok"))
    mock.post("/api/system/inputs").mock(return_value=response("createInput.created"))
    mock.delete(f"/api/system/inputs/{INPUT_ID}").mock(return_value=httpx.Response(204))
    mock.get("/api/streams/paginated").mock(return_value=response("listStreams.ok"))
    mock.get("/api/system/indices/index_sets").mock(return_value=response("listIndexSets.ok"))
    mock.post("/api/streams").mock(return_value=response("createStream.created"))
    resume = mock.post(f"/api/streams/{STREAM_ID}/resume").mock(return_value=httpx.Response(204))
    mock.get(f"/api/streams/{STREAM_ID}").mock(return_value=response("getStream.ok"))
    mock.delete(f"/api/streams/{STREAM_ID}").mock(return_value=httpx.Response(204))
    mock.post("/api/views/search/sync").mock(return_value=response("searchRelative.ok"))
    mid = "99c65855-e38e-11f1-8dde-020650dd320d"
    mock.get(f"/api/messages/graylog_0/{mid}").mock(return_value=response("getMessage.ok"))
    mock.get("/api/system/fields").mock(return_value=response("listLabels.ok"))
    async with sdk.AsyncGraylogClient(config()) as c:
        assert (await c.health()).healthy
        assert (await c.health()).status == "unreachable"
        assert await c.ping() >= 0
        assert await c.server_version() == "7.0.16+58e0f6e"
        assert (await c.system_info()).is_processing
        assert await c.list_inputs()
        assert (await c.get_input(INPUT_ID)).id == INPUT_ID
        assert (await c.get_input_state(INPUT_ID)).state == "RUNNING"
        assert await c.list_input_types()
        assert await c.create_input("org.x.Y", {}) == INPUT_ID
        await c.delete_input(INPUT_ID)
        assert (await c.list_streams()).streams
        assert await c.list_index_sets()
        assert await c.create_stream("t") == STREAM_ID
        assert await c.create_stream("t", index_set_id="i", start=False) == STREAM_ID
        assert resume.call_count == 1
        assert (await c.get_stream(STREAM_ID)).id == STREAM_ID
        await c.delete_stream(STREAM_ID)
        assert (await c.search("x", limit=5)).messages
        assert (await c.search_relative("x", 600)).messages
        assert (await c.get_message("graylog_0", mid)).id == mid
        assert "message" in await c.list_fields()
        assert (await c.request(sdk.Request("GET", "/api/system"))).status == 200
        assert TOKEN not in repr(c)
        query = c.log_query_client()
        assert isinstance(query, sdk.AsyncGraylogLogQueryClient)


async def test_async_ensure_gelf_input(mock: respx.MockRouter) -> None:
    mock.get("/api/system/inputs").mock(
        side_effect=[
            httpx.Response(200, json={"inputs": []}),
            httpx.Response(200, json={}),
            httpx.Response(200, json={"inputs": []}),
            httpx.Response(200, json=_inputs_with(9)),
            httpx.Response(200, json={"inputs": []}),
            httpx.Response(200, json=_inputs_with(9)),
        ]
    )
    mock.post("/api/system/inputs").mock(return_value=response("createInput.created"))
    mock.get(f"/api/system/inputs/{INPUT_ID}").mock(return_value=response("getInput.ok"))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        side_effect=[
            httpx.Response(404),
            response("getInputState.running"),
            httpx.Response(
                200, json={"id": INPUT_ID, "state": "FAILED", "detailed_message": "busy"}
            ),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
            httpx.Response(200, json={"id": INPUT_ID, "state": "STARTING"}),
        ]
    )
    delete = mock.delete(f"/api/system/inputs/{INPUT_ID}").mock(
        side_effect=[httpx.Response(204), httpx.Response(404, json={"message": "x"})]
    )
    async with sdk.AsyncGraylogClient(config()) as c:
        ensured = await c.ensure_gelf_input("http", 12299, interval_s=0.01)
        assert ensured.created
        with pytest.raises(sdk.ConflictError, match="busy"):
            await c.ensure_gelf_input("http", 9, interval_s=0.01)
        with pytest.raises(sdk.TimeoutError):
            await c.ensure_gelf_input("http", 9, timeout_s=0.03, interval_s=0.01)
        assert delete.call_count == 2
        with pytest.raises(sdk.ValidationError):
            await c.create_stream("")


async def test_async_ensure_reuses_and_index_set_missing(mock: respx.MockRouter) -> None:
    mock.get("/api/system/inputs").mock(return_value=httpx.Response(200, json=_inputs_with(9)))
    mock.get(f"/api/system/inputstates/{INPUT_ID}").mock(
        return_value=httpx.Response(200, json={"id": INPUT_ID, "state": "FAILED"})
    )
    mock.get("/api/system/indices/index_sets").mock(return_value=httpx.Response(200, json={}))
    async with sdk.AsyncGraylogClient(config()) as c:
        with pytest.raises(sdk.ConflictError):
            await c.ensure_gelf_input("http", 9)
        with pytest.raises(sdk.ValidationError):
            await c.create_stream("t")


async def test_async_log_client_and_close() -> None:
    sent: list[int] = []

    class Recorder:
        protocol = "udp"

        def send(self, messages: Any, *, gzip: Any = None, cancel: Any = None) -> Any:
            sent.append(len(messages))
            return sdk.GelfSendResult(len(messages))

        async def asend(self, messages: Any, *, gzip: Any = None) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            sent.append(-1)

    c = sdk.AsyncGraylogClient(config())
    logs = c.log_client(transport=Recorder(), options=sdk.BatchOptions(flush_interval_s=0.05))
    assert isinstance(logs, sdk.AsyncBatchingLogClient)
    logs.logger("t").info("hello")
    await c.aclose()
    await c.close()
    assert sent == [1, -1]
    with pytest.raises(sdk.CancelledError):
        c.log_client()


async def test_async_cancellation(mock: respx.MockRouter) -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={})

    mock.get("/api/system").mock(side_effect=slow)
    async with sdk.AsyncGraylogClient(config()) as c:
        task = asyncio.ensure_future(c.ping())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


def test_async_from_env() -> None:
    c = sdk.AsyncGraylogClient.from_env({"GRAYLOG_URL": "http://a:9000"})
    assert c.config.url == "http://a:9000"
    asyncio.run(c.aclose())
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("GROW_GRAYLOG_URL", "http://b:9000")
        c2 = sdk.AsyncGraylogClient()
        assert c2.config.url == "http://b:9000"
        asyncio.run(c2.aclose())
