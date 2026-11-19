"""GraylogConfig: fields, environment precedence, validation, endpoints, auth and redaction."""

from __future__ import annotations

import base64
from typing import Any

import pytest

import grow_graylog as sdk

P = sdk.ENV_PREFIX


def test_defaults() -> None:
    cfg = sdk.GraylogConfig()
    assert cfg.url == "http://127.0.0.1:9000"
    assert cfg.gelf_host == "127.0.0.1"
    assert cfg.gelf_protocol == "tcp"
    assert cfg.gelf_port is None
    assert cfg.gelf_port_for() == 12201
    assert cfg.gelf_port_for("udp") == 12201
    assert cfg.gelf_port_for("http") == 12202
    assert cfg.gelf_http_endpoint() == "http://127.0.0.1:12202/gelf"
    assert cfg.otlp_grpc_endpoint() == "http://127.0.0.1:4317"
    assert cfg.requested_by == "grow-codes-graylog"
    assert cfg.authorization_header() is None
    assert cfg.known_secrets() == []


def test_explicit_endpoints_and_ipv6() -> None:
    cfg = sdk.GraylogConfig(url="http://[::1]:9000", gelf_port=5555, gelf_tls=True)
    assert cfg.gelf_host == "::1"
    assert cfg.gelf_port_for("http") == 5555
    assert cfg.gelf_http_endpoint() == "https://[::1]:5555/gelf"
    assert cfg.otlp_grpc_endpoint() == "http://[::1]:4317"
    explicit = sdk.GraylogConfig(
        gelf_host="[fe80::1]",
        gelf_http_url="http://h:1/gelf",
        otlp_endpoint="https://o:4317",
    )
    assert explicit.gelf_host == "fe80::1"
    assert explicit.gelf_http_endpoint() == "http://h:1/gelf"
    assert explicit.otlp_grpc_endpoint() == "https://o:4317"


def test_empty_strings_are_unset() -> None:
    cfg = sdk.GraylogConfig(api_token="", username="", gelf_http_url="", otlp_endpoint="")
    assert cfg.api_token is None and cfg.username is None
    assert cfg.gelf_http_url is None and cfg.otlp_endpoint is None


def test_auth_header_token_wins() -> None:
    cfg = sdk.GraylogConfig(api_token="tok-1234", username="admin", password="pw-12345")
    token_b64 = base64.b64encode(b"tok-1234:token").decode()
    assert cfg.authorization_header() == f"Basic {token_b64}"
    user_b64 = base64.b64encode(b"admin:pw-12345").decode()
    assert set(cfg.known_secrets()) == {"tok-1234", "pw-12345", token_b64, user_b64}
    pw = sdk.GraylogConfig(username="admin", password="pw-12345")
    assert pw.authorization_header() == f"Basic {user_b64}"


def test_repr_redacts_everything() -> None:
    cfg = sdk.GraylogConfig(
        api_token="tok-secret-1",
        username="admin",
        password="pw-secret-2",
        gelf_http_url="http://u:gelfpw@h:12202/gelf?k=v",
        otlp_endpoint="http://u:otlppw@h:4317",
    )
    for text in (repr(cfg), str(cfg)):
        for secret in ("tok-secret-1", "pw-secret-2", "gelfpw", "otlppw"):
            assert secret not in text
        assert "admin" in text


def test_from_env_precedence() -> None:
    env = {
        "GRAYLOG_URL": "http://vendor:9000",
        "GRAYLOG_API_TOKEN": "vendor-token",
        "GRAYLOG_USER": "u",
        "GRAYLOG_PASSWORD": "p-1234",
        "GRAYLOG_HOST": "platform-host",
        "GRAYLOG_PORT": "1111",
        "GRAYLOG_TRANSPORT": "udp",
        "GRAYLOG_GELF_HTTP_URL": "http://g:1/gelf",
        "GRAYLOG_OTLP_GRPC_ENDPOINT": "http://o:4317",
    }
    cfg = sdk.GraylogConfig.from_env(env)
    assert cfg.url == "http://vendor:9000"
    assert cfg.api_token is not None and cfg.api_token.reveal() == "vendor-token"
    assert cfg.username == "u" and cfg.password is not None
    assert cfg.gelf_host == "platform-host"
    assert cfg.gelf_port == 1111
    assert cfg.gelf_protocol == "udp"
    assert cfg.gelf_http_url == "http://g:1/gelf"
    assert cfg.otlp_endpoint == "http://o:4317"
    env.update(
        {
            "GRAYLOG_GELF_HOST": "vendor-host",
            "GRAYLOG_GELF_PORT": "2222",
            "GRAYLOG_GELF_PROTOCOL": "HTTP",
        }
    )
    cfg = sdk.GraylogConfig.from_env(env)
    assert (cfg.gelf_host, cfg.gelf_port, cfg.gelf_protocol) == ("vendor-host", 2222, "http")
    env.update(
        {
            P + "GELF_HOST": "grow-host",
            P + "GELF_PORT": "3333",
            P + "GELF_PROTOCOL": "tcp",
            P + "GELF_TLS": "true",
            P + "API_TOKEN": "grow-token",
            P + "OTLP_ENDPOINT": "http://grow-otlp:4317",
            P + "GELF_HTTP_URL": "http://grow-gelf:1/gelf",
        }
    )
    cfg = sdk.GraylogConfig.from_env(env)
    assert (cfg.gelf_host, cfg.gelf_port, cfg.gelf_protocol) == ("grow-host", 3333, "tcp")
    assert cfg.gelf_tls is True
    assert cfg.api_token is not None and cfg.api_token.reveal() == "grow-token"
    assert cfg.otlp_endpoint == "http://grow-otlp:4317"
    assert cfg.gelf_http_url == "http://grow-gelf:1/gelf"
    explicit = sdk.GraylogConfig.from_env(env, gelf_host="explicit", gelf_protocol="udp")
    assert explicit.gelf_host == "explicit" and explicit.gelf_protocol == "udp"


def test_from_env_bad_protocol_names_variable() -> None:
    with pytest.raises(sdk.ConfigError) as info:
        sdk.GraylogConfig.from_env({"GRAYLOG_TRANSPORT": "carrier-pigeon"})
    assert "GRAYLOG_TRANSPORT" in str(info.value)
    assert "carrier-pigeon" not in str(info.value)
    with pytest.raises(sdk.ConfigError):
        sdk.GraylogConfig.from_env({P + "GELF_PORT": "abc"})


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"api_token": "   "}, "api_token"),
        ({"username": "u"}, "together"),
        ({"password": "p"}, "together"),
        ({"gelf_port": 0}, "gelf_port"),
        ({"gelf_port": True}, "gelf_port"),
        ({"gelf_protocol": "smtp"}, "gelf_protocol"),
        ({"gelf_http_url": "ftp://x"}, "gelf_http_url"),
        ({"gelf_http_url": "http://[::1"}, "gelf_http_url"),
        ({"otlp_endpoint": "grpc://x"}, "otlp_endpoint"),
        ({"requested_by": " "}, "requested_by"),
        ({"url": "http://[::1"}, "url"),
    ],
)
def test_validate(kwargs: dict[str, Any], fragment: str) -> None:
    with pytest.raises(sdk.ConfigError) as info:
        sdk.GraylogConfig(**kwargs).validate()
    assert fragment in str(info.value)


def test_with_options_follows_url() -> None:
    cfg = sdk.GraylogConfig(url="http://a:9000")
    moved = cfg.with_options(url="http://b:9000")
    assert moved.gelf_host == "b"
    kept = sdk.GraylogConfig(url="http://a:9000", gelf_host="g").with_options(gelf_port=1)
    assert (kept.gelf_host, kept.gelf_port) == ("g", 1)
    with pytest.raises(sdk.ConfigError):
        cfg.with_options(gelf_port=-1)


def test_parse_gelf_protocol() -> None:
    assert sdk.parse_gelf_protocol(" UDP ") == "udp"
    assert sdk.parse_gelf_protocol("x") is None
    assert sdk.GELF_PROTOCOLS == ("udp", "tcp", "http")
