"""Recorded responses of the real Graylog 7.0 container (copied from the prep run)."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import httpx

import grow_graylog as sdk
from _support import fast_retry

FIXTURES = Path(__file__).parent / "fixtures"
URL = "http://graylog.test:9000"
TOKEN = "tok-graylog-abcdef123456"


@cache
def load(name: str) -> dict[str, Any]:
    """The whole fixture document."""
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return data


def body(name: str) -> Any:
    """The recorded response body."""
    return load(name)["response"].get("body")


def response(name: str, status: int | None = None) -> httpx.Response:
    """An ``httpx.Response`` replaying the fixture (JSON, text or empty body)."""
    rec = load(name)["response"]
    code = status if status is not None else int(rec["status"])
    headers = {
        k: v
        for k, v in (rec.get("headers") or {}).items()
        if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")
    }
    payload = rec.get("body")
    if payload is None:
        return httpx.Response(code, headers=headers)
    if isinstance(payload, str):
        return httpx.Response(code, text=payload, headers=headers)
    return httpx.Response(code, json=payload, headers=headers)


def config(**kw: Any) -> sdk.GraylogConfig:
    kw.setdefault("url", URL)
    kw.setdefault("api_token", TOKEN)
    kw.setdefault("retry", fast_retry(max_retries=1))
    return sdk.GraylogConfig(**kw)
