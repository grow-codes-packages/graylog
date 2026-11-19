"""Shared logging conformance scenarios against the real Graylog (GELF TCP and HTTP)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from factories import LOGGING_CAPABILITIES, core_client, logging_target

import grow_graylog as sdk
from grow_graylog.testing import ConformanceRunner, assert_scenario, pytest_params


@pytest.fixture
def clients() -> Iterator[list[sdk.GraylogClient]]:
    made: list[sdk.GraylogClient] = []
    yield made
    for c in made:
        c.close()


@pytest.mark.parametrize("protocol", ["tcp", "http"])
@pytest.mark.parametrize("scenario", pytest_params(categories=["logging"]))
def test_logging_conformance(
    env: dict[str, str],
    clients: list[sdk.GraylogClient],
    scenario: dict[str, Any],
    protocol: sdk.LogProtocol,
) -> None:
    def factory(ctx: Any) -> Any:
        client = core_client(env)
        clients.append(client)
        return logging_target(client, ctx.scenario, protocol)

    runner = ConformanceRunner({"logging": factory}, capabilities=LOGGING_CAPABILITIES)
    assert_scenario(runner, scenario)
