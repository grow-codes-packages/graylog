"""Factories the integration suite and the conformance runner use (owned by this repository).

Capabilities: core "version"; logging "query", "tail", "streams", "labels" (nothing skipped).
The logging target sends GELF over TCP (the bootstrap default) or HTTP and reads back through the
views search API.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import grow_graylog as sdk
from grow_graylog.testing import LoggingTarget

URL_VAR = "GROW_GRAYLOG_URL"

#: Capabilities of the deployment under test for the core scenarios ("version" = serverVersion).
CORE_CAPABILITIES: set[str] = {"version"}

#: Capabilities for the logging scenarios: query, tail, streams, labels.
LOGGING_CAPABILITIES: set[str] = {"query", "tail", "streams", "labels"}


def core_client(env: Mapping[str, str], **overrides: Any) -> sdk.GraylogClient:
    """A client configured from the test environment (URL, token … from /bootstrap/env)."""
    overrides.setdefault("retry", sdk.RetryPolicy(max_retries=2, initial_backoff=0.05))
    return sdk.GraylogClient.from_env(env, **overrides)


def async_core_client(env: Mapping[str, str], **overrides: Any) -> sdk.AsyncGraylogClient:
    overrides.setdefault("retry", sdk.RetryPolicy(max_retries=2, initial_backoff=0.05))
    return sdk.AsyncGraylogClient.from_env(env, **overrides)


def batch_options(scenario: Mapping[str, Any] | None = None) -> sdk.BatchOptions:
    """Fast flushes plus the scenario's ``batchOptions``."""
    data: dict[str, Any] = {"flushIntervalMs": 200}
    if scenario:
        data.update(scenario.get("batchOptions") or {})
    return sdk.BatchOptions.from_mapping(data)


def logging_target(
    client: sdk.GraylogClient,
    scenario: Mapping[str, Any],
    protocol: sdk.LogProtocol = "tcp",
) -> LoggingTarget:
    """A ``LoggingTarget(log client, query client)`` for one scenario."""
    return LoggingTarget(
        client=client.log_client(
            protocol,
            options=batch_options(scenario),
            resource={"service.name": f"sdk-py-conformance-{protocol}"},
        ),
        query=client.log_query_client(),
    )
