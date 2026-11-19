"""Graylog Open Python SDK tour: configuration from the environment, health, version, admin
(inputs, streams, index sets), sending logs through GELF and reading them back with search.

    pip install grow-graylog
    GRAYLOG_URL=http://127.0.0.1:9000 GRAYLOG_API_TOKEN=... GRAYLOG_GELF_HOST=127.0.0.1 \
        python examples/python/tour.py
"""

from __future__ import annotations

import secrets
import sys

import grow_graylog as sdk


def main() -> int:
    with sdk.GraylogClient.from_env() as client:
        print(f"config: {client.config}")  # credentials print as [REDACTED]
        health = client.health()  # never raises for an unreachable service
        print(f"health: {health}")
        if not health.healthy:
            return 1
        try:
            print(f"ping: {client.ping():.1f} ms")
            print(f"server version: {client.server_version()}")

            # Admin: make sure a GELF input exists for the configured protocol and port.
            protocol = client.config.gelf_protocol
            gelf_input = client.ensure_gelf_input(protocol, client.config.gelf_port_for(protocol))
            state = "created" if gelf_input.created else "existing"
            print(f"GELF {protocol} input {gelf_input.id} ({state})")
            sets = [
                f"{s.title}{' (default)' if s.is_default else ''}" for s in client.list_index_sets()
            ]
            print(f"index sets: {sets}")
            print(f"streams: {[s.title for s in client.list_streams().streams]}")

            # Send logs through GELF (batched, redacted) and find them again.
            run = secrets.token_hex(4)
            logs = client.log_client(
                resource={"service.name": "example", "deployment.environment": "dev"}
            )
            log = logs.logger("example", {"run": run})
            log.info(f"hello from the example {run}", {"user_id": 42, "password": "never-sent"})
            log.error(f"something failed {run}", {"attempt": 3})
            logs.flush(30)

            query = client.log_query_client()
            found = query.wait_for_log(f"run:{run} AND level:3", timeout_s=20)
            print(f"found: {found.severity.name} {found.body} {dict(found.attributes)}")
            page = client.search(f"run:{run}", range_s=300, fields=["message", "source"])
            print(f"search: {page.total} messages")
            if page.messages:
                first = page.messages[0]
                print(f"get_message: {client.get_message(first.index, first.id).fields['message']}")
        except sdk.GraylogError as err:
            # Canonical code + HTTP status; the message never contains credentials.
            print(f"{err.code}: {err.message} (HTTP {err.http_status})", file=sys.stderr)
            return 1
    return 0  # leaving the block flushed and closed every log client


if __name__ == "__main__":
    sys.exit(main())
