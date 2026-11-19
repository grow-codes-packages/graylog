"""Configuration for the Graylog Open client.

This file is owned by the service package (generated once by sdk-kit).
"""

from __future__ import annotations

import base64
import dataclasses
from collections.abc import Mapping
from typing import Any, ClassVar, Literal, TypeVar
from urllib.parse import urlsplit

from ._core import BaseConfig, ConfigError, EnvReader, Secret, redact_url
from ._core.redaction import safe_repr

__all__ = [
    "DEFAULT_URL",
    "DEFAULT_GELF_PORT",
    "DEFAULT_GELF_HTTP_PORT",
    "DEFAULT_OTLP_GRPC_PORT",
    "DEFAULT_REQUESTED_BY",
    "GELF_PROTOCOLS",
    "GelfProtocol",
    "GraylogConfig",
    "parse_gelf_protocol",
]

#: Default REST endpoint when neither the config nor the environment sets one.
DEFAULT_URL = "http://127.0.0.1:9000"
#: Default GELF port for UDP and TCP inputs.
DEFAULT_GELF_PORT = 12201
#: Default GELF HTTP port (Graylog has no fixed one; 12202 is the common choice).
DEFAULT_GELF_HTTP_PORT = 12202
#: Default OTLP gRPC port of the Graylog OpenTelemetry input.
DEFAULT_OTLP_GRPC_PORT = 4317
#: Default value of the ``X-Requested-By`` header Graylog requires on non-GET requests.
DEFAULT_REQUESTED_BY = "grow-codes-graylog"

GelfProtocol = Literal["udp", "tcp", "http"]
"""GELF transport protocol."""

#: Every :data:`GelfProtocol`.
GELF_PROTOCOLS: tuple[GelfProtocol, ...] = ("udp", "tcp", "http")

_C = TypeVar("_C", bound="GraylogConfig")


def parse_gelf_protocol(value: str) -> GelfProtocol | None:
    """Parse a GELF protocol name (case-insensitive); ``None`` when unknown."""
    v = value.strip().lower()
    for proto in GELF_PROTOCOLS:
        if proto == v:
            return proto
    return None


def bare_host(host: str) -> str:
    """Strip IPv6 brackets: ``[::1]`` → ``::1``."""
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def url_host(host: str) -> str:
    """Host as written in a URL authority (IPv6 addresses get brackets)."""
    bare = bare_host(host)
    return f"[{bare}]" if ":" in bare else bare


def _is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _basic(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode("ascii")


@dataclasses.dataclass(frozen=True, repr=False)
class GraylogConfig(BaseConfig):
    """Immutable settings for :class:`~grow_graylog.GraylogClient`.

    Common fields (``url``, timeouts, ``retry``, ``tls``, ``proxy``, ``headers``,
    ``user_agent_suffix``, ``hooks``, ``logger``) come from :class:`BaseConfig`. Durations are
    float seconds; ``datetime.timedelta`` is accepted. Credentials accept a ``str`` and are stored
    as :class:`Secret`; ``repr()`` never shows them.

    Environment (:meth:`from_env`), precedence: explicit keyword > ``GROW_GRAYLOG_<NAME>`` >
    vendor variable > platform alias > default.

    ============== ====================== ============================================
    Field          ``GROW_GRAYLOG_*``     Vendor / platform
    ============== ====================== ============================================
    url            ``URL``                ``GRAYLOG_URL``
    api_token      ``API_TOKEN``          ``GRAYLOG_API_TOKEN``
    username       ``USER``               ``GRAYLOG_USER``
    password       ``PASSWORD``           ``GRAYLOG_PASSWORD``
    gelf_host      ``GELF_HOST``          ``GRAYLOG_GELF_HOST``, ``GRAYLOG_HOST``
    gelf_port      ``GELF_PORT``          ``GRAYLOG_GELF_PORT``, ``GRAYLOG_PORT``
    gelf_protocol  ``GELF_PROTOCOL``      ``GRAYLOG_GELF_PROTOCOL``, ``GRAYLOG_TRANSPORT``
    gelf_http_url  ``GELF_HTTP_URL``      ``GRAYLOG_GELF_HTTP_URL``
    gelf_tls       ``GELF_TLS``           —
    otlp_endpoint  ``OTLP_ENDPOINT``      ``GRAYLOG_OTLP_GRPC_ENDPOINT``
    ============== ====================== ============================================

    Plus the common ``CONNECT_TIMEOUT``, ``REQUEST_TIMEOUT``, ``TOTAL_TIMEOUT``,
    ``MAX_RETRIES``, ``CA_CERT``, ``CLIENT_CERT``, ``CLIENT_KEY``, ``INSECURE_SKIP_VERIFY`` and
    ``PROXY``.

    Attributes:
        api_token: REST API access token, sent as HTTP Basic ``<token>:token``; wins over
            ``username``/``password``.
        username: REST user name for HTTP Basic auth.
        password: REST password.
        gelf_host: GELF host (default: the host of ``url``).
        gelf_port: GELF port; ``None`` means 12202 for HTTP and 12201 otherwise
            (see :meth:`gelf_port_for`).
        gelf_protocol: default GELF transport (``udp``, ``tcp``, ``http``); default ``tcp``.
        gelf_http_url: full GELF HTTP endpoint (default ``http(s)://<gelf_host>:<port>/gelf``).
        gelf_tls: TLS for GELF TCP (and ``https`` for the default GELF HTTP URL), with ``tls``.
        otlp_endpoint: OTLP gRPC endpoint of a Graylog OpenTelemetry input
            (default ``http://<gelf_host>:4317``).
        requested_by: value of the ``X-Requested-By`` header on non-GET requests.
    """

    #: Vendor and platform variables per GROW_* suffix, in precedence order.
    ENV_VENDOR: ClassVar[Mapping[str, tuple[str, ...]]] = {
        "URL": ("GRAYLOG_URL",),
        "API_TOKEN": ("GRAYLOG_API_TOKEN",),
        "USER": ("GRAYLOG_USER",),
        "PASSWORD": ("GRAYLOG_PASSWORD",),
        "GELF_HOST": ("GRAYLOG_GELF_HOST", "GRAYLOG_HOST"),
        "GELF_PORT": ("GRAYLOG_GELF_PORT", "GRAYLOG_PORT"),
        "GELF_PROTOCOL": ("GRAYLOG_GELF_PROTOCOL", "GRAYLOG_TRANSPORT"),
        "GELF_HTTP_URL": ("GRAYLOG_GELF_HTTP_URL",),
        "GELF_TLS": (),
        "OTLP_ENDPOINT": ("GRAYLOG_OTLP_GRPC_ENDPOINT",),
    }

    url: str = DEFAULT_URL
    api_token: Secret | None = None
    username: str | None = None
    password: Secret | None = None
    gelf_host: str = ""
    gelf_port: int | None = None
    gelf_protocol: GelfProtocol = "tcp"
    gelf_http_url: str | None = None
    gelf_tls: bool = False
    otlp_endpoint: str | None = None
    requested_by: str = DEFAULT_REQUESTED_BY

    def __post_init__(self) -> None:
        super().__post_init__()
        for name in ("api_token", "password"):
            value = getattr(self, name)
            if isinstance(value, Secret) and not value.reveal():
                object.__setattr__(self, name, None)
        for name in ("username", "gelf_http_url", "otlp_endpoint"):
            if getattr(self, name) == "":
                object.__setattr__(self, name, None)
        host = self.gelf_host
        if not host:
            try:
                host = urlsplit(self.url).hostname or "127.0.0.1"
            except ValueError:
                host = "127.0.0.1"  # validate() reports the bad URL
        object.__setattr__(self, "gelf_host", bare_host(host))

    def __repr__(self) -> str:
        text = safe_repr(self)
        for value in (self.gelf_http_url, self.otlp_endpoint):
            if value:
                text = text.replace(repr(value), repr(redact_url(value)))
        return text

    __str__ = __repr__

    @classmethod
    def _env_values(cls, reader: EnvReader) -> dict[str, Any]:
        vendor = cls.ENV_VENDOR
        values = super()._env_values(reader)
        token = reader.string("API_TOKEN", vendor.get("API_TOKEN", ()))
        if token is not None:
            values["api_token"] = Secret(token)
        user = reader.string("USER", vendor.get("USER", ()))
        if user is not None:
            values["username"] = user
        password = reader.string("PASSWORD", vendor.get("PASSWORD", ()))
        if password is not None:
            values["password"] = Secret(password)
        host = reader.string("GELF_HOST", vendor.get("GELF_HOST", ()))
        if host is not None:
            values["gelf_host"] = host
        port = reader.int("GELF_PORT", vendor.get("GELF_PORT", ()))
        if port is not None:
            values["gelf_port"] = port
        found = reader.lookup("GELF_PROTOCOL", vendor.get("GELF_PROTOCOL", ()))
        if found is not None:
            protocol = parse_gelf_protocol(found[1])
            if protocol is None:
                raise ConfigError(
                    f"config: {found[0]} is not a valid GELF protocol (expected udp, tcp or http)"
                )
            values["gelf_protocol"] = protocol
        http_url = reader.string("GELF_HTTP_URL", vendor.get("GELF_HTTP_URL", ()))
        if http_url is not None:
            values["gelf_http_url"] = http_url
        tls = reader.bool("GELF_TLS", vendor.get("GELF_TLS", ()))
        if tls is not None:
            values["gelf_tls"] = tls
        otlp = reader.string("OTLP_ENDPOINT", vendor.get("OTLP_ENDPOINT", ()))
        if otlp is not None:
            values["otlp_endpoint"] = otlp
        return values

    def with_options(self: _C, **changes: Any) -> _C:
        """A validated copy with some fields replaced (``gelf_host`` follows a new ``url``)."""
        if "url" in changes and "gelf_host" not in changes:
            changes["gelf_host"] = ""
        return dataclasses.replace(self, **changes).validate()

    def validate(self: _C) -> _C:
        """Common checks plus the Graylog rules; raises :class:`ConfigError`."""
        super().validate()
        problems: list[str] = []
        if self.api_token is not None and not self.api_token.reveal().strip():
            problems.append("api_token must not be blank")
        if (self.username is None) != (self.password is None):
            problems.append("username and password must be given together")
        port = self.gelf_port
        if port is not None and (
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        ):
            problems.append("gelf_port must be an integer 1..65535")
        if self.gelf_protocol not in GELF_PROTOCOLS:
            problems.append("gelf_protocol must be udp, tcp or http")
        if self.gelf_http_url is not None and not _is_http_url(self.gelf_http_url):
            problems.append("gelf_http_url must be an http(s) URL")
        if self.otlp_endpoint is not None and not _is_http_url(self.otlp_endpoint):
            problems.append("otlp_endpoint must be an http(s) URL")
        if not self.requested_by.strip():
            problems.append("requested_by must not be blank")
        if problems:
            raise ConfigError(f"config: invalid configuration: {'; '.join(problems)}")
        return self

    def gelf_port_for(self, protocol: GelfProtocol | None = None) -> int:
        """The GELF port for ``protocol``: :attr:`gelf_port`, else 12202 (HTTP) / 12201."""
        if self.gelf_port is not None:
            return self.gelf_port
        proto = protocol or self.gelf_protocol
        return DEFAULT_GELF_HTTP_PORT if proto == "http" else DEFAULT_GELF_PORT

    def gelf_http_endpoint(self) -> str:
        """The effective GELF HTTP endpoint."""
        if self.gelf_http_url is not None:
            return self.gelf_http_url
        scheme = "https" if self.gelf_tls else "http"
        return f"{scheme}://{url_host(self.gelf_host)}:{self.gelf_port_for('http')}/gelf"

    def otlp_grpc_endpoint(self) -> str:
        """The effective OTLP gRPC endpoint."""
        if self.otlp_endpoint is not None:
            return self.otlp_endpoint
        return f"http://{url_host(self.gelf_host)}:{DEFAULT_OTLP_GRPC_PORT}"

    def authorization_header(self) -> str | None:
        """``Authorization`` value: Basic ``<token>:token`` or Basic ``<user>:<password>``."""
        if self.api_token is not None:
            return f"Basic {_basic(self.api_token.reveal(), 'token')}"
        if self.username is not None and self.password is not None:
            return f"Basic {_basic(self.username, self.password.reveal())}"
        return None

    def known_secrets(self) -> list[str]:
        """Credential values (and their Basic encodings) to redact from errors and logs."""
        out = super().known_secrets()
        if self.api_token is not None:
            out.append(_basic(self.api_token.reveal(), "token"))
        if self.username is not None and self.password is not None:
            out.append(_basic(self.username, self.password.reveal()))
        return out
