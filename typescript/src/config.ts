// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type CommonConfig,
  type CommonConfigOptions,
  type CommonVendorEnv,
  ConfigError,
  type EnvMap,
  EnvReader,
  type Hooks,
  type ClientLogger,
  REDACTED,
  type RetryPolicy,
  Secret,
  type TlsOptions,
  describeCommonConfig,
  mergeOptions,
  readCommonEnv,
  redactUrl,
  resolveCommonConfig,
  secretValues,
  validateCommonConfig,
} from "./core/index.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Port text from the stack catalog; the default URL uses its first number. */
const CATALOG_PORT = "9000";

/** GELF transport protocols. */
export type GelfProtocol = "udp" | "tcp" | "http";

/** Every {@link GelfProtocol}. */
export const GELF_PROTOCOLS: readonly GelfProtocol[] = ["udp", "tcp", "http"];

/** Default GELF port for UDP and TCP inputs. */
export const DEFAULT_GELF_PORT = 12201;
/** Default GELF HTTP port (Graylog has no fixed one; 12202 is the common choice). */
export const DEFAULT_GELF_HTTP_PORT = 12202;
/** Default OTLP gRPC port of the Graylog OpenTelemetry input. */
export const DEFAULT_OTLP_GRPC_PORT = 4317;
/** Default value of the `X-Requested-By` header Graylog requires on non-GET requests. */
export const DEFAULT_REQUESTED_BY = "grow-codes-graylog";

/** Options accepted by {@link GraylogConfig} (all optional). */
export interface GraylogConfigOptions extends CommonConfigOptions {
  /**
   * REST API access token (env `GROW_GRAYLOG_API_TOKEN`, `GRAYLOG_API_TOKEN`). Sent as HTTP Basic
   * `<token>:token`. Wins over `username`/`password` when both are set.
   */
  apiToken?: string | Secret;
  /** REST user name for HTTP Basic auth (env `GROW_GRAYLOG_USER`, `GRAYLOG_USER`). */
  username?: string;
  /** REST password (env `GROW_GRAYLOG_PASSWORD`, `GRAYLOG_PASSWORD`). */
  password?: string | Secret;
  /** GELF host (env `GROW_GRAYLOG_GELF_HOST`, `GRAYLOG_GELF_HOST`, `GRAYLOG_HOST`). Default: host of `url`. */
  gelfHost?: string;
  /**
   * GELF port (env `GROW_GRAYLOG_GELF_PORT`, `GRAYLOG_GELF_PORT`, `GRAYLOG_PORT`). Default 12201
   * for UDP/TCP and 12202 for HTTP.
   */
  gelfPort?: number;
  /** Default GELF transport (env `GROW_GRAYLOG_GELF_PROTOCOL`, `GRAYLOG_GELF_PROTOCOL`, `GRAYLOG_TRANSPORT`). Default `tcp`. */
  gelfProtocol?: GelfProtocol;
  /**
   * Full GELF HTTP endpoint (env `GROW_GRAYLOG_GELF_HTTP_URL`, `GRAYLOG_GELF_HTTP_URL`).
   * Default `http(s)://<gelfHost>:<gelfPort>/gelf`.
   */
  gelfHttpUrl?: string;
  /** Use TLS for GELF TCP (and `https` for the default GELF HTTP URL); env `GROW_GRAYLOG_GELF_TLS`. Uses the `tls` options. */
  gelfTls?: boolean;
  /**
   * OTLP gRPC endpoint of a Graylog OpenTelemetry input (env `GROW_GRAYLOG_OTLP_ENDPOINT`,
   * `GRAYLOG_OTLP_GRPC_ENDPOINT`). Default `http://<gelfHost>:4317`.
   */
  otlpEndpoint?: string;
  /** Value of the `X-Requested-By` header on non-GET requests. Default `grow-codes-graylog`. */
  requestedBy?: string;
}

/** Vendor and platform environment variables read after `GROW_GRAYLOG_*`, in order. */
export const VENDOR_ENV: CommonVendorEnv & {
  apiToken: readonly string[];
  username: readonly string[];
  password: readonly string[];
  gelfHost: readonly string[];
  gelfPort: readonly string[];
  gelfProtocol: readonly string[];
  gelfHttpUrl: readonly string[];
  gelfTls: readonly string[];
  otlpEndpoint: readonly string[];
} = {
  url: ["GRAYLOG_URL"],
  apiToken: ["GRAYLOG_API_TOKEN"],
  username: ["GRAYLOG_USER"],
  password: ["GRAYLOG_PASSWORD"],
  gelfHost: ["GRAYLOG_GELF_HOST", "GRAYLOG_HOST"],
  gelfPort: ["GRAYLOG_GELF_PORT", "GRAYLOG_PORT"],
  gelfProtocol: ["GRAYLOG_GELF_PROTOCOL", "GRAYLOG_TRANSPORT"],
  gelfHttpUrl: ["GRAYLOG_GELF_HTTP_URL"],
  gelfTls: [],
  otlpEndpoint: ["GRAYLOG_OTLP_GRPC_ENDPOINT"],
};

/** Parses a GELF protocol name (case-insensitive); `undefined` when unknown. */
export function parseGelfProtocol(value: string): GelfProtocol | undefined {
  const v = value.trim().toLowerCase();
  return (GELF_PROTOCOLS as readonly string[]).includes(v) ? (v as GelfProtocol) : undefined;
}

/** Strips IPv6 brackets: `[::1]` → `::1`. */
export function bareHost(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/** Host as written in a URL authority (IPv6 addresses get brackets). */
export function urlHost(host: string): string {
  const bare = bareHost(host);
  return bare.includes(":") ? `[${bare}]` : bare;
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function basicCredentials(username: string, password: string): string {
  return Buffer.from(`${username}:${password}`, "utf8").toString("base64");
}

/** Immutable configuration of {@link GraylogClient}. */
export class GraylogConfig implements CommonConfig {
  /** Default REST endpoint. */
  static readonly DEFAULT_URL = `http://127.0.0.1:${/\d+/.exec(CATALOG_PORT)?.[0] ?? "8080"}`;
  /** Prefix of every environment variable. */
  static readonly ENV_PREFIX = "GROW_GRAYLOG_";

  readonly url: string;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly totalTimeoutMs: number;
  readonly retry: RetryPolicy;
  readonly tls: Readonly<TlsOptions>;
  readonly proxy?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly userAgentSuffix?: string;
  readonly hooks?: Hooks;
  readonly logger?: ClientLogger;
  /** REST API token. */
  readonly apiToken?: Secret;
  /** REST user name. */
  readonly username?: string;
  /** REST password. */
  readonly password?: Secret;
  /** GELF host (no IPv6 brackets). */
  readonly gelfHost: string;
  /** Explicit GELF port; see {@link gelfPortFor} for the effective one. */
  readonly gelfPort?: number;
  /** Default GELF transport. */
  readonly gelfProtocol: GelfProtocol;
  /** Explicit GELF HTTP URL; see {@link gelfHttpEndpoint} for the effective one. */
  readonly gelfHttpUrl?: string;
  /** TLS for GELF TCP / default GELF HTTP URL. */
  readonly gelfTls: boolean;
  /** Explicit OTLP gRPC endpoint; see {@link otlpGrpcEndpoint} for the effective one. */
  readonly otlpEndpoint?: string;
  /** `X-Requested-By` header value. */
  readonly requestedBy: string;

  /** Applies defaults, validates (throws {@link ConfigError}) and freezes. */
  constructor(options: GraylogConfigOptions = {}) {
    const common = resolveCommonConfig(options, GraylogConfig.DEFAULT_URL);
    this.url = common.url;
    this.connectTimeoutMs = common.connectTimeoutMs;
    this.requestTimeoutMs = common.requestTimeoutMs;
    this.totalTimeoutMs = common.totalTimeoutMs;
    this.retry = common.retry;
    this.tls = common.tls;
    this.headers = common.headers;
    if (common.proxy !== undefined) this.proxy = common.proxy;
    if (common.userAgentSuffix !== undefined) this.userAgentSuffix = common.userAgentSuffix;
    if (common.hooks !== undefined) this.hooks = common.hooks;
    if (common.logger !== undefined) this.logger = common.logger;
    const token = Secret.from(options.apiToken);
    if (token !== undefined) this.apiToken = token;
    if (options.username !== undefined && options.username !== "") this.username = options.username;
    const password = Secret.from(options.password);
    if (password !== undefined) this.password = password;
    let defaultHost = "127.0.0.1";
    try {
      defaultHost = new URL(this.url).hostname || defaultHost;
    } catch {
      // validate() reports the bad URL
    }
    this.gelfHost = bareHost(
      options.gelfHost !== undefined && options.gelfHost !== "" ? options.gelfHost : defaultHost,
    );
    if (options.gelfPort !== undefined) this.gelfPort = options.gelfPort;
    this.gelfProtocol = options.gelfProtocol ?? "tcp";
    if (options.gelfHttpUrl !== undefined && options.gelfHttpUrl !== "")
      this.gelfHttpUrl = options.gelfHttpUrl;
    this.gelfTls = options.gelfTls ?? false;
    if (options.otlpEndpoint !== undefined && options.otlpEndpoint !== "")
      this.otlpEndpoint = options.otlpEndpoint;
    this.requestedBy = options.requestedBy ?? DEFAULT_REQUESTED_BY;
    this.validate();
    Object.freeze(this);
  }

  /** Returns `options` when it already is a config, otherwise builds one. */
  static from(options: GraylogConfigOptions = {}): GraylogConfig {
    if (options instanceof GraylogConfig) return options;
    return new GraylogConfig(options);
  }

  /**
   * Builds a config from the environment. Precedence: explicit `overrides` >
   * `GROW_GRAYLOG_<NAME>` > vendor variables > platform aliases ({@link VENDOR_ENV}) > defaults.
   */
  static fromEnv(overrides: GraylogConfigOptions = {}, env: EnvMap = process.env): GraylogConfig {
    const reader = new EnvReader(GraylogConfig.ENV_PREFIX, env);
    const fromEnv: GraylogConfigOptions = readCommonEnv(reader, VENDOR_ENV);
    const token = reader.secret("API_TOKEN", VENDOR_ENV.apiToken);
    if (token !== undefined) fromEnv.apiToken = token;
    const username = reader.string("USER", VENDOR_ENV.username);
    if (username !== undefined) fromEnv.username = username;
    const password = reader.secret("PASSWORD", VENDOR_ENV.password);
    if (password !== undefined) fromEnv.password = password;
    const gelfHost = reader.string("GELF_HOST", VENDOR_ENV.gelfHost);
    if (gelfHost !== undefined) fromEnv.gelfHost = gelfHost;
    const gelfPort = reader.int("GELF_PORT", VENDOR_ENV.gelfPort);
    if (gelfPort !== undefined) fromEnv.gelfPort = gelfPort;
    const protocolHit = reader.lookup("GELF_PROTOCOL", VENDOR_ENV.gelfProtocol);
    if (protocolHit !== undefined) {
      const protocol = parseGelfProtocol(protocolHit.value);
      if (protocol === undefined) {
        throw new ConfigError(
          `invalid value in environment variable ${protocolHit.name}: expected udp, tcp or http`,
        );
      }
      fromEnv.gelfProtocol = protocol;
    }
    const gelfHttpUrl = reader.string("GELF_HTTP_URL", VENDOR_ENV.gelfHttpUrl);
    if (gelfHttpUrl !== undefined) fromEnv.gelfHttpUrl = gelfHttpUrl;
    const gelfTls = reader.bool("GELF_TLS", VENDOR_ENV.gelfTls);
    if (gelfTls !== undefined) fromEnv.gelfTls = gelfTls;
    const otlp = reader.string("OTLP_ENDPOINT", VENDOR_ENV.otlpEndpoint);
    if (otlp !== undefined) fromEnv.otlpEndpoint = otlp;
    const merged = mergeOptions<GraylogConfigOptions>(fromEnv, overrides);
    return new GraylogConfig(merged);
  }

  /** A copy of this config with some fields replaced (validated again). */
  with(overrides: GraylogConfigOptions): GraylogConfig {
    const current: GraylogConfigOptions = {
      url: this.url,
      connectTimeoutMs: this.connectTimeoutMs,
      requestTimeoutMs: this.requestTimeoutMs,
      totalTimeoutMs: this.totalTimeoutMs,
      retry: this.retry,
      tls: { ...this.tls },
      headers: { ...this.headers },
      gelfHost: this.gelfHost,
      gelfProtocol: this.gelfProtocol,
      gelfTls: this.gelfTls,
      requestedBy: this.requestedBy,
      ...(this.proxy === undefined ? {} : { proxy: this.proxy }),
      ...(this.userAgentSuffix === undefined ? {} : { userAgentSuffix: this.userAgentSuffix }),
      ...(this.hooks === undefined ? {} : { hooks: this.hooks }),
      ...(this.logger === undefined ? {} : { logger: this.logger }),
      ...(this.apiToken === undefined ? {} : { apiToken: this.apiToken }),
      ...(this.username === undefined ? {} : { username: this.username }),
      ...(this.password === undefined ? {} : { password: this.password }),
      ...(this.gelfPort === undefined ? {} : { gelfPort: this.gelfPort }),
      ...(this.gelfHttpUrl === undefined ? {} : { gelfHttpUrl: this.gelfHttpUrl }),
      ...(this.otlpEndpoint === undefined ? {} : { otlpEndpoint: this.otlpEndpoint }),
    };
    return new GraylogConfig({ ...current, ...overrides });
  }

  /** Throws {@link ConfigError} when a setting is invalid. */
  validate(): void {
    validateCommonConfig(this);
    const problems: string[] = [];
    if (this.apiToken?.reveal().trim() === "") problems.push("apiToken must not be blank");
    if ((this.username === undefined) !== (this.password === undefined)) {
      problems.push("username and password must be given together");
    }
    if (
      this.gelfPort !== undefined &&
      (!Number.isInteger(this.gelfPort) || this.gelfPort < 1 || this.gelfPort > 65_535)
    ) {
      problems.push("gelfPort must be an integer 1..65535");
    }
    if (!(GELF_PROTOCOLS as readonly string[]).includes(this.gelfProtocol)) {
      problems.push("gelfProtocol must be udp, tcp or http");
    }
    if (this.gelfHttpUrl !== undefined && !isHttpUrl(this.gelfHttpUrl)) {
      problems.push("gelfHttpUrl must be an http(s) URL");
    }
    if (this.otlpEndpoint !== undefined && !isHttpUrl(this.otlpEndpoint)) {
      problems.push("otlpEndpoint must be an http(s) URL");
    }
    if (this.requestedBy.trim() === "") problems.push("requestedBy must not be blank");
    if (problems.length > 0) {
      throw new ConfigError(`invalid configuration: ${problems.join("; ")}`);
    }
  }

  /** The GELF port used for `protocol`: {@link gelfPort}, else 12202 for HTTP and 12201 otherwise. */
  gelfPortFor(protocol: GelfProtocol = this.gelfProtocol): number {
    return this.gelfPort ?? (protocol === "http" ? DEFAULT_GELF_HTTP_PORT : DEFAULT_GELF_PORT);
  }

  /** The effective GELF HTTP endpoint. */
  gelfHttpEndpoint(): string {
    if (this.gelfHttpUrl !== undefined) return this.gelfHttpUrl;
    const scheme = this.gelfTls ? "https" : "http";
    return `${scheme}://${urlHost(this.gelfHost)}:${this.gelfPortFor("http")}/gelf`;
  }

  /** The effective OTLP gRPC endpoint. */
  otlpGrpcEndpoint(): string {
    return this.otlpEndpoint ?? `http://${urlHost(this.gelfHost)}:${DEFAULT_OTLP_GRPC_PORT}`;
  }

  /** The `Authorization` header value: Basic `<token>:token` or Basic `<user>:<password>`. */
  authorizationHeader(): string | undefined {
    if (this.apiToken !== undefined) {
      return `Basic ${basicCredentials(this.apiToken.reveal(), "token")}`;
    }
    if (this.username !== undefined && this.password !== undefined) {
      return `Basic ${basicCredentials(this.username, this.password.reveal())}`;
    }
    return undefined;
  }

  /** Credential values to redact from error messages and logs. */
  knownSecrets(): string[] {
    const out = secretValues(this.apiToken, this.password);
    if (this.apiToken !== undefined) out.push(basicCredentials(this.apiToken.reveal(), "token"));
    if (this.username !== undefined && this.password !== undefined) {
      out.push(basicCredentials(this.username, this.password.reveal()));
    }
    return out;
  }

  /** Debug form with every credential redacted. */
  toJSON(): Record<string, unknown> {
    return {
      ...describeCommonConfig(this),
      apiToken: this.apiToken === undefined ? null : REDACTED,
      username: this.username ?? null,
      password: this.password === undefined ? null : REDACTED,
      gelfHost: this.gelfHost,
      gelfPort: this.gelfPort ?? null,
      gelfProtocol: this.gelfProtocol,
      gelfHttpUrl: this.gelfHttpUrl === undefined ? null : redactUrl(this.gelfHttpUrl),
      gelfTls: this.gelfTls,
      otlpEndpoint: this.otlpEndpoint === undefined ? null : redactUrl(this.otlpEndpoint),
      requestedBy: this.requestedBy,
    };
  }

  toString(): string {
    return `GraylogConfig(${JSON.stringify(this.toJSON())})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}
