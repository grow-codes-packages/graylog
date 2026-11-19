package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.EnvReader;
import codes.grow.packages.graylog.core.Hooks;
import codes.grow.packages.graylog.core.Logger;
import codes.grow.packages.graylog.core.Redaction;
import codes.grow.packages.graylog.core.RetryPolicy;
import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.core.TlsOptions;
import codes.grow.packages.graylog.core.TransportConfig;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Immutable configuration of a {@link GraylogClient} (SPEC section 2.2).
 *
 * <p>Build one with {@link #builder()} or read it from the environment with {@link #fromEnv()}.
 * Precedence: explicit builder value &gt; {@code GROW_GRAYLOG_<NAME>} &gt; vendor variables ({@code
 * GRAYLOG_*}) &gt; platform stack aliases ({@code GRAYLOG_HOST}, {@code GRAYLOG_PORT}, {@code
 * GRAYLOG_TRANSPORT}) &gt; default. {@link #toString()} never prints credentials.
 *
 * <p>REST credentials: an API token (sent as HTTP Basic {@code <token>:token}) wins over username
 * and password. The GELF fields configure the ingest transports of {@link
 * GraylogClient#logClient(GraylogLogClientOptions)}: unset values default to the host of {@link
 * #url()}, TCP, port 12201 (12202 for HTTP, see {@link #gelfPortFor(GelfProtocol)}) and {@code
 * http://<gelfHost>:<port>/gelf} (see {@link #gelfHttpEndpoint()}).
 */
public final class GraylogConfig {
  /** Default REST endpoint. */
  public static final String DEFAULT_URL = "http://127.0.0.1:9000";

  /** Default GELF UDP and TCP port. */
  public static final int DEFAULT_GELF_PORT = 12201;

  /** Default GELF HTTP port (Graylog has no fixed one; 12202 is the common choice). */
  public static final int DEFAULT_GELF_HTTP_PORT = 12202;

  /** Default port of the OpenTelemetry (gRPC) input. */
  public static final int DEFAULT_OTLP_GRPC_PORT = 4317;

  /** Default {@code X-Requested-By} value (Graylog requires it on every non-GET request). */
  public static final String DEFAULT_REQUESTED_BY = "grow-codes-graylog";

  /** Default GELF protocol. */
  public static final GelfProtocol DEFAULT_GELF_PROTOCOL = GelfProtocol.TCP;

  static final String[] URL_VENDOR_VARS = {"GRAYLOG_URL"};
  static final String[] API_TOKEN_VENDOR_VARS = {"GRAYLOG_API_TOKEN"};
  static final String[] USER_VENDOR_VARS = {"GRAYLOG_USER"};
  static final String[] PASSWORD_VENDOR_VARS = {"GRAYLOG_PASSWORD"};
  static final String[] GELF_HOST_VENDOR_VARS = {"GRAYLOG_GELF_HOST", "GRAYLOG_HOST"};
  static final String[] GELF_PORT_VENDOR_VARS = {"GRAYLOG_GELF_PORT", "GRAYLOG_PORT"};
  static final String[] GELF_PROTOCOL_VENDOR_VARS = {"GRAYLOG_GELF_PROTOCOL", "GRAYLOG_TRANSPORT"};
  static final String[] GELF_HTTP_URL_VENDOR_VARS = {"GRAYLOG_GELF_HTTP_URL"};
  static final String[] OTLP_ENDPOINT_VENDOR_VARS = {"GRAYLOG_OTLP_GRPC_ENDPOINT"};

  private final String url;
  private final Secret apiToken;
  private final String username;
  private final Secret password;
  private final String gelfHost;
  private final Integer gelfPort;
  private final GelfProtocol gelfProtocol;
  private final String gelfHttpUrl;
  private final boolean gelfTls;
  private final String otlpEndpoint;
  private final String requestedBy;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final Duration totalTimeout;
  private final RetryPolicy retry;
  private final TlsOptions tls;
  private final String proxy;
  private final Map<String, String> headers;
  private final String userAgentSuffix;
  private final Hooks hooks;
  private final Logger logger;

  private GraylogConfig(Builder b) {
    this.url = b.url != null ? b.url : DEFAULT_URL;
    this.apiToken = b.apiToken;
    this.username = b.username;
    this.password = b.password;
    this.gelfHost = b.gelfHost;
    this.gelfPort = b.gelfPort;
    this.gelfProtocol = b.gelfProtocol != null ? b.gelfProtocol : DEFAULT_GELF_PROTOCOL;
    this.gelfHttpUrl = b.gelfHttpUrl;
    this.gelfTls = b.gelfTls != null && b.gelfTls;
    this.otlpEndpoint = b.otlpEndpoint;
    this.requestedBy = b.requestedBy != null ? b.requestedBy : DEFAULT_REQUESTED_BY;
    this.connectTimeout = b.connectTimeout != null ? b.connectTimeout : Duration.ofSeconds(10);
    this.requestTimeout = b.requestTimeout != null ? b.requestTimeout : Duration.ofSeconds(30);
    this.totalTimeout = b.totalTimeout != null ? b.totalTimeout : Duration.ofSeconds(120);
    this.retry = b.retry != null ? b.retry : RetryPolicy.defaults();
    this.tls = b.tls != null ? b.tls : TlsOptions.defaults();
    this.proxy = b.proxy;
    this.headers = Map.copyOf(b.headers);
    this.userAgentSuffix = b.userAgentSuffix;
    this.hooks = b.hooks != null ? b.hooks : Hooks.NONE;
    this.logger = b.logger != null ? b.logger : Logger.NOOP;
  }

  /**
   * Starts an empty builder (every field at its default).
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns a builder pre-filled with this configuration.
   *
   * @return a new builder
   */
  public Builder toBuilder() {
    Builder b = new Builder();
    b.url = url;
    b.apiToken = apiToken;
    b.username = username;
    b.password = password;
    b.gelfHost = gelfHost;
    b.gelfPort = gelfPort;
    b.gelfProtocol = gelfProtocol;
    b.gelfHttpUrl = gelfHttpUrl;
    b.gelfTls = gelfTls;
    b.otlpEndpoint = otlpEndpoint;
    b.requestedBy = requestedBy;
    b.connectTimeout = connectTimeout;
    b.requestTimeout = requestTimeout;
    b.totalTimeout = totalTimeout;
    b.retry = retry;
    b.tls = tls;
    b.proxy = proxy;
    b.headers.putAll(headers);
    b.userAgentSuffix = userAgentSuffix;
    b.hooks = hooks;
    b.logger = logger;
    return b;
  }

  /**
   * Reads the configuration from the process environment.
   *
   * @return the validated configuration
   * @throws ConfigException when a variable holds an invalid value (the message names the variable,
   *     never the value)
   */
  public static GraylogConfig fromEnv() {
    return builder().fromEnv(EnvReader.system()).build();
  }

  /**
   * Reads the configuration from an explicit variable map (tests).
   *
   * @param env variable map
   * @return the validated configuration
   */
  public static GraylogConfig fromEnv(Map<String, String> env) {
    return builder().fromEnv(EnvReader.of(env)).build();
  }

  /**
   * Checks URLs, timeouts, TLS pairs, the GELF settings and the credentials.
   *
   * @throws ConfigException when a rule is violated
   */
  public void validate() {
    if (!isHttpUrl(url)) {
      throw new ConfigException("config: url must use http or https and include a host");
    }
    requirePositive("connectTimeout", connectTimeout);
    requirePositive("requestTimeout", requestTimeout);
    requirePositive("totalTimeout", totalTimeout);
    tls.validate();
    if (proxy != null) {
      URI p;
      try {
        p = new URI(proxy);
      } catch (URISyntaxException e) {
        throw new ConfigException("config: proxy is not a valid URL");
      }
      if (p.getHost() == null) {
        throw new ConfigException("config: proxy must be an absolute URL");
      }
    }
    if (!gelfProtocol.isGelf()) {
      throw new ConfigException("config: gelfProtocol must be udp, tcp or http");
    }
    if (gelfPort != null && (gelfPort < 1 || gelfPort > 65535)) {
      throw new ConfigException("config: gelfPort must be an integer 1..65535");
    }
    if (gelfHost != null && gelfHost.isBlank()) {
      throw new ConfigException("config: gelfHost must not be blank");
    }
    if (gelfHttpUrl != null && !isHttpUrl(gelfHttpUrl)) {
      throw new ConfigException("config: gelfHttpUrl must be an http(s) URL");
    }
    if (otlpEndpoint != null && !isHttpUrl(otlpEndpoint)) {
      throw new ConfigException("config: otlpEndpoint must be an http(s) URL");
    }
    if (apiToken != null && apiToken.reveal().isBlank()) {
      throw new ConfigException("config: apiToken must not be blank");
    }
    if ((username == null) != (password == null)) {
      throw new ConfigException("config: username and password must be given together");
    }
    if (username != null && username.isBlank()) {
      throw new ConfigException("config: username must not be blank");
    }
    if (requestedBy.isBlank()) {
      throw new ConfigException("config: requestedBy must not be blank");
    }
  }

  static boolean isHttpUrl(String s) {
    if (s == null) {
      return false;
    }
    try {
      URI u = new URI(s);
      String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
      return (scheme.equals("http") || scheme.equals("https")) && u.getHost() != null;
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private static void requirePositive(String name, Duration d) {
    if (d.isZero() || d.isNegative()) {
      throw new ConfigException("config: " + name + " must be positive");
    }
  }

  /**
   * Translates the common fields into transport settings (credentials are added per request).
   *
   * @return the transport configuration
   */
  public TransportConfig toTransportConfig() {
    return toTransportConfig(url, headers);
  }

  TransportConfig toTransportConfig(String baseUrl, Map<String, String> extraHeaders) {
    return TransportConfig.builder(baseUrl)
        .connectTimeout(connectTimeout)
        .requestTimeout(requestTimeout)
        .totalTimeout(totalTimeout)
        .retry(retry)
        .tls(tls)
        .proxy(proxy)
        .headers(extraHeaders)
        .userAgentSuffix(userAgentSuffix)
        .hooks(hooks)
        .logger(logger)
        .knownSecrets(this::knownSecrets)
        .build();
  }

  /**
   * Returns the secret values that must never appear in messages or logs.
   *
   * @return the API token, password and Basic credentials that are set
   */
  List<String> knownSecrets() {
    List<String> out = new ArrayList<>();
    if (apiToken != null && !apiToken.isCleared()) {
      out.add(apiToken.reveal());
    }
    if (password != null && !password.isCleared() && !password.reveal().isEmpty()) {
      out.add(password.reveal());
    }
    basicCredentials().ifPresent(out::add);
    return out;
  }

  /**
   * Returns the base64 HTTP Basic credentials: {@code <token>:token} for an API token (it wins),
   * {@code <user>:<password>} otherwise.
   *
   * @return the credentials, or empty when none are configured
   */
  Optional<String> basicCredentials() {
    String pair;
    if (apiToken != null) {
      pair = apiToken.reveal() + ":token";
    } else if (username != null) {
      pair = username + ":" + password.reveal();
    } else {
      return Optional.empty();
    }
    return Optional.of(Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Returns the REST base URL.
   *
   * @return the URL
   */
  public String url() {
    return url;
  }

  /**
   * Returns the Graylog access token.
   *
   * @return the token, or empty
   */
  public Optional<Secret> apiToken() {
    return Optional.ofNullable(apiToken);
  }

  /**
   * Returns the HTTP Basic username.
   *
   * @return the username, or empty
   */
  public Optional<String> username() {
    return Optional.ofNullable(username);
  }

  /**
   * Returns the HTTP Basic password.
   *
   * @return the password, or empty
   */
  public Optional<Secret> password() {
    return Optional.ofNullable(password);
  }

  /**
   * Returns the host of the GELF inputs: the configured value, else the host of {@link #url()}.
   *
   * @return the host
   */
  public String gelfHost() {
    if (gelfHost != null) {
      return gelfHost;
    }
    try {
      String h = new URI(url).getHost();
      if (h != null && h.startsWith("[") && h.endsWith("]")) {
        h = h.substring(1, h.length() - 1);
      }
      return h;
    } catch (URISyntaxException e) {
      return "127.0.0.1";
    }
  }

  /**
   * Returns the explicitly configured GELF port.
   *
   * @return the port, or empty for the protocol default
   */
  public OptionalInt gelfPort() {
    return gelfPort == null ? OptionalInt.empty() : OptionalInt.of(gelfPort);
  }

  /**
   * Returns the GELF port used for {@code protocol}: the configured port when set, else 12202 for
   * HTTP and 12201 otherwise.
   *
   * @param protocol the GELF protocol
   * @return the port
   */
  public int gelfPortFor(GelfProtocol protocol) {
    if (gelfPort != null) {
      return gelfPort;
    }
    return protocol == GelfProtocol.HTTP ? DEFAULT_GELF_HTTP_PORT : DEFAULT_GELF_PORT;
  }

  /**
   * Returns the GELF protocol of new log clients (default TCP).
   *
   * @return the protocol
   */
  public GelfProtocol gelfProtocol() {
    return gelfProtocol;
  }

  /**
   * Returns the explicitly configured GELF HTTP URL.
   *
   * @return the URL, or empty
   */
  public Optional<String> gelfHttpUrl() {
    return Optional.ofNullable(gelfHttpUrl);
  }

  /**
   * Returns the effective GELF HTTP URL: {@link #gelfHttpUrl()} when set, else {@code
   * http(s)://<gelfHost>:<gelfPortFor(HTTP)>/gelf} (https with {@link #gelfTls()}).
   *
   * @return the URL
   */
  public String gelfHttpEndpoint() {
    if (gelfHttpUrl != null) {
      return gelfHttpUrl;
    }
    return (gelfTls ? "https" : "http")
        + "://"
        + hostPort(gelfHost(), gelfPortFor(GelfProtocol.HTTP))
        + "/gelf";
  }

  /**
   * Returns whether the GELF TCP transport uses TLS and the default GELF HTTP URL uses https.
   *
   * @return true when enabled
   */
  public boolean gelfTls() {
    return gelfTls;
  }

  /**
   * Returns the explicitly configured OTLP/gRPC endpoint.
   *
   * @return the endpoint, or empty
   */
  public Optional<String> otlpEndpoint() {
    return Optional.ofNullable(otlpEndpoint);
  }

  /**
   * Returns the effective OTLP/gRPC endpoint: {@link #otlpEndpoint()} when set, else {@code
   * http://<gelfHost>:4317}.
   *
   * @return the endpoint
   */
  public String otlpGrpcEndpoint() {
    if (otlpEndpoint != null) {
      return otlpEndpoint;
    }
    return "http://" + hostPort(gelfHost(), DEFAULT_OTLP_GRPC_PORT);
  }

  static String hostPort(String host, int port) {
    String h = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
    return h + ":" + port;
  }

  /**
   * Returns the {@code X-Requested-By} value of non-GET requests.
   *
   * @return the value
   */
  public String requestedBy() {
    return requestedBy;
  }

  /**
   * Returns the connect timeout.
   *
   * @return the timeout
   */
  public Duration connectTimeout() {
    return connectTimeout;
  }

  /**
   * Returns the per-attempt timeout.
   *
   * @return the timeout
   */
  public Duration requestTimeout() {
    return requestTimeout;
  }

  /**
   * Returns the total timeout per call including retries.
   *
   * @return the timeout
   */
  public Duration totalTimeout() {
    return totalTimeout;
  }

  /**
   * Returns the retry policy.
   *
   * @return the policy
   */
  public RetryPolicy retry() {
    return retry;
  }

  /**
   * Returns the TLS options.
   *
   * @return the options
   */
  public TlsOptions tls() {
    return tls;
  }

  /**
   * Returns the explicit proxy URL.
   *
   * @return the proxy, or empty
   */
  public Optional<String> proxy() {
    return Optional.ofNullable(proxy);
  }

  /**
   * Returns the extra request headers.
   *
   * @return immutable map
   */
  public Map<String, String> headers() {
    return headers;
  }

  /**
   * Returns the user agent suffix.
   *
   * @return the suffix, or empty
   */
  public Optional<String> userAgentSuffix() {
    return Optional.ofNullable(userAgentSuffix);
  }

  /**
   * Returns the hooks.
   *
   * @return the hooks
   */
  public Hooks hooks() {
    return hooks;
  }

  /**
   * Returns the logger.
   *
   * @return the logger
   */
  public Logger logger() {
    return logger;
  }

  @Override
  public String toString() {
    return "GraylogConfig{url="
        + Redaction.redactUrl(url)
        + ", apiToken="
        + (apiToken == null ? "null" : Redaction.REDACTED)
        + ", username="
        + username
        + ", password="
        + (password == null ? "null" : Redaction.REDACTED)
        + ", gelfHost="
        + gelfHost
        + ", gelfPort="
        + gelfPort
        + ", gelfProtocol="
        + gelfProtocol
        + ", gelfHttpUrl="
        + (gelfHttpUrl == null ? "null" : Redaction.redactUrl(gelfHttpUrl))
        + ", gelfTls="
        + gelfTls
        + ", otlpEndpoint="
        + (otlpEndpoint == null ? "null" : Redaction.redactUrl(otlpEndpoint))
        + ", requestedBy="
        + requestedBy
        + ", connectTimeout="
        + connectTimeout
        + ", requestTimeout="
        + requestTimeout
        + ", totalTimeout="
        + totalTimeout
        + ", retry="
        + retry
        + ", tls="
        + tls
        + ", proxy="
        + (proxy == null ? "null" : Redaction.redactUrl(proxy))
        + ", headers="
        + Redaction.redactHeaders(headers)
        + ", userAgentSuffix="
        + userAgentSuffix
        + "}";
  }

  /**
   * Builder of the configuration.
   *
   * <p>Unset fields take the environment (when {@link #fromEnv(EnvReader)} is called) or the
   * default.
   */
  public static final class Builder {
    private String url;
    private Secret apiToken;
    private String username;
    private Secret password;
    private String gelfHost;
    private Integer gelfPort;
    private GelfProtocol gelfProtocol;
    private String gelfHttpUrl;
    private Boolean gelfTls;
    private String otlpEndpoint;
    private String requestedBy;
    private Duration connectTimeout;
    private Duration requestTimeout;
    private Duration totalTimeout;
    private RetryPolicy retry;
    private TlsOptions tls;
    private String proxy;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private String userAgentSuffix;
    private Hooks hooks;
    private Logger logger;

    private Builder() {}

    /**
     * Fills every field that was not set explicitly from the environment.
     *
     * @param env environment reader
     * @return this builder
     * @throws ConfigException when a variable holds an invalid value
     */
    public Builder fromEnv(EnvReader env) {
      if (url == null) {
        url = env.string("URL", URL_VENDOR_VARS).orElse(null);
      }
      if (apiToken == null) {
        apiToken = env.string("API_TOKEN", API_TOKEN_VENDOR_VARS).map(Secret::of).orElse(null);
      }
      if (username == null) {
        username = env.string("USER", USER_VENDOR_VARS).orElse(null);
      }
      if (password == null) {
        password = env.string("PASSWORD", PASSWORD_VENDOR_VARS).map(Secret::of).orElse(null);
      }
      if (gelfHost == null) {
        gelfHost = env.string("GELF_HOST", GELF_HOST_VENDOR_VARS).orElse(null);
      }
      if (gelfPort == null) {
        OptionalInt p = env.integer("GELF_PORT", GELF_PORT_VENDOR_VARS);
        gelfPort = p.isPresent() ? p.getAsInt() : null;
      }
      if (gelfProtocol == null) {
        Optional<String> p = env.string("GELF_PROTOCOL", GELF_PROTOCOL_VENDOR_VARS);
        if (p.isPresent()) {
          gelfProtocol =
              GelfProtocol.parseGelf(p.get())
                  .orElseThrow(
                      () ->
                          new ConfigException(
                              "config: invalid value in "
                                  + env.source("GELF_PROTOCOL", GELF_PROTOCOL_VENDOR_VARS).get()
                                  + " (expected udp, tcp or http)"));
        }
      }
      if (gelfHttpUrl == null) {
        gelfHttpUrl = env.string("GELF_HTTP_URL", GELF_HTTP_URL_VENDOR_VARS).orElse(null);
      }
      if (gelfTls == null) {
        gelfTls = env.bool("GELF_TLS").orElse(null);
      }
      if (otlpEndpoint == null) {
        otlpEndpoint = env.string("OTLP_ENDPOINT", OTLP_ENDPOINT_VENDOR_VARS).orElse(null);
      }
      if (connectTimeout == null) {
        connectTimeout = env.duration("CONNECT_TIMEOUT").orElse(null);
      }
      if (requestTimeout == null) {
        requestTimeout = env.duration("REQUEST_TIMEOUT").orElse(null);
      }
      if (totalTimeout == null) {
        totalTimeout = env.duration("TOTAL_TIMEOUT").orElse(null);
      }
      if (retry == null && env.integer("MAX_RETRIES").isPresent()) {
        int n = env.integer("MAX_RETRIES").getAsInt();
        if (n < 0) {
          String variable = EnvReader.DEFAULT_PREFIX + "MAX_RETRIES";
          throw new ConfigException("config: invalid value in " + variable + " (expected >= 0)");
        }
        retry = RetryPolicy.builder().maxRetries(n).build();
      }
      if (tls == null) {
        TlsOptions.Builder t = TlsOptions.builder();
        env.string("CA_CERT").ifPresent(p -> t.caCertPath(Paths.get(p)));
        env.string("CLIENT_CERT").ifPresent(p -> t.clientCertPath(Paths.get(p)));
        env.string("CLIENT_KEY").ifPresent(p -> t.clientKeyPath(Paths.get(p)));
        env.bool("INSECURE_SKIP_VERIFY").ifPresent(t::insecureSkipVerify);
        tls = t.build();
      }
      if (proxy == null) {
        proxy = env.string("PROXY").orElse(null);
      }
      return this;
    }

    /**
     * Sets the REST base URL (default {@value GraylogConfig#DEFAULT_URL}).
     *
     * @param url {@code http} or {@code https} URL
     * @return this builder
     */
    public Builder url(String url) {
      this.url = url;
      return this;
    }

    /**
     * Sets the Graylog access token (wins over username/password).
     *
     * @param token token
     * @return this builder
     */
    public Builder apiToken(Secret token) {
      this.apiToken = token;
      return this;
    }

    /**
     * Sets the Graylog access token (wins over username/password).
     *
     * @param token token
     * @return this builder
     */
    public Builder apiToken(String token) {
      this.apiToken = token == null ? null : Secret.of(token);
      return this;
    }

    /**
     * Sets HTTP Basic credentials.
     *
     * @param username username
     * @param password password
     * @return this builder
     */
    public Builder basicAuth(String username, Secret password) {
      this.username = username;
      this.password = password;
      return this;
    }

    /**
     * Sets HTTP Basic credentials.
     *
     * @param username username
     * @param password password
     * @return this builder
     */
    public Builder basicAuth(String username, String password) {
      return basicAuth(username, password == null ? null : Secret.of(password));
    }

    /**
     * Sets the host of the GELF inputs (default: the host of the URL).
     *
     * @param host host name or address
     * @return this builder
     */
    public Builder gelfHost(String host) {
      this.gelfHost = host;
      return this;
    }

    /**
     * Sets the GELF port (default 12201 for UDP/TCP, 12202 for HTTP).
     *
     * @param port port 1..65535
     * @return this builder
     */
    public Builder gelfPort(int port) {
      this.gelfPort = port;
      return this;
    }

    /**
     * Sets the GELF protocol of new log clients (default TCP).
     *
     * @param protocol UDP, TCP or HTTP
     * @return this builder
     */
    public Builder gelfProtocol(GelfProtocol protocol) {
      this.gelfProtocol = protocol;
      return this;
    }

    /**
     * Sets the full URL of the GELF HTTP input.
     *
     * @param url http(s) URL, e.g. {@code http://graylog:12202/gelf}
     * @return this builder
     */
    public Builder gelfHttpUrl(String url) {
      this.gelfHttpUrl = url;
      return this;
    }

    /**
     * Enables TLS for the GELF TCP transport and https for the default GELF HTTP URL (using the TLS
     * options of this configuration).
     *
     * @param tls true to enable
     * @return this builder
     */
    public Builder gelfTls(boolean tls) {
      this.gelfTls = tls;
      return this;
    }

    /**
     * Sets the http(s) URL of the OpenTelemetry (gRPC) input (default {@code
     * http://<gelfHost>:4317}).
     *
     * @param endpoint endpoint URL
     * @return this builder
     */
    public Builder otlpEndpoint(String endpoint) {
      this.otlpEndpoint = endpoint;
      return this;
    }

    /**
     * Sets the {@code X-Requested-By} value (default {@value GraylogConfig#DEFAULT_REQUESTED_BY}).
     *
     * @param requestedBy non-blank value
     * @return this builder
     */
    public Builder requestedBy(String requestedBy) {
      this.requestedBy = requestedBy;
      return this;
    }

    /**
     * Sets the connect timeout (default 10 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      this.connectTimeout = d;
      return this;
    }

    /**
     * Sets the per-attempt timeout (default 30 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      this.requestTimeout = d;
      return this;
    }

    /**
     * Sets the total timeout per call including retries (default 120 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      this.totalTimeout = d;
      return this;
    }

    /**
     * Sets the retry policy (default {@link RetryPolicy#defaults()}).
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      this.retry = retry;
      return this;
    }

    /**
     * Sets the TLS options; environment TLS variables are then ignored.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      this.tls = tls;
      return this;
    }

    /**
     * Sets an explicit proxy URL; environment proxies ({@code HTTPS_PROXY}) are never used.
     *
     * @param proxy proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      this.proxy = proxy;
      return this;
    }

    /**
     * Adds a header sent with every REST request.
     *
     * @param name header name
     * @param value header value
     * @return this builder
     */
    public Builder header(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Sets the text appended to the {@code User-Agent}.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      this.userAgentSuffix = suffix;
      return this;
    }

    /**
     * Sets request hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      this.hooks = hooks;
      return this;
    }

    /**
     * Sets the logger (default silent).
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      this.logger = logger;
      return this;
    }

    /**
     * Builds and validates the configuration.
     *
     * @return the configuration
     * @throws ConfigException when a rule is violated
     */
    public GraylogConfig build() {
      GraylogConfig c = new GraylogConfig(this);
      c.validate();
      return c;
    }
  }
}
