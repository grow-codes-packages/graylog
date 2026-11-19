package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.AuthenticationException;
import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.ConflictException;
import codes.grow.packages.graylog.core.EnvReader;
import codes.grow.packages.graylog.core.GraylogException;
import codes.grow.packages.graylog.core.HealthStatus;
import codes.grow.packages.graylog.core.Hooks;
import codes.grow.packages.graylog.core.HttpTransport;
import codes.grow.packages.graylog.core.Logger;
import codes.grow.packages.graylog.core.NotFoundException;
import codes.grow.packages.graylog.core.Poll;
import codes.grow.packages.graylog.core.Redaction;
import codes.grow.packages.graylog.core.RetryPolicy;
import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.core.TlsOptions;
import codes.grow.packages.graylog.core.TransportRequest;
import codes.grow.packages.graylog.core.TransportResponse;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.UnsupportedException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.BatchingLogClient;
import codes.grow.packages.graylog.logging.LogExporter;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

/**
 * Client for Graylog Open: health, REST admin (inputs, streams, index sets), search, and log
 * clients that send through GELF (UDP, TCP, HTTP) or OTLP/gRPC.
 *
 * <p>Thread-safe; create one per Graylog and close it when done. Every I/O method has a blocking
 * form and an {@code …Async} form returning {@link CompletableFuture}.
 *
 * <pre>{@code
 * try (GraylogClient client = GraylogClient.fromEnv()) {
 *   HealthStatus health = client.health();
 *   BatchingLogClient logs = client.logClient(GraylogLogClientOptions.defaults());
 *   logs.logger("app").info("hello", Map.of("user", "u-1"));
 * }
 * }</pre>
 */
public final class GraylogClient implements AutoCloseable {
  static final String PATH_LB_STATUS = "/api/system/lbstatus";
  static final String PATH_SYSTEM = "/api/system";
  static final String PATH_INPUTS = "/api/system/inputs";
  static final String PATH_INPUT_TYPES = "/api/system/inputs/types";
  static final String PATH_INPUT_STATES = "/api/system/inputstates";
  static final String PATH_STREAMS = "/api/streams";
  static final String PATH_STREAMS_PAGE = "/api/streams/paginated";
  static final String PATH_INDEX_SETS = "/api/system/indices/index_sets";
  static final String PATH_FIELDS = "/api/system/fields";
  static final String PATH_SEARCH_SYNC = "/api/views/search/sync";
  static final String PATH_MESSAGES = "/api/messages";

  /** Graylog's CSRF guard header, required on every non-GET request (HTTP 400 without it). */
  public static final String HEADER_REQUESTED_BY = "X-Requested-By";

  private static final DateTimeFormatter ISO_MILLIS =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
          .withZone(java.time.ZoneOffset.UTC);

  private final GraylogConfig config;
  private final HttpTransport transport;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final List<AutoCloseable> resources = new ArrayList<>();

  private GraylogClient(GraylogConfig config) {
    this.config = config;
    this.transport = new HttpTransport(config.toTransportConfig());
  }

  /**
   * Creates a client.
   *
   * @param config validated configuration
   * @return a new client
   * @throws ConfigException when the configuration is invalid
   */
  public static GraylogClient create(GraylogConfig config) {
    config.validate();
    return new GraylogClient(config);
  }

  /**
   * Creates a client from {@code GROW_GRAYLOG_*} and vendor environment variables.
   *
   * @return a new client
   */
  public static GraylogClient fromEnv() {
    return create(GraylogConfig.fromEnv());
  }

  /**
   * Starts a client builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the configuration.
   *
   * @return the configuration
   */
  public GraylogConfig config() {
    return config;
  }

  /**
   * Returns the HTTP transport, for service modules built on this client.
   *
   * @return the transport
   */
  public HttpTransport transport() {
    return transport;
  }

  /**
   * Registers a resource (log client, tail) closed with the client; closes it immediately when the
   * client is already closed.
   *
   * @param resource the resource
   */
  public void register(AutoCloseable resource) {
    synchronized (resources) {
      if (!closed.get()) {
        resources.add(resource);
        return;
      }
    }
    closeQuietly(resource);
  }

  private void requireOpen() {
    if (closed.get()) {
      throw new CancelledException("logClient: client is closed");
    }
  }

  // ---- requests --------------------------------------------------------------------------

  private TransportRequest.Builder request(String method, String path, String operation) {
    TransportRequest.Builder b = TransportRequest.builder(method, path).operation(operation);
    config.basicCredentials().ifPresent(c -> b.header("Authorization", "Basic " + c));
    if (!method.equals("GET") && !method.equals("HEAD")) {
      b.header(HEADER_REQUESTED_BY, config.requestedBy());
    }
    return b;
  }

  private CompletableFuture<JsonNode> json(TransportRequest.Builder b, String operation) {
    return transport.sendAsync(b.build()).thenApply(r -> Nodes.object(r.jsonNode(), operation));
  }

  private static <T> CompletableFuture<T> failed(RuntimeException e) {
    return CompletableFuture.failedFuture(e);
  }

  static String segment(String operation, String name, String value) {
    if (value == null || value.isBlank()) {
      throw new ValidationException(operation + ": " + name + " is required");
    }
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static <T> T await(CompletableFuture<T> f, String operation) {
    return HttpTransport.await(f, operation);
  }

  // ---- client surface ----------------------------------------------------------------------

  /**
   * Checks the unauthenticated load-balancer status ({@code GET /api/system/lbstatus}, {@code
   * text/plain}): {@code ALIVE} (200) is healthy {@code ok}, {@code THROTTLED} (429) {@code
   * degraded}, {@code DEAD} (503) or anything else {@code unhealthy}, network errors {@code
   * unreachable}. {@code details["lb_status"]} holds Graylog's word. Throws only {@link
   * CancelledException} and {@link ConfigException}.
   *
   * @return the health status
   */
  public HealthStatus health() {
    return await(healthAsync(), "health");
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health status
   */
  public CompletableFuture<HealthStatus> healthAsync() {
    TransportRequest r =
        TransportRequest.get(PATH_LB_STATUS)
            .operation("health")
            .header("Accept", "text/plain")
            .acceptAnyStatus()
            .maxRetries(0)
            .build();
    return transport
        .sendAsync(r)
        .handle(
            (resp, err) -> {
              if (err != null) {
                GraylogException e = HttpTransport.asSdkException(err, "health");
                if (e instanceof CancelledException || e instanceof ConfigException) {
                  throw e;
                }
                return HealthStatus.unreachable(String.valueOf(e.getMessage()));
              }
              return healthFrom(resp);
            });
  }

  private HealthStatus healthFrom(TransportResponse resp) {
    String text = resp.text().trim();
    int nl = text.indexOf('\n');
    String word =
        Redaction.truncate(
            Redaction.redactText(nl < 0 ? text : text.substring(0, nl), config.knownSecrets())
                .trim()
                .toUpperCase(Locale.ROOT),
            Redaction.MAX_VENDOR_TEXT);
    if (resp.status() == 429) {
      return new HealthStatus(false, "degraded", Map.of("lb_status", "THROTTLED"));
    }
    if (resp.status() == 503) {
      return new HealthStatus(false, "unhealthy", Map.of("lb_status", "DEAD"));
    }
    if (resp.status() == 200 && word.equals("ALIVE")) {
      return new HealthStatus(true, "ok", Map.of("lb_status", word));
    }
    if (word.isEmpty() || word.startsWith("<") || word.startsWith("{")) {
      word = "HTTP " + resp.status();
    }
    return new HealthStatus(false, "unhealthy", Map.of("lb_status", word));
  }

  /**
   * Makes an authenticated round trip ({@code GET /api/system}) and returns its latency.
   *
   * @return the latency
   * @throws AuthenticationException on bad or missing credentials
   */
  public Duration ping() {
    return await(pingAsync(), "ping");
  }

  /**
   * Asynchronous {@link #ping()}.
   *
   * @return a future with the latency
   */
  public CompletableFuture<Duration> pingAsync() {
    long start = System.nanoTime();
    return transport
        .sendAsync(request("GET", PATH_SYSTEM, "ping").build())
        .thenApply(r -> Duration.ofNanos(Math.max(1, System.nanoTime() - start)));
  }

  /**
   * Returns the server version as reported by {@code GET /api/system}, e.g. {@code 7.0.16+58e0f6e}.
   *
   * @return the version
   * @throws UnsupportedException when the server reports none
   */
  public String serverVersion() {
    return await(serverVersionAsync(), "serverVersion");
  }

  /**
   * Asynchronous {@link #serverVersion()}.
   *
   * @return a future with the version
   */
  public CompletableFuture<String> serverVersionAsync() {
    return systemInfoAsync()
        .thenApply(
            info -> {
              if (info.version().isEmpty()) {
                throw new UnsupportedException(
                    "serverVersion: the service does not report a version");
              }
              return info.version();
            });
  }

  /**
   * Returns the node's system information ({@code GET /api/system}).
   *
   * @return the information
   */
  public SystemInfo systemInfo() {
    return await(systemInfoAsync(), "systemInfo");
  }

  /**
   * Asynchronous {@link #systemInfo()}.
   *
   * @return a future with the information
   */
  public CompletableFuture<SystemInfo> systemInfoAsync() {
    return json(request("GET", PATH_SYSTEM, "systemInfo"), "systemInfo")
        .thenApply(SystemInfo::from);
  }

  // ---- inputs ------------------------------------------------------------------------------

  /**
   * Returns every input ({@code GET /api/system/inputs}).
   *
   * @return the inputs
   */
  public List<GraylogInput> listInputs() {
    return await(listInputsAsync(), "listInputs");
  }

  /**
   * Asynchronous {@link #listInputs()}.
   *
   * @return a future with the inputs
   */
  public CompletableFuture<List<GraylogInput>> listInputsAsync() {
    return json(request("GET", PATH_INPUTS, "listInputs"), "listInputs")
        .thenApply(n -> Nodes.array(n, "inputs").stream().map(GraylogInput::from).toList());
  }

  /**
   * Returns one input ({@code GET /api/system/inputs/{id}}).
   *
   * @param id input id
   * @return the input
   * @throws NotFoundException when it does not exist
   */
  public GraylogInput getInput(String id) {
    return await(getInputAsync(id), "getInput");
  }

  /**
   * Asynchronous {@link #getInput(String)}.
   *
   * @param id input id
   * @return a future with the input
   */
  public CompletableFuture<GraylogInput> getInputAsync(String id) {
    try {
      String path = PATH_INPUTS + "/" + segment("getInput", "id", id);
      return json(request("GET", path, "getInput"), "getInput").thenApply(GraylogInput::from);
    } catch (ValidationException e) {
      return failed(e);
    }
  }

  /**
   * Returns the installed input types, class name to display name ({@code GET
   * /api/system/inputs/types}).
   *
   * @return the types, sorted by class
   */
  public Map<String, String> listInputTypes() {
    return await(listInputTypesAsync(), "listInputTypes");
  }

  /**
   * Asynchronous {@link #listInputTypes()}.
   *
   * @return a future with the types
   */
  public CompletableFuture<Map<String, String>> listInputTypesAsync() {
    return json(request("GET", PATH_INPUT_TYPES, "listInputTypes"), "listInputTypes")
        .thenApply(n -> new TreeMap<>(Nodes.stringMap(n.get("types"))));
  }

  /**
   * Returns the runtime state of an input ({@code GET /api/system/inputstates/{id}}).
   *
   * @param id input id
   * @return the state
   * @throws NotFoundException when the input is not running on any node
   */
  public InputState getInputState(String id) {
    return await(getInputStateAsync(id), "getInputState");
  }

  /**
   * Asynchronous {@link #getInputState(String)}.
   *
   * @param id input id
   * @return a future with the state
   */
  public CompletableFuture<InputState> getInputStateAsync(String id) {
    try {
      String path = PATH_INPUT_STATES + "/" + segment("getInputState", "id", id);
      return json(request("GET", path, "getInputState"), "getInputState")
          .thenApply(InputState::from);
    } catch (ValidationException e) {
      return failed(e);
    }
  }

  /**
   * Creates an input of class {@code type} ({@code POST /api/system/inputs}) and returns its id.
   * Graylog does not reject a busy port here: the input is created and its state becomes {@code
   * FAILED} (see {@link #getInputState(String)} or {@link #ensureGelfInput}).
   *
   * @param type input class, e.g. {@link InputTypes#GELF_TCP}
   * @param configuration input configuration
   * @param options title and node
   * @return the input id
   * @throws NotFoundException for an unknown type (Graylog answers 404)
   */
  public String createInput(String type, Map<String, ?> configuration, CreateInputOptions options) {
    return await(createInputAsync(type, configuration, options), "createInput");
  }

  /**
   * Asynchronous {@link #createInput(String, Map, CreateInputOptions)}.
   *
   * @param type input class
   * @param configuration input configuration
   * @param options title and node
   * @return a future with the input id
   */
  public CompletableFuture<String> createInputAsync(
      String type, Map<String, ?> configuration, CreateInputOptions options) {
    if (type == null || type.isBlank()) {
      return failed(new ValidationException("createInput: type is required"));
    }
    CreateInputOptions o = options == null ? CreateInputOptions.defaults() : options;
    Map<String, Object> body = new LinkedHashMap<>();
    body.put(
        "title", o.title().orElse(type.substring(type.lastIndexOf('.') + 1) + " (grow-codes)"));
    body.put("type", type);
    body.put("global", o.node().isEmpty());
    body.put("configuration", configuration == null ? Map.of() : configuration);
    o.node().ifPresent(n -> body.put("node", n));
    return json(request("POST", PATH_INPUTS, "createInput").json(body), "createInput")
        .thenApply(
            n -> {
              String id = Nodes.text(n, "id");
              if (id.isEmpty()) {
                throw new UnavailableException("createInput: response has no input id");
              }
              return id;
            });
  }

  /**
   * Deletes an input ({@code DELETE /api/system/inputs/{id}}).
   *
   * @param id input id
   * @throws NotFoundException when it does not exist
   */
  public void deleteInput(String id) {
    await(deleteInputAsync(id), "deleteInput");
  }

  /**
   * Asynchronous {@link #deleteInput(String)}.
   *
   * @param id input id
   * @return a future completed when deleted
   */
  public CompletableFuture<Void> deleteInputAsync(String id) {
    try {
      String path = PATH_INPUTS + "/" + segment("deleteInput", "id", id);
      return transport
          .sendAsync(request("DELETE", path, "deleteInput").build())
          .thenApply(r -> null);
    } catch (ValidationException e) {
      return failed(e);
    }
  }

  /** Default configuration of a new GELF input per protocol (the same as the Docker bootstrap). */
  static Map<String, Object> gelfInputDefaults(GelfProtocol p, int port, String bindAddress) {
    Map<String, Object> c = new LinkedHashMap<>();
    c.put("bind_address", bindAddress);
    c.put("port", port);
    c.put("number_worker_threads", 2);
    c.put("decompress_size_limit", 8_388_608);
    switch (p) {
      case UDP:
        c.put("recv_buffer_size", 262_144);
        break;
      case TCP:
        c.put("recv_buffer_size", 1_048_576);
        c.put("tls_enable", false);
        c.put("tcp_keepalive", false);
        c.put("use_null_delimiter", true);
        c.put("max_message_size", 2_097_152);
        break;
      default:
        c.put("recv_buffer_size", 1_048_576);
        c.put("tls_enable", false);
        c.put("tcp_keepalive", false);
        c.put("enable_bulk_receiving", true);
        c.put("enable_cors", true);
        c.put("max_chunk_size", 8_388_608);
        c.put("idle_writer_timeout", 60);
        break;
    }
    return c;
  }

  /**
   * Returns a running GELF input of {@code protocol} on {@code port}: an existing input of the same
   * type, port and bind address is reused, otherwise one is created. It then waits until the input
   * is {@code RUNNING}. A {@code FAILED} input (for example a port used by another input) is a
   * {@link ConflictException} carrying Graylog's message, a {@code TimeoutException} after the
   * timeout; an input created by this call is deleted again when it does not start.
   *
   * @param protocol UDP, TCP or HTTP
   * @param port port 1..65535
   * @param options title, bind address, extra configuration, timeout
   * @return the input and whether it was created
   */
  public EnsuredInput ensureGelfInput(
      GelfProtocol protocol, int port, EnsureGelfInputOptions options) {
    return await(ensureGelfInputAsync(protocol, port, options), "ensureGelfInput");
  }

  /**
   * Asynchronous {@link #ensureGelfInput(GelfProtocol, int, EnsureGelfInputOptions)}.
   *
   * @param protocol UDP, TCP or HTTP
   * @param port port 1..65535
   * @param options options
   * @return a future with the input
   */
  public CompletableFuture<EnsuredInput> ensureGelfInputAsync(
      GelfProtocol protocol, int port, EnsureGelfInputOptions options) {
    String type;
    try {
      type = InputTypes.gelf(protocol);
    } catch (ValidationException e) {
      return failed(e);
    }
    if (port < 1 || port > 65535) {
      return failed(new ValidationException("ensureGelfInput: port must be an integer 1..65535"));
    }
    EnsureGelfInputOptions o = options == null ? EnsureGelfInputOptions.defaults() : options;
    String bind = o.bindAddress();
    Function<List<GraylogInput>, Optional<GraylogInput>> match =
        inputs ->
            inputs.stream()
                .filter(
                    in ->
                        in.type().equals(type)
                            && in.port() == port
                            && in.bindAddress().map(bind::equals).orElse(true))
                .findFirst();
    return listInputsAsync()
        .thenCompose(
            inputs -> {
              Optional<GraylogInput> existing = match.apply(inputs);
              if (existing.isPresent()) {
                return CompletableFuture.completedFuture(new EnsuredInput(existing.get(), false));
              }
              Map<String, Object> cfg = gelfInputDefaults(protocol, port, bind);
              cfg.putAll(o.configuration());
              cfg.put("bind_address", bind);
              cfg.put("port", port);
              String title =
                  o.title()
                      .orElse(
                          "grow-codes GELF "
                              + protocol.wireValue().toUpperCase(Locale.ROOT)
                              + " "
                              + port);
              return createInputAsync(type, cfg, CreateInputOptions.titled(title))
                  .thenCompose(id -> getInputAsync(id).thenApply(in -> new EnsuredInput(in, true)))
                  .exceptionallyCompose(
                      err ->
                          // the create may have reached the server; re-list before failing
                          listInputsAsync()
                              .handle(
                                  (again, lerr) -> {
                                    Optional<GraylogInput> found =
                                        lerr == null ? match.apply(again) : Optional.empty();
                                    if (found.isEmpty()) {
                                      throw HttpTransport.asSdkException(err, "ensureGelfInput");
                                    }
                                    return new EnsuredInput(found.get(), false);
                                  }));
            })
        .thenCompose(ensured -> waitRunning(ensured, protocol, port, o));
  }

  private CompletableFuture<EnsuredInput> waitRunning(
      EnsuredInput ensured, GelfProtocol protocol, int port, EnsureGelfInputOptions o) {
    String op = "ensureGelfInput";
    String id = ensured.id();
    String path = PATH_INPUT_STATES + "/" + segment(op, "id", id);
    CompletableFuture<EnsuredInput> polled =
        Poll.untilAsync(
            op,
            o.timeout(),
            o.interval(),
            () ->
                transport
                    .sendAsync(request("GET", path, op).acceptStatus(404).build())
                    .thenApply(
                        r -> {
                          if (r.status() == 404) {
                            return Optional.<EnsuredInput>empty(); // not started yet
                          }
                          InputState st = InputState.from(Nodes.object(r.jsonNode(), op));
                          if (InputTypes.STATE_FAILED.equals(st.state())) {
                            String msg =
                                op + " " + protocol + ":" + port + ": input failed to start";
                            if (st.detailedMessage().isPresent()) {
                              msg +=
                                  ": "
                                      + Redaction.truncate(
                                          Redaction.redactText(
                                              st.detailedMessage().get(), config.knownSecrets()),
                                          Redaction.MAX_VENDOR_TEXT);
                            }
                            throw new ConflictException(msg);
                          }
                          return InputTypes.STATE_RUNNING.equals(st.state())
                              ? Optional.of(ensured)
                              : Optional.<EnsuredInput>empty();
                        }));
    return polled.exceptionallyCompose(
        err -> {
          GraylogException e = HttpTransport.asSdkException(err, op);
          if (!ensured.created() || e instanceof CancelledException) {
            return failed(e);
          }
          return deleteInputAsync(id)
              .handle(
                  (v, ignored) -> {
                    throw e;
                  });
        });
  }

  // ---- streams and index sets --------------------------------------------------------------

  /**
   * Returns one page of streams ({@code GET /api/streams/paginated}).
   *
   * @param options page, page size, query and sort
   * @return the page
   */
  public StreamPage listStreams(ListStreamsOptions options) {
    return await(listStreamsAsync(options), "listStreams");
  }

  /**
   * Returns the first page of streams (50, sorted by title).
   *
   * @return the page
   */
  public StreamPage listStreams() {
    return listStreams(ListStreamsOptions.defaults());
  }

  /**
   * Asynchronous {@link #listStreams(ListStreamsOptions)}.
   *
   * @param options options
   * @return a future with the page
   */
  public CompletableFuture<StreamPage> listStreamsAsync(ListStreamsOptions options) {
    ListStreamsOptions o = options == null ? ListStreamsOptions.defaults() : options;
    if (o.page() < 1) {
      return failed(new ValidationException("listStreams: page must be at least 1"));
    }
    if (o.perPage() < 1 || o.perPage() > 10_000) {
      return failed(new ValidationException("listStreams: perPage must be an integer 1..10000"));
    }
    TransportRequest.Builder b =
        request("GET", PATH_STREAMS_PAGE, "listStreams")
            .query("page", o.page())
            .query("per_page", o.perPage())
            .query("sort", o.sort())
            .query("order", o.order().wireValue());
    o.query().ifPresent(q -> b.query("query", q));
    return json(b, "listStreams")
        .thenApply(
            n -> {
              List<GraylogStream> streams =
                  Nodes.array(n, "elements").stream().map(GraylogStream::from).toList();
              JsonNode p = n.path("pagination");
              long total = Nodes.number(p, "total", Nodes.number(n, "total", streams.size()));
              return new StreamPage(
                  streams,
                  (int) total,
                  (int) Nodes.number(p, "page", o.page()),
                  (int) Nodes.number(p, "per_page", o.perPage()));
            });
  }

  /**
   * Follows the pages of {@link #listStreams(ListStreamsOptions)} and returns every stream.
   *
   * @return a future with all streams
   */
  CompletableFuture<List<GraylogStream>> listAllStreamsAsync() {
    return collectStreams(1, new ArrayList<>());
  }

  private CompletableFuture<List<GraylogStream>> collectStreams(int page, List<GraylogStream> acc) {
    return listStreamsAsync(ListStreamsOptions.page(page, 100))
        .thenCompose(
            p -> {
              acc.addAll(p.streams());
              if (p.streams().isEmpty() || acc.size() >= p.total()) {
                return CompletableFuture.completedFuture(List.copyOf(acc));
              }
              return collectStreams(page + 1, acc);
            });
  }

  /**
   * Returns one stream ({@code GET /api/streams/{id}}).
   *
   * @param id stream id
   * @return the stream
   * @throws NotFoundException when it does not exist
   */
  public GraylogStream getStream(String id) {
    return await(getStreamAsync(id), "getStream");
  }

  /**
   * Asynchronous {@link #getStream(String)}.
   *
   * @param id stream id
   * @return a future with the stream
   */
  public CompletableFuture<GraylogStream> getStreamAsync(String id) {
    try {
      String path = PATH_STREAMS + "/" + segment("getStream", "id", id);
      return json(request("GET", path, "getStream"), "getStream").thenApply(GraylogStream::from);
    } catch (ValidationException e) {
      return failed(e);
    }
  }

  /**
   * Creates a stream ({@code POST /api/streams}) in the given (default: the default) index set and
   * resumes it unless {@code start(false)} (Graylog creates streams paused). Returns the stream id.
   *
   * @param options title, rules, index set
   * @return the stream id
   */
  public String createStream(CreateStreamOptions options) {
    return await(createStreamAsync(options), "createStream");
  }

  /**
   * Asynchronous {@link #createStream(CreateStreamOptions)}.
   *
   * @param options options
   * @return a future with the stream id
   */
  public CompletableFuture<String> createStreamAsync(CreateStreamOptions options) {
    String op = "createStream";
    if (options == null || options.title() == null || options.title().isBlank()) {
      return failed(new ValidationException(op + ": title is required"));
    }
    String matching = options.matchingType().toUpperCase(Locale.ROOT);
    if (!matching.equals("AND") && !matching.equals("OR")) {
      return failed(new ValidationException(op + ": matchingType must be \"AND\" or \"OR\""));
    }
    CompletableFuture<String> indexSet =
        options.indexSetId().isPresent()
            ? CompletableFuture.completedFuture(options.indexSetId().get())
            : listIndexSetsAsync()
                .thenApply(
                    sets ->
                        sets.stream()
                            .filter(IndexSet::isDefault)
                            .findFirst()
                            .or(() -> sets.stream().findFirst())
                            .map(IndexSet::id)
                            .orElseThrow(
                                () -> new ValidationException(op + ": no index set available")));
    return indexSet
        .thenCompose(
            setId -> {
              Map<String, Object> entity = new LinkedHashMap<>();
              entity.put("title", options.title());
              entity.put("description", options.description());
              entity.put("index_set_id", setId);
              entity.put("matching_type", matching);
              entity.put(
                  "remove_matches_from_default_stream", options.removeMatchesFromDefaultStream());
              entity.put("rules", options.rules().stream().map(StreamRule::toWire).toList());
              return json(request("POST", PATH_STREAMS, op).json(Map.of("entity", entity)), op);
            })
        .thenCompose(
            n -> {
              String id = Nodes.text(n, "stream_id");
              if (id.isEmpty()) {
                throw new UnavailableException(op + ": response has no stream id");
              }
              return options.start()
                  ? resumeStreamAsync(id).thenApply(v -> id)
                  : CompletableFuture.completedFuture(id);
            });
  }

  /**
   * Starts (resumes) a paused stream ({@code POST /api/streams/{id}/resume}).
   *
   * @param id stream id
   */
  public void resumeStream(String id) {
    await(resumeStreamAsync(id), "resumeStream");
  }

  /**
   * Asynchronous {@link #resumeStream(String)}.
   *
   * @param id stream id
   * @return a future completed when resumed
   */
  public CompletableFuture<Void> resumeStreamAsync(String id) {
    try {
      String path = PATH_STREAMS + "/" + segment("resumeStream", "id", id) + "/resume";
      return transport
          .sendAsync(request("POST", path, "resumeStream").idempotent(true).build())
          .thenApply(r -> null);
    } catch (ValidationException e) {
      return failed(e);
    }
  }

  /**
   * Deletes a stream ({@code DELETE /api/streams/{id}}).
   *
   * @param id stream id
   * @throws NotFoundException when it does not exist
   */
  public void deleteStream(String id) {
    await(deleteStreamAsync(id), "deleteStream");
  }

  /**
   * Asynchronous {@link #deleteStream(String)}.
   *
   * @param id stream id
   * @return a future completed when deleted
   */
  public CompletableFuture<Void> deleteStreamAsync(String id) {
    try {
      String path = PATH_STREAMS + "/" + segment("deleteStream", "id", id);
      return transport
          .sendAsync(request("DELETE", path, "deleteStream").build())
          .thenApply(r -> null);
    } catch (ValidationException e) {
      return failed(e);
    }
  }

  /**
   * Returns every index set ({@code GET /api/system/indices/index_sets?skip_stats=true}).
   *
   * @return the index sets
   */
  public List<IndexSet> listIndexSets() {
    return await(listIndexSetsAsync(), "listIndexSets");
  }

  /**
   * Asynchronous {@link #listIndexSets()}.
   *
   * @return a future with the index sets
   */
  public CompletableFuture<List<IndexSet>> listIndexSetsAsync() {
    return json(
            request("GET", PATH_INDEX_SETS, "listIndexSets").query("skip_stats", "true"),
            "listIndexSets")
        .thenApply(n -> Nodes.array(n, "index_sets").stream().map(IndexSet::from).toList());
  }

  // ---- search ------------------------------------------------------------------------------

  /**
   * Runs a Lucene query through the Views search API ({@code POST /api/views/search/sync}) and
   * returns one page of messages. An empty query matches everything. Query errors (Graylog answers
   * HTTP 200 with {@code errors}) are {@link ValidationException}s.
   *
   * @param query Lucene query, e.g. {@code marker:abc AND level:<=3}
   * @param options range, page, fields, sort and streams
   * @return the page
   */
  public MessageSearchResult search(String query, MessageSearchOptions options) {
    return await(searchAsync(query, options), "search");
  }

  /**
   * Searches the last 5 minutes with the default options.
   *
   * @param query Lucene query
   * @return the page
   */
  public MessageSearchResult search(String query) {
    return search(query, MessageSearchOptions.defaults());
  }

  /**
   * Asynchronous {@link #search(String, MessageSearchOptions)}.
   *
   * @param query Lucene query
   * @param options options
   * @return a future with the page
   */
  public CompletableFuture<MessageSearchResult> searchAsync(
      String query, MessageSearchOptions options) {
    MessageSearchOptions o = options == null ? MessageSearchOptions.defaults() : options;
    Map<String, Object> body;
    try {
      body = searchBody(query, o);
    } catch (ValidationException e) {
      return failed(e);
    }
    return json(request("POST", PATH_SEARCH_SYNC, "search").json(body).idempotent(true), "search")
        .thenApply(n -> decodeSearch(n, o.offset()));
  }

  Map<String, Object> searchBody(String query, MessageSearchOptions o) {
    String op = "search";
    if (o.limit() < 1 || o.limit() > MessageSearchOptions.MAX_LIMIT) {
      throw new ValidationException(op + ": limit must be an integer 1..10000");
    }
    if (o.offset() < 0) {
      throw new ValidationException(op + ": offset must not be negative");
    }
    List<SearchSort> sorts = o.sort().isEmpty() ? List.of(SearchSort.desc("timestamp")) : o.sort();
    List<Map<String, Object>> sortBody = new ArrayList<>();
    for (SearchSort s : sorts) {
      if (s.field() == null || s.field().isBlank()) {
        throw new ValidationException(op + ": sort field must not be empty");
      }
      sortBody.add(
          Map.of("field", s.field(), "order", s.order().wireValue().toUpperCase(Locale.ROOT)));
    }
    Map<String, Object> st = new LinkedHashMap<>();
    st.put("id", "st1");
    st.put("type", "messages");
    st.put("limit", o.limit());
    st.put("offset", o.offset());
    st.put("sort", sortBody);
    if (!o.fields().isEmpty()) {
      st.put("fields", o.fields());
    }
    Map<String, Object> q = new LinkedHashMap<>();
    q.put("id", "q1");
    q.put(
        "query",
        Map.of(
            "type",
            "elasticsearch",
            "query_string",
            query == null || query.isBlank() ? "*" : query));
    q.put("timerange", timerange(o));
    q.put("search_types", List.of(st));
    if (!o.streams().isEmpty()) {
      List<Map<String, Object>> filters = new ArrayList<>();
      for (String s : o.streams()) {
        filters.add(Map.of("type", "stream", "id", s));
      }
      q.put("filter", Map.of("type", "or", "filters", filters));
    }
    return Map.of("queries", List.of(q));
  }

  static Map<String, Object> timerange(MessageSearchOptions o) {
    String op = "search";
    int kinds =
        (o.range().isPresent() ? 1 : 0)
            + (o.start().isPresent() || o.end().isPresent() ? 1 : 0)
            + (o.keyword().isPresent() ? 1 : 0);
    if (kinds > 1) {
      throw new ValidationException(op + ": give only one of range, start/end and keyword");
    }
    if (o.start().isPresent() || o.end().isPresent()) {
      Instant end = o.end().orElseGet(Instant::now);
      Instant start = o.start().orElse(end.minus(MessageSearchOptions.DEFAULT_RANGE));
      if (start.isAfter(end)) {
        throw new ValidationException(op + ": start is after end");
      }
      return Map.of(
          "type",
          "absolute",
          "from",
          ISO_MILLIS.format(start.truncatedTo(ChronoUnit.MILLIS)),
          "to",
          ISO_MILLIS.format(end.truncatedTo(ChronoUnit.MILLIS)));
    }
    if (o.keyword().isPresent()) {
      if (o.keyword().get().isBlank()) {
        throw new ValidationException(op + ": keyword must not be empty");
      }
      return Map.of("type", "keyword", "keyword", o.keyword().get());
    }
    Duration range = o.range().orElse(MessageSearchOptions.DEFAULT_RANGE);
    if (range.isZero() || range.isNegative()) {
      throw new ValidationException(op + ": range must be positive");
    }
    long seconds = range.getSeconds() + (range.getNano() > 0 ? 1 : 0);
    return Map.of("type", "relative", "range", seconds);
  }

  private MessageSearchResult decodeSearch(JsonNode body, int offset) {
    JsonNode q1 = body.path("results").path("q1");
    List<JsonNode> errors = new ArrayList<>(Nodes.array(body, "errors"));
    errors.addAll(Nodes.array(q1, "errors"));
    if (!errors.isEmpty() || body.path("execution").path("completed_exceptionally").asBoolean()) {
      String text = "query failed";
      for (JsonNode e : errors) {
        String d = Nodes.text(e, "description");
        if (!d.isEmpty()) {
          text = d;
          break;
        }
      }
      throw new ValidationException(
          "search: "
              + Redaction.truncate(
                  Redaction.redactText(text, config.knownSecrets()), Redaction.MAX_VENDOR_TEXT));
    }
    JsonNode st = q1.path("search_types").path("st1");
    List<GraylogMessage> messages = new ArrayList<>();
    for (JsonNode h : Nodes.array(st, "messages")) {
      messages.add(GraylogMessage.of(Nodes.map(h.get("message")), Nodes.text(h, "index")));
    }
    long total = Nodes.number(st, "total_results", messages.size());
    JsonNode range = st.path("effective_timerange");
    OptionalInt next =
        !messages.isEmpty() && offset + messages.size() < total
            ? OptionalInt.of(offset + messages.size())
            : OptionalInt.empty();
    return new MessageSearchResult(
        messages, total, Nodes.instant(range, "from"), Nodes.instant(range, "to"), next);
  }

  /**
   * {@link #search(String, MessageSearchOptions)} over the last {@code range} (relative range,
   * whole seconds rounded up); start, end and keyword of {@code options} must be unset.
   *
   * @param query Lucene query
   * @param range positive duration
   * @param options other options
   * @return the page
   */
  public MessageSearchResult searchRelative(
      String query, Duration range, MessageSearchOptions options) {
    return await(searchRelativeAsync(query, range, options), "searchRelative");
  }

  /**
   * {@link #searchRelative(String, Duration, MessageSearchOptions)} with the default options.
   *
   * @param query Lucene query
   * @param range positive duration
   * @return the page
   */
  public MessageSearchResult searchRelative(String query, Duration range) {
    return searchRelative(query, range, MessageSearchOptions.defaults());
  }

  /**
   * Asynchronous {@link #searchRelative(String, Duration, MessageSearchOptions)}.
   *
   * @param query Lucene query
   * @param range positive duration
   * @param options other options
   * @return a future with the page
   */
  public CompletableFuture<MessageSearchResult> searchRelativeAsync(
      String query, Duration range, MessageSearchOptions options) {
    if (range == null || range.isZero() || range.isNegative()) {
      return failed(new ValidationException("searchRelative: range must be positive"));
    }
    MessageSearchOptions o = options == null ? MessageSearchOptions.defaults() : options;
    return searchAsync(query, o.toBuilder().range(range).build());
  }

  /**
   * Returns one stored message ({@code GET /api/messages/{index}/{id}}); search hits carry both
   * values ({@link GraylogMessage#index()}, {@link GraylogMessage#id()}).
   *
   * @param index index name
   * @param id message id
   * @return the message
   * @throws NotFoundException when it does not exist or the caller may not read it
   */
  public GraylogMessage getMessage(String index, String id) {
    return await(getMessageAsync(index, id), "getMessage");
  }

  /**
   * Asynchronous {@link #getMessage(String, String)}.
   *
   * @param index index name
   * @param id message id
   * @return a future with the message
   */
  public CompletableFuture<GraylogMessage> getMessageAsync(String index, String id) {
    String op = "getMessage";
    String path;
    try {
      path = PATH_MESSAGES + "/" + segment(op, "index", index) + "/" + segment(op, "id", id);
    } catch (ValidationException e) {
      return failed(e);
    }
    return json(request("GET", path, op), op)
        .thenApply(
            n -> {
              JsonNode message = n.path("message");
              GraylogMessage m =
                  GraylogMessage.of(Nodes.map(message.get("fields")), Nodes.text(n, "index"));
              if (m.id().isEmpty()) {
                return new GraylogMessage(
                    Nodes.text(message, "id"), m.index(), m.timestamp(), m.fields());
              }
              return m;
            });
  }

  /**
   * Returns every indexed field name ({@code GET /api/system/fields}), sorted.
   *
   * @return the field names
   */
  public List<String> listFields() {
    return await(listFieldsAsync(), "listFields");
  }

  /**
   * Asynchronous {@link #listFields()}.
   *
   * @return a future with the field names
   */
  public CompletableFuture<List<String>> listFieldsAsync() {
    return json(request("GET", PATH_FIELDS, "listFields"), "listFields")
        .thenApply(
            n ->
                Nodes.array(n, "fields").stream()
                    .filter(JsonNode::isTextual)
                    .map(JsonNode::asText)
                    .sorted()
                    .toList());
  }

  // ---- logging -----------------------------------------------------------------------------

  /**
   * Builds a GELF transport from the configuration for {@code protocol} ({@code null} = {@link
   * GraylogConfig#gelfProtocol()}): host {@link GraylogConfig#gelfHost()}, port {@link
   * GraylogConfig#gelfPortFor}, HTTP URL {@link GraylogConfig#gelfHttpEndpoint()}, TLS for TCP with
   * {@link GraylogConfig#gelfTls()}. TCP and HTTP share the client's timeouts and retry policy;
   * HTTP also its TLS, proxy, hooks and logger. The caller owns (closes) the transport.
   *
   * @param protocol UDP, TCP or HTTP
   * @param options UDP compression and chunk size, HTTP bulk and headers
   * @return the transport
   */
  public GelfTransport gelfTransport(GelfProtocol protocol, GelfTransportOptions options) {
    GelfProtocol p = protocol == null ? config.gelfProtocol() : protocol;
    GelfTransportOptions o = options == null ? GelfTransportOptions.defaults() : options;
    switch (p) {
      case UDP:
        return GelfUdpTransport.builder(config.gelfHost())
            .port(config.gelfPortFor(GelfProtocol.UDP))
            .compression(o.compression())
            .chunkSize(o.chunkSize())
            .build();
      case TCP:
        return GelfTcpTransport.builder(config.gelfHost())
            .port(config.gelfPortFor(GelfProtocol.TCP))
            .tls(config.gelfTls())
            .tlsOptions(config.tls())
            .connectTimeout(config.connectTimeout())
            .writeTimeout(config.requestTimeout())
            .retry(config.retry())
            .build();
      case HTTP:
        return GelfHttpTransport.builder(config.gelfHttpEndpoint())
            .config(config)
            .bulk(o.bulk())
            .headers(o.headers())
            .build();
      default:
        throw new ValidationException("gelfTransport: protocol must be udp, tcp or http");
    }
  }

  /**
   * Builds a GELF transport for {@code protocol} with the default options.
   *
   * @param protocol UDP, TCP or HTTP ({@code null} = configured)
   * @return the transport
   */
  public GelfTransport gelfTransport(GelfProtocol protocol) {
    return gelfTransport(protocol, GelfTransportOptions.defaults());
  }

  /**
   * Returns a batching log client that sends through GELF (UDP, TCP, HTTP) or OTLP/gRPC ({@link
   * GelfProtocol#OTLP}, endpoint {@link GraylogConfig#otlpGrpcEndpoint()}). {@link #close()}
   * flushes and closes it.
   *
   * @param options batching, resource, redaction and transport options
   * @return the log client
   * @throws CancelledException when the client is closed
   */
  public BatchingLogClient logClient(GraylogLogClientOptions options) {
    requireOpen();
    GraylogLogClientOptions o = options == null ? GraylogLogClientOptions.defaults() : options;
    GelfProtocol p = o.protocol().orElse(config.gelfProtocol());
    LogExporter exporter;
    if (p == GelfProtocol.OTLP) {
      exporter =
          OtlpGrpcLogExporter.builder(config.otlpGrpcEndpoint())
              .timeout(config.requestTimeout())
              .connectTimeout(config.connectTimeout())
              .tls(config.tls())
              .bearerToken(o.bearerToken().orElse(null))
              .headers(o.headers())
              .build();
    } else {
      GelfTransport t = o.transport().orElseGet(() -> gelfTransport(p, o.transportOptions()));
      exporter = new GelfLogExporter(t, o.host().orElse(null));
    }
    return logClientWithExporter(exporter, o);
  }

  /**
   * Returns a batching log client over the configured GELF protocol with default options.
   *
   * @return the log client
   */
  public BatchingLogClient logClient() {
    return logClient(GraylogLogClientOptions.defaults());
  }

  /**
   * Returns a batching log client for any exporter (batching, resource and redaction from {@code
   * options}). {@link #close()} flushes and closes it.
   *
   * @param exporter the exporter
   * @param options batching, resource and redaction
   * @return the log client
   * @throws CancelledException when the client is closed
   */
  public BatchingLogClient logClientWithExporter(
      LogExporter exporter, GraylogLogClientOptions options) {
    requireOpen();
    GraylogLogClientOptions o = options == null ? GraylogLogClientOptions.defaults() : options;
    BatchingLogClient lc;
    try {
      lc =
          BatchingLogClient.builder(exporter)
              .batchOptions(o.batchOptions())
              .resource(o.resource())
              .redaction(o.redaction())
              .build();
    } catch (RuntimeException e) {
      exporter.shutdown();
      throw e;
    }
    register(lc);
    return lc;
  }

  /**
   * Returns the {@link GraylogLogQueryClient} of this client (search, polling tail, streams,
   * fields).
   *
   * @param options streams and default window
   * @return the query client
   */
  public GraylogLogQueryClient logQueryClient(GraylogLogQueryClientOptions options) {
    return new GraylogLogQueryClient(
        this, options == null ? GraylogLogQueryClientOptions.defaults() : options);
  }

  /**
   * Returns the {@link GraylogLogQueryClient} with default options.
   *
   * @return the query client
   */
  public GraylogLogQueryClient logQueryClient() {
    return logQueryClient(GraylogLogQueryClientOptions.defaults());
  }

  /**
   * Returns whether {@link #close()} was called.
   *
   * @return true once closed
   */
  public boolean isClosed() {
    return closed.get();
  }

  /**
   * Flushes and closes the log clients created by this client, stops its tails and releases the
   * connections. Later calls fail with {@link CancelledException}. Idempotent.
   */
  @Override
  public void close() {
    List<AutoCloseable> copy;
    synchronized (resources) {
      if (!closed.compareAndSet(false, true)) {
        return;
      }
      copy = new ArrayList<>(resources);
      resources.clear();
    }
    for (AutoCloseable r : copy) {
      closeQuietly(r);
    }
    transport.close();
  }

  private static void closeQuietly(AutoCloseable r) {
    try {
      r.close();
    } catch (Exception ignored) {
      // best effort: close must not throw
    }
  }

  @Override
  public String toString() {
    return "GraylogClient{" + config + "}";
  }

  /** Builder that configures and creates a client in one chain. */
  public static final class Builder {
    private final GraylogConfig.Builder config = GraylogConfig.builder();

    private Builder() {}

    /**
     * Fills unset fields from an environment reader.
     *
     * @param env reader, e.g. {@link EnvReader#system()}
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      config.fromEnv(env);
      return this;
    }

    /**
     * Sets the REST base URL.
     *
     * @param url URL
     * @return this builder
     */
    public Builder url(String url) {
      config.url(url);
      return this;
    }

    /**
     * Sets the Graylog access token.
     *
     * @param token token
     * @return this builder
     */
    public Builder apiToken(String token) {
      config.apiToken(token);
      return this;
    }

    /**
     * Sets the Graylog access token.
     *
     * @param token token
     * @return this builder
     */
    public Builder apiToken(Secret token) {
      config.apiToken(token);
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
      config.basicAuth(username, password);
      return this;
    }

    /**
     * Sets the GELF host.
     *
     * @param host host
     * @return this builder
     */
    public Builder gelfHost(String host) {
      config.gelfHost(host);
      return this;
    }

    /**
     * Sets the GELF port.
     *
     * @param port port
     * @return this builder
     */
    public Builder gelfPort(int port) {
      config.gelfPort(port);
      return this;
    }

    /**
     * Sets the GELF protocol.
     *
     * @param protocol UDP, TCP or HTTP
     * @return this builder
     */
    public Builder gelfProtocol(GelfProtocol protocol) {
      config.gelfProtocol(protocol);
      return this;
    }

    /**
     * Sets the GELF HTTP URL.
     *
     * @param url URL
     * @return this builder
     */
    public Builder gelfHttpUrl(String url) {
      config.gelfHttpUrl(url);
      return this;
    }

    /**
     * Enables GELF TLS.
     *
     * @param tls true to enable
     * @return this builder
     */
    public Builder gelfTls(boolean tls) {
      config.gelfTls(tls);
      return this;
    }

    /**
     * Sets the OTLP/gRPC endpoint.
     *
     * @param endpoint endpoint
     * @return this builder
     */
    public Builder otlpEndpoint(String endpoint) {
      config.otlpEndpoint(endpoint);
      return this;
    }

    /**
     * Sets the connect timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      config.connectTimeout(d);
      return this;
    }

    /**
     * Sets the per-attempt timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      config.requestTimeout(d);
      return this;
    }

    /**
     * Sets the total timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      config.totalTimeout(d);
      return this;
    }

    /**
     * Sets the retry policy.
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      config.retry(retry);
      return this;
    }

    /**
     * Sets the TLS options.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      config.tls(tls);
      return this;
    }

    /**
     * Sets the proxy URL.
     *
     * @param proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      config.proxy(proxy);
      return this;
    }

    /**
     * Adds a header.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      config.header(name, value);
      return this;
    }

    /**
     * Sets the user agent suffix.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      config.userAgentSuffix(suffix);
      return this;
    }

    /**
     * Sets hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      config.hooks(hooks);
      return this;
    }

    /**
     * Sets the logger.
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      config.logger(logger);
      return this;
    }

    /**
     * Builds the configuration and the client.
     *
     * @return a new client
     * @throws ConfigException when the configuration is invalid
     */
    public GraylogClient build() {
      return create(config.build());
    }
  }
}
