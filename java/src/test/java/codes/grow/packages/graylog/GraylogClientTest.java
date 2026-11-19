package codes.grow.packages.graylog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.graylog.core.AuthenticationException;
import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.ConflictException;
import codes.grow.packages.graylog.core.HealthStatus;
import codes.grow.packages.graylog.core.Hooks;
import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.Logger;
import codes.grow.packages.graylog.core.MockServer;
import codes.grow.packages.graylog.core.NotFoundException;
import codes.grow.packages.graylog.core.RetryPolicy;
import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.core.TimeoutException;
import codes.grow.packages.graylog.core.TlsOptions;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.UnsupportedException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.BatchingLogClient;
import codes.grow.packages.graylog.logging.SortOrder;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GraylogClientTest {
  private MockServer server;
  private GraylogClient client;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = client(server.url());
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  static GraylogClient client(String url) {
    return GraylogClient.builder()
        .url(url)
        .apiToken("tok-123456")
        .retry(RetryPolicy.builder().maxRetries(1).initialBackoff(Duration.ofMillis(1)).build())
        .build();
  }

  private MockServer.Recorded last() {
    List<MockServer.Recorded> r = server.requests();
    return r.get(r.size() - 1);
  }

  private static JsonNode json(MockServer.Recorded r) {
    return Json.tree(r.body().getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void healthMapsLbStatus() throws Exception {
    Fixtures.enqueue(server, "health.ok");
    HealthStatus ok = client.health();
    assertThat(ok.healthy()).isTrue();
    assertThat(ok.status()).isEqualTo("ok");
    assertThat(ok.details()).containsEntry("lb_status", "ALIVE");
    assertThat(last().uri()).isEqualTo("/api/system/lbstatus");
    assertThat(last().header("Accept")).isEqualTo("text/plain");
    assertThat(last().header("Authorization")).isNull();

    server.enqueue(429, "THROTTLED").enqueue(503, "DEAD").enqueue(500, "<html>boom</html>");
    server.enqueue(200, "STARTING\nmore").enqueue(200, "");
    assertThat(client.health())
        .isEqualTo(new HealthStatus(false, "degraded", Map.of("lb_status", "THROTTLED")));
    assertThat(client.health().details()).containsEntry("lb_status", "DEAD");
    assertThat(client.health().details()).containsEntry("lb_status", "HTTP 500");
    assertThat(client.health().details()).containsEntry("lb_status", "STARTING");
    assertThat(client.healthAsync().get().details()).containsEntry("lb_status", "HTTP 200");

    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    try (GraylogClient down = client("http://127.0.0.1:" + port)) {
      HealthStatus h = down.health();
      assertThat(h.status()).isEqualTo("unreachable");
      assertThat(h.healthy()).isFalse();
    }
    GraylogClient closed = client(server.url());
    closed.close();
    assertThatThrownBy(closed::health).isInstanceOf(CancelledException.class);
  }

  @Test
  void pingAuthAndVersion() throws Exception {
    Fixtures.enqueue(server, "ping.ok_token");
    assertThat(client.ping()).isPositive();
    String expected =
        "Basic "
            + Base64.getEncoder()
                .encodeToString("tok-123456:token".getBytes(StandardCharsets.UTF_8));
    assertThat(last().header("Authorization")).isEqualTo(expected);
    assertThat(last().header("X-Requested-By")).isNull();

    Fixtures.enqueue(server, "ping.unauthorized");
    assertThatThrownBy(client::ping)
        .isInstanceOf(AuthenticationException.class)
        .hasMessageNotContaining("tok-123456");

    Fixtures.enqueue(server, "ping.ok_token");
    String version = client.serverVersion();
    assertThat(version).startsWith("7.0.");
    Fixtures.enqueue(server, "ping.ok_token");
    SystemInfo info = client.systemInfoAsync().get();
    assertThat(info.version()).isEqualTo(version);
    assertThat(info.nodeId()).isNotEmpty();
    assertThat(info.startedAt()).isPresent();
    assertThat(info.isProcessing()).isTrue();

    server.enqueue(200, "{\"facility\":\"graylog-server\"}");
    assertThatThrownBy(client::serverVersion).isInstanceOf(UnsupportedException.class);
    server.enqueue(200, "[]");
    assertThatThrownBy(client::systemInfo)
        .isInstanceOf(UnavailableException.class)
        .hasMessageContaining("not a JSON object");

    try (GraylogClient pw =
        GraylogClient.builder().url(server.url()).basicAuth("admin", "pw-secret-1").build()) {
      Fixtures.enqueue(server, "ping.ok_password");
      pw.pingAsync().get();
      assertThat(last().header("Authorization"))
          .isEqualTo(
              "Basic "
                  + Base64.getEncoder()
                      .encodeToString("admin:pw-secret-1".getBytes(StandardCharsets.UTF_8)));
    }
    try (GraylogClient anon = GraylogClient.builder().url(server.url()).build()) {
      Fixtures.enqueue(server, "ping.no_auth");
      assertThatThrownBy(anon::ping).isInstanceOf(AuthenticationException.class);
      assertThat(last().header("Authorization")).isNull();
    }
  }

  @Test
  void inputs() throws Exception {
    Fixtures.enqueue(server, "listInputs.ok");
    List<GraylogInput> inputs = client.listInputs();
    assertThat(inputs).isNotEmpty();
    assertThat(inputs).anyMatch(i -> i.type().equals(InputTypes.GELF_TCP) && i.port() == 12201);

    Fixtures.enqueue(server, "getInput.ok");
    GraylogInput in = client.getInput("6afe0a6607ba3acebff1891c");
    assertThat(last().uri()).isEqualTo("/api/system/inputs/6afe0a6607ba3acebff1891c");
    assertThat(in.type()).isEqualTo(InputTypes.GELF_HTTP);
    assertThat(in.port()).isEqualTo(12299);
    assertThat(in.bindAddress()).contains("0.0.0.0");
    assertThat(in.global()).isTrue();
    assertThat(in.createdAt()).isPresent();
    assertThat(in.attributes().get("tls_key_password")).isEqualTo(Map.of("is_set", false));

    Fixtures.enqueue(server, "getInput.not_found");
    assertThatThrownBy(() -> client.getInput("6afe0a6607ba3acebff18999"))
        .isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.getInput(" ")).isInstanceOf(ValidationException.class);
    client.getInputAsync("a/b").exceptionally(e -> null).get();

    Fixtures.enqueue(server, "listInputTypes.ok");
    Map<String, String> types = client.listInputTypes();
    assertThat(types).containsKey(InputTypes.GELF_HTTP);

    Fixtures.enqueue(server, "getInputState.running");
    InputState st = client.getInputState("6afe0a6607ba3acebff1891c");
    assertThat(st.state()).isEqualTo("RUNNING");
    assertThat(st.input().id()).isNotEmpty();
    assertThatThrownBy(() -> client.getInputState(null)).isInstanceOf(ValidationException.class);
    Fixtures.enqueue(server, "getInputState.port_collision");
    assertThat(client.getInputState("x").state()).isEqualTo("FAILED");

    Fixtures.enqueue(server, "createInput.created");
    String id = client.createInput(InputTypes.GELF_UDP, Map.of("port", 12291), null);
    assertThat(id).hasSize(24);
    MockServer.Recorded created = last();
    assertThat(created.method()).isEqualTo("POST");
    assertThat(created.header("X-Requested-By")).isEqualTo("grow-codes-graylog");
    JsonNode body = json(created);
    assertThat(body.path("title").asText()).isEqualTo("GELFUDPInput (grow-codes)");
    assertThat(body.path("global").asBoolean()).isTrue();
    assertThat(body.path("configuration").path("port").asInt()).isEqualTo(12291);
    assertThat(body.has("node")).isFalse();

    server.enqueue(201, "{\"id\":\"n1\"}");
    client.createInput(
        InputTypes.GELF_TCP, null, CreateInputOptions.titled("t").withNode("node-1"));
    body = json(last());
    assertThat(body.path("global").asBoolean()).isFalse();
    assertThat(body.path("node").asText()).isEqualTo("node-1");
    assertThat(body.path("title").asText()).isEqualTo("t");

    server.enqueue(201, "{}");
    assertThatThrownBy(() -> client.createInput("x.Y", Map.of(), CreateInputOptions.defaults()))
        .isInstanceOf(UnavailableException.class);
    Fixtures.enqueue(server, "createInput.bad_type");
    assertThatThrownBy(() -> client.createInput("org.example.Nope", Map.of(), null))
        .isInstanceOf(NotFoundException.class);
    Fixtures.enqueue(server, "createInput.missing_requested_by");
    assertThatThrownBy(() -> client.createInput("x.Y", Map.of(), null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.createInput("", Map.of(), null))
        .isInstanceOf(ValidationException.class);

    Fixtures.enqueue(server, "deleteInput.deleted");
    client.deleteInput("abc");
    assertThat(last().method()).isEqualTo("DELETE");
    Fixtures.enqueue(server, "deleteInput.not_found");
    assertThatThrownBy(() -> client.deleteInput("abc")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.deleteInput("")).isInstanceOf(ValidationException.class);
  }

  private static String inputJson(String id, String type, int port, String bind) {
    return "{\"id\":\""
        + id
        + "\",\"type\":\""
        + type
        + "\",\"attributes\":{\"port\":"
        + port
        + (bind == null ? "" : ",\"bind_address\":\"" + bind + "\"")
        + "}}";
  }

  @Test
  void ensureGelfInputReusesExisting() {
    server.enqueue(
        200,
        "{\"inputs\":["
            + inputJson("u1", InputTypes.GELF_UDP, 12201, "0.0.0.0")
            + ","
            + inputJson("t0", InputTypes.GELF_TCP, 12201, "10.0.0.1")
            + ","
            + inputJson("t1", InputTypes.GELF_TCP, 12201, null)
            + "]}");
    server.enqueue(200, "{\"id\":\"t1\",\"state\":\"RUNNING\"}");
    EnsuredInput e = client.ensureGelfInput(GelfProtocol.TCP, 12201, null);
    assertThat(e.created()).isFalse();
    assertThat(e.id()).isEqualTo("t1");
  }

  @Test
  void ensureGelfInputCreatesAndWaits() {
    server.enqueue(200, "{\"inputs\":[]}");
    server.enqueue(201, "{\"id\":\"h1\"}");
    server.enqueue(200, inputJson("h1", InputTypes.GELF_HTTP, 12292, "0.0.0.0"));
    server.enqueue(404, "{\"type\":\"ApiError\",\"message\":\"not running\"}");
    server.enqueue(200, "{\"id\":\"h1\",\"state\":\"STARTING\"}");
    server.enqueue(200, "{\"id\":\"h1\",\"state\":\"RUNNING\"}");
    EnsuredInput e =
        client.ensureGelfInput(
            GelfProtocol.HTTP,
            12292,
            EnsureGelfInputOptions.builder()
                .interval(Duration.ofMillis(5))
                .configuration("enable_bulk_receiving", false)
                .title("custom")
                .bindAddress(null)
                .timeout(null)
                .build());
    assertThat(e.created()).isTrue();
    assertThat(e.input().port()).isEqualTo(12292);
    JsonNode body = json(server.requests().get(1));
    assertThat(body.path("type").asText()).isEqualTo(InputTypes.GELF_HTTP);
    assertThat(body.path("title").asText()).isEqualTo("custom");
    JsonNode cfg = body.path("configuration");
    assertThat(cfg.path("enable_bulk_receiving").asBoolean()).isFalse();
    assertThat(cfg.path("max_chunk_size").asInt()).isEqualTo(8_388_608);
    assertThat(cfg.path("port").asInt()).isEqualTo(12292);
  }

  @Test
  void ensureGelfInputFailedStateDeletesCreatedInput() {
    server.enqueue(200, "{\"inputs\":[]}");
    server.enqueue(201, "{\"id\":\"u9\"}");
    server.enqueue(200, inputJson("u9", InputTypes.GELF_UDP, 12201, "0.0.0.0"));
    Fixtures.enqueue(server, "getInputState.port_collision");
    server.enqueue(204, "");
    assertThatThrownBy(
            () ->
                client.ensureGelfInput(
                    GelfProtocol.UDP,
                    12201,
                    EnsureGelfInputOptions.builder().interval(Duration.ofMillis(5)).build()))
        .isInstanceOf(ConflictException.class)
        .hasMessageContaining("input failed to start");
    MockServer.Recorded del = last();
    assertThat(del.method()).isEqualTo("DELETE");
    assertThat(del.uri()).isEqualTo("/api/system/inputs/u9");
    JsonNode cfg = json(server.requests().get(1)).path("configuration");
    assertThat(cfg.path("recv_buffer_size").asInt()).isEqualTo(262_144);
    assertThat(json(server.requests().get(1)).path("title").asText())
        .isEqualTo("grow-codes GELF UDP 12201");
  }

  @Test
  void ensureGelfInputTimeoutAndCreateErrors() {
    server.enqueue(200, "{\"inputs\":[]}");
    server.enqueue(201, "{\"id\":\"t5\"}");
    server.enqueue(200, inputJson("t5", InputTypes.GELF_TCP, 12205, "0.0.0.0"));
    server.fallback(ex -> MockServer.send(ex, 200, "{\"id\":\"t5\",\"state\":\"STARTING\"}"));
    assertThatThrownBy(
            () ->
                client.ensureGelfInput(
                    GelfProtocol.TCP,
                    12205,
                    EnsureGelfInputOptions.builder()
                        .interval(Duration.ofMillis(10))
                        .timeout(Duration.ofMillis(60))
                        .build()))
        .isInstanceOf(TimeoutException.class);
    assertThat(server.requests()).anyMatch(r -> r.method().equals("DELETE"));

    server.fallback(ex -> MockServer.send(ex, 500, "{}"));
    // create fails, the re-list finds the input (the create reached the server)
    server.enqueue(200, "{\"inputs\":[]}");
    server.enqueue(400, "{\"message\":\"bad\"}");
    server.enqueue(
        200, "{\"inputs\":[" + inputJson("t6", InputTypes.GELF_TCP, 12206, "0.0.0.0") + "]}");
    server.enqueue(200, "{\"state\":\"RUNNING\"}");
    EnsuredInput e = client.ensureGelfInput(GelfProtocol.TCP, 12206, null);
    assertThat(e.id()).isEqualTo("t6");
    assertThat(e.created()).isFalse();
    // create fails and the re-list does not find it
    server.enqueue(200, "{\"inputs\":[]}");
    server.enqueue(400, "{\"message\":\"bad config\"}");
    server.enqueue(200, "{\"inputs\":[]}");
    assertThatThrownBy(() -> client.ensureGelfInput(GelfProtocol.TCP, 12207, null))
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("bad config");
    // create fails and the re-list fails too
    server.enqueue(200, "{\"inputs\":[]}");
    server.enqueue(400, "{\"message\":\"bad config\"}");
    server.enqueue(401, "");
    assertThatThrownBy(() -> client.ensureGelfInput(GelfProtocol.TCP, 12207, null))
        .isInstanceOf(ValidationException.class);

    assertThatThrownBy(() -> client.ensureGelfInput(GelfProtocol.OTLP, 4317, null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.ensureGelfInput(null, 4317, null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.ensureGelfInput(GelfProtocol.UDP, 0, null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.ensureGelfInput(GelfProtocol.UDP, 70000, null))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void ensureGelfInputExistingFailureKeepsInput() {
    server.enqueue(
        200, "{\"inputs\":[" + inputJson("x1", InputTypes.GELF_UDP, 1, "0.0.0.0") + "]}");
    server.enqueue(200, "{\"state\":\"FAILED\"}");
    assertThatThrownBy(() -> client.ensureGelfInput(GelfProtocol.UDP, 1, null))
        .isInstanceOf(ConflictException.class);
    assertThat(server.requests()).noneMatch(r -> r.method().equals("DELETE"));
  }

  @Test
  void streams() throws Exception {
    Fixtures.enqueue(server, "listStreams.ok");
    StreamPage page = client.listStreams();
    assertThat(last().uri())
        .startsWith("/api/streams/paginated?")
        .contains("page=1", "per_page=50", "sort=title", "order=asc");
    assertThat(page.total()).isEqualTo(3);
    assertThat(page.page()).isEqualTo(1);
    assertThat(page.perPage()).isEqualTo(50);
    assertThat(page.streams()).anyMatch(GraylogStream::isDefault);

    server.enqueue(200, "{\"elements\":[{\"id\":\"s\",\"rules\":[{\"field\":\"f\",\"type\":1}]}]}");
    StreamPage p2 =
        client.listStreams(
            ListStreamsOptions.page(2, 10).withQuery("abc").withSort("id", SortOrder.DESC));
    assertThat(last().uri())
        .contains("page=2", "per_page=10", "sort=id", "order=desc", "query=abc");
    assertThat(p2.total()).isEqualTo(1);
    assertThat(p2.page()).isEqualTo(2);
    assertThat(p2.streams().get(0).rules().get(0).type()).isEqualTo(StreamRule.TYPE_EXACT);
    assertThatThrownBy(() -> client.listStreams(ListStreamsOptions.page(-1, 1)))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.listStreams(ListStreamsOptions.page(1, 20000)))
        .isInstanceOf(ValidationException.class);
    server.enqueue(200, "{\"total\":0}");
    assertThat(client.listStreams(null).streams()).isEmpty();

    Fixtures.enqueue(server, "getStream.ok");
    GraylogStream s = client.getStream("6afe0a6607ba3acebff1894e");
    assertThat(s.title()).isNotEmpty();
    assertThat(s.rules()).isNotEmpty();
    assertThat(s.indexSetId()).isNotEmpty();
    Fixtures.enqueue(server, "getStream.not_found");
    assertThatThrownBy(() -> client.getStream("nope")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.getStream("")).isInstanceOf(ValidationException.class);

    // createStream with the default index set lookup and resume
    Fixtures.enqueue(server, "listIndexSets.ok");
    Fixtures.enqueue(server, "createStream.created");
    Fixtures.enqueue(server, "resumeStream.ok");
    String id =
        client.createStream(
            CreateStreamOptions.builder("grow")
                .description("d")
                .rules(StreamRule.of("marker", StreamRule.TYPE_EXACT, "abc"))
                .matchingType("or")
                .removeMatchesFromDefaultStream(true)
                .build());
    assertThat(id).isEqualTo("6afe0a6607ba3acebff1894e");
    List<MockServer.Recorded> reqs = server.requests();
    MockServer.Recorded create = reqs.get(reqs.size() - 2);
    JsonNode entity = json(create).path("entity");
    assertThat(entity.path("title").asText()).isEqualTo("grow");
    assertThat(entity.path("matching_type").asText()).isEqualTo("OR");
    assertThat(entity.path("index_set_id").asText()).isNotEmpty();
    assertThat(entity.path("remove_matches_from_default_stream").asBoolean()).isTrue();
    assertThat(entity.path("rules").get(0).path("value").asText()).isEqualTo("abc");
    assertThat(entity.path("rules").get(0).has("id")).isFalse();
    assertThat(last().uri()).isEqualTo("/api/streams/" + id + "/resume");
    assertThat(last().header("X-Requested-By")).isEqualTo("grow-codes-graylog");

    server.enqueue(201, "{\"stream_id\":\"s2\"}");
    assertThat(
            client
                .createStreamAsync(
                    CreateStreamOptions.builder("t")
                        .indexSetId("is1")
                        .start(false)
                        .matchingType(null)
                        .description(null)
                        .build())
                .get())
        .isEqualTo("s2");
    assertThat(json(last()).path("entity").path("index_set_id").asText()).isEqualTo("is1");

    server.enqueue(200, "{\"index_sets\":[{\"id\":\"first\",\"default\":false}]}");
    server.enqueue(201, "{}");
    assertThatThrownBy(() -> client.createStream(CreateStreamOptions.builder("t").build()))
        .isInstanceOf(UnavailableException.class);
    assertThat(json(last()).path("entity").path("index_set_id").asText()).isEqualTo("first");
    server.enqueue(200, "{\"index_sets\":[]}");
    assertThatThrownBy(() -> client.createStream(CreateStreamOptions.builder("t").build()))
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("no index set");
    Fixtures.enqueue(server, "createStream.missing_index_set");
    assertThatThrownBy(
            () -> client.createStream(CreateStreamOptions.builder("t").indexSetId("x").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.createStream(CreateStreamOptions.builder(" ").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.createStream(null)).isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () -> client.createStream(CreateStreamOptions.builder("t").matchingType("XOR").build()))
        .isInstanceOf(ValidationException.class);

    server.enqueue(204, "");
    client.resumeStream("s2");
    assertThatThrownBy(() -> client.resumeStream("")).isInstanceOf(ValidationException.class);
    Fixtures.enqueue(server, "deleteStream.deleted");
    client.deleteStream("s2");
    Fixtures.enqueue(server, "deleteStream.not_found");
    assertThatThrownBy(() -> client.deleteStream("s2")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.deleteStream(null)).isInstanceOf(ValidationException.class);

    Fixtures.enqueue(server, "listIndexSets.ok");
    List<IndexSet> sets = client.listIndexSets();
    assertThat(last().uri()).isEqualTo("/api/system/indices/index_sets?skip_stats=true");
    assertThat(sets).anyMatch(IndexSet::isDefault);
    IndexSet def = sets.stream().filter(IndexSet::isDefault).findFirst().get();
    assertThat(def.indexPrefix()).isNotEmpty();
    assertThat(def.shards()).isPositive();
    assertThat(def.writable()).isTrue();
  }

  @Test
  void searchRequestBody() throws Exception {
    Fixtures.enqueue(server, "search.empty");
    MessageSearchResult empty = client.search("");
    assertThat(empty.messages()).isEmpty();
    assertThat(empty.nextOffset()).isEmpty();
    MockServer.Recorded r = last();
    assertThat(r.uri()).isEqualTo("/api/views/search/sync");
    assertThat(r.header("X-Requested-By")).isEqualTo("grow-codes-graylog");
    JsonNode q = json(r).path("queries").get(0);
    assertThat(q.path("query").path("query_string").asText()).isEqualTo("*");
    assertThat(q.path("timerange").path("type").asText()).isEqualTo("relative");
    assertThat(q.path("timerange").path("range").asLong()).isEqualTo(300);
    JsonNode st = q.path("search_types").get(0);
    assertThat(st.path("limit").asInt()).isEqualTo(100);
    assertThat(st.path("sort").get(0).path("field").asText()).isEqualTo("timestamp");
    assertThat(st.path("sort").get(0).path("order").asText()).isEqualTo("DESC");
    assertThat(st.has("fields")).isFalse();
    assertThat(q.has("filter")).isFalse();

    Instant from = Instant.parse("2026-11-18T20:23:00.123456Z");
    Fixtures.enqueue(server, "search.absolute_sorted_fields");
    MessageSearchResult res =
        client.search(
            "marker:abc",
            MessageSearchOptions.builder()
                .start(from)
                .end(from.plusSeconds(60))
                .limit(10)
                .offset(0)
                .fields("message", "seq")
                .sort(SearchSort.asc("seq"), new SearchSort("timestamp", null))
                .streams("s1", "s2")
                .build());
    q = json(last()).path("queries").get(0);
    assertThat(q.path("timerange").path("from").asText()).isEqualTo("2026-11-18T20:23:00.123Z");
    assertThat(q.path("timerange").path("to").asText()).isEqualTo("2026-11-18T20:24:00.123Z");
    assertThat(q.path("filter").path("filters").get(1).path("id").asText()).isEqualTo("s2");
    st = q.path("search_types").get(0);
    assertThat(st.path("fields").size()).isEqualTo(2);
    assertThat(st.path("sort").get(0).path("order").asText()).isEqualTo("ASC");
    assertThat(st.path("sort").get(1).path("order").asText()).isEqualTo("DESC");
    assertThat(res.messages()).isNotEmpty();
    GraylogMessage m = res.messages().get(0);
    assertThat(m.id()).isNotEmpty();
    assertThat(m.index()).isNotEmpty();
    assertThat(res.from()).isPresent();
    assertThat(res.records()).hasSameSizeAs(res.messages());

    Fixtures.enqueue(server, "search.desc_limit_offset");
    MessageSearchResult paged =
        client.search("x", MessageSearchOptions.builder().limit(1).offset(1).build());
    assertThat(paged.messages()).hasSize(1);
    assertThat(paged.nextOffset()).hasValue(2);

    Fixtures.enqueue(server, "search.keyword_range");
    client.search("x", MessageSearchOptions.builder().keyword("last five minutes").build());
    q = json(last()).path("queries").get(0);
    assertThat(q.path("timerange").path("keyword").asText()).isEqualTo("last five minutes");

    Fixtures.enqueue(server, "searchRelative.ok");
    client.searchRelative("x", Duration.ofMillis(1500));
    q = json(last()).path("queries").get(0);
    assertThat(q.path("timerange").path("range").asLong()).isEqualTo(2);

    server.enqueue(200, "{\"results\":{}}");
    client.search("x", MessageSearchOptions.builder().end(from).build());
    q = json(last()).path("queries").get(0);
    assertThat(q.path("timerange").path("from").asText()).isEqualTo("2026-11-18T20:18:00.123Z");
    server.enqueue(200, "{\"results\":{}}");
    client
        .searchAsync(
            "x", MessageSearchOptions.builder().start(Instant.now().minusSeconds(5)).build())
        .get();
    server.enqueue(200, "{\"results\":{}}");
    client.searchRelativeAsync("x", Duration.ofSeconds(5), null).get();
    server.enqueue(200, "{\"results\":{}}");
    assertThat(client.search("x", null).total()).isZero();
  }

  @Test
  void searchValidationAndErrors() {
    MessageSearchOptions.Builder b = MessageSearchOptions.builder();
    assertThatThrownBy(() -> client.search("x", b.limit(0).build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () -> client.search("x", MessageSearchOptions.builder().limit(10001).build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.search("x", MessageSearchOptions.builder().offset(-1).build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () ->
                client.search(
                    "x", MessageSearchOptions.builder().sort(SearchSort.asc(" ")).build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () ->
                client.search(
                    "x",
                    MessageSearchOptions.builder()
                        .range(Duration.ofSeconds(1))
                        .keyword("k")
                        .build()))
        .hasMessageContaining("only one of");
    assertThatThrownBy(
            () ->
                client.search(
                    "x",
                    MessageSearchOptions.builder()
                        .start(Instant.now())
                        .end(Instant.now().minusSeconds(10))
                        .build()))
        .hasMessageContaining("start is after end");
    assertThatThrownBy(
            () -> client.search("x", MessageSearchOptions.builder().keyword(" ").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () ->
                client.search(
                    "x", MessageSearchOptions.builder().range(Duration.ofSeconds(-1)).build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.searchRelative("x", Duration.ZERO))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.searchRelative("x", null, null))
        .isInstanceOf(ValidationException.class);

    Fixtures.enqueue(server, "search.invalid_query");
    assertThatThrownBy(() -> client.search("marker:(("))
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("search_phase_execution_exception");
    server.enqueue(200, "{\"execution\":{\"completed_exceptionally\":true},\"results\":{}}");
    assertThatThrownBy(() -> client.search("x")).hasMessageContaining("query failed");
    server.enqueue(200, "{\"errors\":[{\"description\":\"\"},{\"description\":\"top level\"}]}");
    assertThatThrownBy(() -> client.search("x")).hasMessageContaining("top level");
    Fixtures.enqueue(server, "search.bad_request");
    assertThatThrownBy(() -> client.search("x")).isInstanceOf(ValidationException.class);
    Fixtures.enqueue(server, "search.unauthorized");
    assertThatThrownBy(() -> client.search("x")).isInstanceOf(AuthenticationException.class);
  }

  @Test
  void messagesAndFields() throws Exception {
    Fixtures.enqueue(server, "getMessage.ok");
    GraylogMessage m = client.getMessage("graylog_0", "99c65855-e38e-11f1-8dde-020650dd320d");
    assertThat(last().uri())
        .isEqualTo("/api/messages/graylog_0/99c65855-e38e-11f1-8dde-020650dd320d");
    assertThat(m.id()).isEqualTo("99c65855-e38e-11f1-8dde-020650dd320d");
    assertThat(m.index()).isEqualTo("graylog_0");
    assertThat(m.timestamp()).isPresent();
    assertThat(m.fields()).containsEntry("seq", 0L);
    assertThat(m.toLogRecord().resource()).containsEntry("host.name", "grow-sdk-verify");

    server.enqueue(
        200, "{\"message\":{\"id\":\"mid\",\"fields\":{\"message\":\"x\"}},\"index\":\"i\"}");
    assertThat(client.getMessageAsync("i", "a b").get().id()).isEqualTo("mid");
    assertThat(last().uri()).isEqualTo("/api/messages/i/a%20b");
    Fixtures.enqueue(server, "getMessage.not_found");
    assertThatThrownBy(() -> client.getMessage("graylog_0", "nope"))
        .isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.getMessage("", "x")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.getMessage("i", null)).isInstanceOf(ValidationException.class);

    Fixtures.enqueue(server, "listLabels.ok");
    List<String> fields = client.listFields();
    assertThat(fields).contains("message", "source").isSorted();
  }

  @Test
  void transportsAndLogClients() throws Exception {
    GraylogClient c =
        GraylogClient.builder()
            .url("http://graylog.example:9000")
            .gelfPort(12345)
            .gelfHttpUrl("http://graylog.example:12202/gelf")
            .build();
    try (GelfTransport udp = c.gelfTransport(GelfProtocol.UDP);
        GelfTransport tcp = c.gelfTransport(null);
        GelfTransport http =
            c.gelfTransport(
                GelfProtocol.HTTP,
                GelfTransportOptions.builder().bulk(false).header("X-A", "b").build())) {
      assertThat(udp).isInstanceOf(GelfUdpTransport.class);
      assertThat(udp.toString()).contains("graylog.example:12345");
      assertThat(tcp).isInstanceOf(GelfTcpTransport.class);
      assertThat(((GelfTcpTransport) tcp).secure()).isFalse();
      assertThat(http).isInstanceOf(GelfHttpTransport.class);
      assertThat(((GelfHttpTransport) http).url()).isEqualTo("http://graylog.example:12202/gelf");
    }
    assertThatThrownBy(() -> c.gelfTransport(GelfProtocol.OTLP, null))
        .isInstanceOf(ValidationException.class);

    BatchingLogClient gelf = c.logClient();
    BatchingLogClient otlp =
        c.logClient(
            GraylogLogClientOptions.builder()
                .protocol(GelfProtocol.OTLP)
                .bearerToken(Secret.of("bearer-1"))
                .header("x-tenant", "t")
                .build());
    BatchingLogClient custom =
        c.logClient(
            GraylogLogClientOptions.builder()
                .transport(GelfUdpTransport.builder("127.0.0.1").build())
                .host("h")
                .resource(Map.of("service.name", "svc"))
                .build());
    assertThat(custom.resource()).containsEntry("service.name", "svc");
    assertThat(c.logQueryClient(null).options().defaultWindow()).isEqualTo(Duration.ofHours(1));
    assertThat(c.logQueryClient().options().streams()).isEmpty();
    c.close();
    c.close();
    assertThat(c.isClosed()).isTrue();
    // registering after close closes immediately
    AutoCloseable[] closedFlag = {null};
    c.register(() -> closedFlag[0] = () -> {});
    assertThat(closedFlag[0]).isNotNull();
    assertThat(gelf).isNotNull();
    assertThat(otlp).isNotNull();
    assertThatThrownBy(
            () ->
                c.logClientWithExporter(
                    new GelfLogExporter(GelfUdpTransport.builder("h").build(), null),
                    GraylogLogClientOptions.builder()
                        .batchOptions(
                            codes.grow.packages.graylog.logging.BatchOptions.builder()
                                .maxQueueSize(-1)
                                .build())
                        .build()))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void builderAndToString() {
    GraylogClient c =
        GraylogClient.builder()
            .url("https://graylog.example")
            .apiToken(Secret.of("tok-secret-xyz"))
            .gelfHost("gelf.example")
            .gelfProtocol(GelfProtocol.UDP)
            .gelfTls(true)
            .otlpEndpoint("https://otel.example:4317")
            .connectTimeout(Duration.ofSeconds(1))
            .requestTimeout(Duration.ofSeconds(2))
            .totalTimeout(Duration.ofSeconds(3))
            .retry(RetryPolicy.none())
            .tls(TlsOptions.defaults())
            .proxy("http://proxy.example:3128")
            .header("X-Extra", "1")
            .userAgentSuffix("it")
            .hooks(Hooks.NONE)
            .logger(Logger.NOOP)
            .build();
    assertThat(c.toString()).doesNotContain("tok-secret-xyz").contains("gelf.example");
    assertThat(c.config().gelfProtocol()).isEqualTo(GelfProtocol.UDP);
    assertThat(c.transport()).isNotNull();
    assertThatThrownBy(() -> GraylogClient.builder().url("ftp://x").build())
        .isInstanceOf(ConfigException.class);
    c.close();
  }

  @Test
  void segmentEncoding() {
    assertThat(GraylogClient.segment("op", "id", "a/b c")).isEqualTo("a%2Fb%20c");
  }
}
