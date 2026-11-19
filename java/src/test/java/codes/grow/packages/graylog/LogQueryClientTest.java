package codes.grow.packages.graylog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.MockServer;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.LogSearchResult;
import codes.grow.packages.graylog.logging.SearchOptions;
import codes.grow.packages.graylog.logging.SortOrder;
import codes.grow.packages.graylog.logging.TailHandle;
import codes.grow.packages.graylog.logging.TailOptions;
import codes.grow.packages.graylog.logging.WaitForLogOptions;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LogQueryClientTest {
  private MockServer server;
  private GraylogClient client;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = GraylogClientTest.client(server.url());
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  private JsonNode lastQuery() {
    List<MockServer.Recorded> r = server.requests();
    return Json.tree(r.get(r.size() - 1).body().getBytes(StandardCharsets.UTF_8))
        .path("queries")
        .get(0);
  }

  private static String hit(String id, String ts, String message) {
    return "{\"message\":{\"_id\":\""
        + id
        + "\",\"timestamp\":\""
        + ts
        + "\",\"message\":\""
        + message
        + "\",\"level\":4},\"index\":\"graylog_0\"}";
  }

  private static String page(long total, String... hits) {
    return "{\"execution\":{\"done\":true},\"results\":{\"q1\":{\"search_types\":{\"st1\":{\"total_results\":"
        + total
        + ",\"messages\":["
        + String.join(",", hits)
        + "]}}}}}";
  }

  @Test
  void searchMapsOptionsAndCursor() throws Exception {
    GraylogLogQueryClient q =
        client.logQueryClient(
            new GraylogLogQueryClientOptions(List.of("s1"), Duration.ofMinutes(10)));
    server.enqueue(
        200,
        page(
            3,
            hit("a", "2026-11-18T20:00:00.000Z", "one"),
            hit("b", "2026-11-18T20:00:01.000Z", "two")));
    Instant end = Instant.parse("2026-11-18T21:00:00Z");
    LogSearchResult res =
        q.search(
            "marker:x", SearchOptions.builder().end(end).limit(2).order(SortOrder.ASC).build());
    assertThat(res.records()).hasSize(2);
    assertThat(res.records().get(0).body()).isEqualTo("one");
    assertThat(res.nextCursor()).contains("2");
    assertThat(res.total()).hasValue(3);
    JsonNode query = lastQuery();
    assertThat(query.path("timerange").path("from").asText()).isEqualTo("2026-11-18T20:50:00.000Z");
    assertThat(query.path("timerange").path("to").asText()).isEqualTo("2026-11-18T21:00:00.000Z");
    assertThat(query.path("filter").path("filters").get(0).path("id").asText()).isEqualTo("s1");
    JsonNode sort = query.path("search_types").get(0).path("sort");
    assertThat(sort.get(0).path("field").asText()).isEqualTo("timestamp");
    assertThat(sort.get(1).path("field").asText()).isEqualTo("gl2_message_id");
    assertThat(sort.get(1).path("order").asText()).isEqualTo("ASC");

    server.enqueue(200, page(3, hit("c", "2026-11-18T20:00:02.000Z", "three")));
    LogSearchResult next =
        q.searchAsync("marker:x", SearchOptions.builder().cursor("2").limit(50000).build()).get();
    assertThat(next.nextCursor()).isEmpty();
    assertThat(lastQuery().path("search_types").get(0).path("offset").asInt()).isEqualTo(2);
    assertThat(lastQuery().path("search_types").get(0).path("limit").asInt()).isEqualTo(10000);

    assertThatThrownBy(() -> q.search("x", SearchOptions.builder().cursor("abc").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> q.search("x", SearchOptions.builder().cursor("-1").build()))
        .isInstanceOf(ValidationException.class);
    server.enqueue(200, page(0));
    assertThat(q.search("x", null).records()).isEmpty();
    assertThat(q.options().defaultWindow()).isEqualTo(Duration.ofMinutes(10));

    server.enqueue(200, page(1, hit("w", "2026-11-18T20:00:00.000Z", "found")));
    LogRecord found =
        q.waitForLog("x", WaitForLogOptions.of(Duration.ofSeconds(5), Duration.ofMillis(10)));
    assertThat(found.body()).isEqualTo("found");
  }

  @Test
  void streamsAndLabels() throws Exception {
    GraylogLogQueryClient q = client.logQueryClient();
    server.enqueue(
        200, "{\"pagination\":{\"total\":3},\"elements\":[{\"title\":\"b\"},{\"title\":\"c\"}]}");
    server.enqueue(200, "{\"pagination\":{\"total\":3},\"elements\":[{\"title\":\"a\"}]}");
    assertThat(q.listStreams()).containsExactly("a", "b", "c");
    assertThat(server.requests().get(1).uri()).contains("page=2", "per_page=100");
    server.enqueue(200, "{\"pagination\":{\"total\":9},\"elements\":[]}");
    assertThat(q.listStreamsAsync().get()).isEmpty();
    Fixtures.enqueue(server, "listLabels.ok");
    assertThat(q.listLabels()).contains("message");
    Fixtures.enqueue(server, "listLabels.ok");
    assertThat(q.listLabelsAsync().get()).contains("source");
  }

  @Test
  void tailPollsDedupesAndReportsErrors() throws Exception {
    AtomicInteger polls = new AtomicInteger();
    server.fallback(
        ex -> {
          List<MockServer.Recorded> r = server.requests();
          JsonNode st =
              Json.tree(r.get(r.size() - 1).body().getBytes(StandardCharsets.UTF_8))
                  .path("queries")
                  .get(0)
                  .path("search_types")
                  .get(0);
          int offset = st.path("offset").asInt();
          int n = polls.incrementAndGet();
          String now = Instant.now().toString();
          if (n == 1) {
            // first page of a two-page poll
            MockServer.send(ex, 200, page(3, hit("a", now, "one"), hit("b", now, "two")));
          } else if (n == 2) {
            assertThat(offset).isEqualTo(2);
            MockServer.send(ex, 200, page(3, hit("c", now, "three")));
          } else if (n == 3) {
            MockServer.send(
                ex,
                200,
                page(
                    4,
                    hit("a", now, "one"),
                    hit("b", now, "two"),
                    hit("c", now, "three"),
                    hit("d", now, "four")));
          } else if (n == 4) {
            MockServer.send(ex, 400, "{\"message\":\"bad\"}");
          } else {
            MockServer.send(ex, 200, page(0));
          }
        });
    GraylogLogQueryClient q = client.logQueryClient(GraylogLogQueryClientOptions.streams("s9"));
    List<String> got = new CopyOnWriteArrayList<>();
    List<Throwable> errors = new CopyOnWriteArrayList<>();
    TailHandle h =
        q.tail(
            "marker:x",
            r -> {
              got.add(r.body());
              if (r.body().equals("two")) {
                throw new IllegalStateException("callback failure is ignored");
              }
            },
            new TailOptions(
                    Optional.of(Instant.now().minusSeconds(60)), Duration.ofMillis(20), null)
                .withOnError(
                    e -> {
                      errors.add(e);
                      throw new IllegalStateException("ignored too");
                    }));
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while ((got.size() < 4 || errors.isEmpty()) && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    h.stop();
    h.close();
    assertThat(got).containsExactly("one", "two", "three", "four");
    assertThat(errors).hasSize(1).first().isInstanceOf(ValidationException.class);
    assertThat(lastQuery().path("filter").path("filters").get(0).path("id").asText())
        .isEqualTo("s9");
  }

  @Test
  void tailDefaultsAndClose() throws Exception {
    server.fallback(ex -> MockServer.send(ex, 200, page(0)));
    GraylogLogQueryClient q = client.logQueryClient();
    TailHandle h = q.tail("x", r -> {});
    TailHandle h2 = q.tail("x", r -> {}, new TailOptions(null, Duration.ZERO, null));
    TailHandle h3 = q.tail("x", r -> {}, null);
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (server.requests().size() < 3 && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    assertThat(server.requests()).hasSizeGreaterThanOrEqualTo(3);
    client.close(); // stops every tail
    h.stop();
    h2.stop();
    h3.stop();
    assertThatThrownBy(() -> q.tail("x", r -> {})).isInstanceOf(CancelledException.class);
    assertThatThrownBy(() -> q.tail("x", null, TailOptions.defaults()))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void tailStopFromCallbackThread() throws Exception {
    String now = Instant.now().toString();
    server.fallback(
        ex -> MockServer.send(ex, 200, page(2, hit("a", now, "one"), hit("b", now, "two"))));
    GraylogLogQueryClient q = client.logQueryClient();
    TailHandle[] handle = new TailHandle[1];
    List<String> got = new CopyOnWriteArrayList<>();
    handle[0] =
        q.tail(
            "x",
            r -> {
              got.add(r.body());
              while (handle[0] == null) {
                Thread.onSpinWait();
              }
              handle[0].stop(); // stopping from the tail thread must not deadlock
            },
            new TailOptions(
                Optional.of(Instant.now().minusSeconds(60)), Duration.ofMillis(10), null));
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (got.isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    Thread.sleep(50);
    assertThat(got).containsExactly("one");
  }
}
