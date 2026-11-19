package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Json;
import codes.grow.packages.graylog.core.MockServer;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;

/** Recorded responses of the real Graylog 7.0 container (prep fixtures). */
final class Fixtures {
  private Fixtures() {}

  static JsonNode load(String name) {
    try (InputStream in =
        Fixtures.class.getResourceAsStream(
            "/codes/grow/packages/graylog/fixtures/" + name + ".json")) {
      if (in == null) {
        throw new IllegalArgumentException("no fixture " + name);
      }
      return Json.tree(in.readAllBytes());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static JsonNode body(String name) {
    return load(name).path("response").path("body");
  }

  static String bodyText(String name) {
    JsonNode b = body(name);
    if (b.isMissingNode() || b.isNull()) {
      return "";
    }
    return b.isTextual() ? b.asText() : Json.stringify(b);
  }

  /** Queues the recorded response (status, headers, body) on the mock server. */
  static void enqueue(MockServer server, String name) {
    JsonNode resp = load(name).path("response");
    int status = resp.path("status").asInt();
    String body = bodyText(name);
    server.enqueue(
        ex -> {
          for (Map.Entry<String, JsonNode> h : resp.path("headers").properties()) {
            if (!h.getKey().equalsIgnoreCase("content-length")) {
              ex.getResponseHeaders().add(h.getKey(), h.getValue().asText());
            }
          }
          MockServer.send(ex, status, body);
        });
  }
}
