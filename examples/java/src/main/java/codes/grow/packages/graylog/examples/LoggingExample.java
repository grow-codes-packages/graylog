// Created by sdk-kit 0.1.0; owned by this repository.
package codes.grow.packages.graylog.examples;

import codes.grow.packages.graylog.GelfMessage;
import codes.grow.packages.graylog.GelfProtocol;
import codes.grow.packages.graylog.GelfTransport;
import codes.grow.packages.graylog.GraylogClient;
import codes.grow.packages.graylog.GraylogLogClientOptions;
import codes.grow.packages.graylog.GraylogLogQueryClient;
import codes.grow.packages.graylog.MessageSearchResult;
import codes.grow.packages.graylog.logging.BatchingLogClient;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.SearchOptions;
import codes.grow.packages.graylog.logging.WaitForLogOptions;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Sends logs through GELF, reads them back through the Views search API and lists the admin
 * objects (inputs, streams, index sets).
 */
public final class LoggingExample {
  private LoggingExample() {}

  /**
   * Runs the example.
   *
   * @param args unused
   */
  public static void main(String[] args) {
    String marker = "example-" + UUID.randomUUID().toString().substring(0, 8);
    try (var client = GraylogClient.fromEnv()) {
      // A batching log client over the configured GELF protocol (default TCP 12201).
      BatchingLogClient logs =
          client.logClient(
              GraylogLogClientOptions.builder()
                  .resource(Map.of("service.name", "logging-example"))
                  .build());
      logs.logger("example", Map.of("marker", marker)).info("hello from Java", Map.of("user", "u-1"));
      logs.flush(Duration.ofSeconds(10));

      // Read the record back (searchable after 1–2 s).
      GraylogLogQueryClient query = client.logQueryClient();
      LogRecord found =
          query.waitForLog(
              "marker:" + marker,
              new WaitForLogOptions(
                  Duration.ofSeconds(30),
                  Duration.ofSeconds(1),
                  null,
                  SearchOptions.builder().start(Instant.now().minusSeconds(300)).build()));
      System.out.println("found: " + found.body() + " " + found.attributes());

      // Raw GELF message through an explicit transport.
      try (GelfTransport tcp = client.gelfTransport(GelfProtocol.TCP)) {
        tcp.send(List.of(GelfMessage.builder("example-host", marker + " raw").field("marker", marker).build()));
      }

      // Search, admin.
      MessageSearchResult page = client.searchRelative("marker:" + marker, Duration.ofMinutes(5));
      System.out.println("matches so far: " + page.total());
      System.out.println("inputs: " + client.listInputs().size());
      System.out.println("streams: " + query.listStreams());
      System.out.println("index sets: " + client.listIndexSets().size());
    }
  }
}
