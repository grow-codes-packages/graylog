package codes.grow.packages.graylog.integration;

import codes.grow.packages.graylog.GraylogClient;
import codes.grow.packages.graylog.GraylogLogClientOptions;
import codes.grow.packages.graylog.core.EnvReader;
import codes.grow.packages.graylog.logging.BatchOptions;
import codes.grow.packages.graylog.logging.BatchingLogClient;
import codes.grow.packages.graylog.testing.ConformanceRunner;
import codes.grow.packages.graylog.testing.logging.LoggingTarget;
import java.util.Map;

/**
 * Conformance targets of this service (owned by the service repository).
 *
 * <p>{@code core} is the client; {@code logging} is a batching {@code LogClient} over the
 * configured GELF protocol (TCP from the bootstrap) plus the Graylog {@code LogQueryClient}.
 * Graylog serves search (Views API), a polling tail, streams, field names (labels) and the server
 * version.
 */
final class Factories {
  /** Capabilities the deployment under test offers (see the scenario {@code requires}). */
  static final String[] CAPABILITIES = {"version", "query", "tail", "labels", "streams"};

  /** Service name used as the {@code service.name} resource of conformance records. */
  static final String SERVICE_NAME = "grow-conformance-java";

  private Factories() {}

  static void register(ConformanceRunner.Builder runner, EnvReader env) {
    runner.serviceName(SERVICE_NAME);
    runner.target("core", scenario -> GraylogClient.builder().fromEnv(env).build());
    runner.target(
        "logging",
        scenario -> {
          GraylogClient client = GraylogClient.builder().fromEnv(env).build();
          BatchingLogClient logs =
              client.logClient(
                  GraylogLogClientOptions.builder()
                      .batchOptions(LoggingTarget.batchOptions(scenario, BatchOptions.defaults()))
                      .resource(
                          Map.of(
                              "service.name", SERVICE_NAME,
                              "deployment.environment", "conformance"))
                      .build());
          return LoggingTarget.of(logs, client.logQueryClient());
        });
  }
}
