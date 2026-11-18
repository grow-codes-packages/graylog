package codes.grow.packages.graylog.integration;

import codes.grow.packages.graylog.GraylogClient;
import codes.grow.packages.graylog.core.EnvReader;
import codes.grow.packages.graylog.testing.ConformanceRunner;

/**
 * Conformance targets of this service (owned by the service repository; generated once).
 *
 * <p>Register one target per category: {@code core} is the client; add {@code secrets}, {@code
 * logging} or {@code tracing} targets as the service implements them. Categories without a target
 * do not run. Every capability left out of {@link #CAPABILITIES} must be justified in {@code
 * docs/compatibility.md}.
 */
final class Factories {
  /** Capabilities the deployment under test offers (see the scenario {@code requires}). */
  static final String[] CAPABILITIES = {"version"};

  private Factories() {}

  static void register(ConformanceRunner.Builder runner, EnvReader env) {
    runner.target("core", scenario -> GraylogClient.builder().fromEnv(env).build());
  }
}
