package codes.grow.packages.graylog;

import java.util.Locale;
import java.util.Optional;

/**
 * Ingest protocol of a Graylog log client.
 *
 * <p>{@link #UDP}, {@link #TCP} and {@link #HTTP} are GELF transports and valid in {@link
 * GraylogConfig#gelfProtocol()}; {@link #OTLP} selects the OpenTelemetry (gRPC) exporter and is
 * only valid in {@link GraylogLogClientOptions#protocol()}.
 */
public enum GelfProtocol {
  /** One (possibly chunked and compressed) datagram per message; delivery is best-effort. */
  UDP("udp"),
  /** NUL-terminated JSON frames over one long-lived connection (the default). */
  TCP("tcp"),
  /** Messages posted to the GELF HTTP input (newline-terminated bulk bodies, gzip). */
  HTTP("http"),
  /** OTLP/gRPC to the Graylog OpenTelemetry input (not a GELF transport). */
  OTLP("otlp");

  private final String wire;

  GelfProtocol(String wire) {
    this.wire = wire;
  }

  /**
   * Returns the lower-case name ({@code udp}, {@code tcp}, {@code http}, {@code otlp}).
   *
   * @return the wire value
   */
  public String wireValue() {
    return wire;
  }

  /**
   * Returns whether this is a GELF transport (UDP, TCP or HTTP).
   *
   * @return true for UDP, TCP and HTTP
   */
  public boolean isGelf() {
    return this != OTLP;
  }

  /**
   * Parses a GELF protocol name ({@code udp}, {@code tcp}, {@code http}; case-insensitive).
   *
   * @param text the name
   * @return the protocol, or empty for anything else (including {@code otlp})
   */
  public static Optional<GelfProtocol> parseGelf(String text) {
    if (text == null) {
      return Optional.empty();
    }
    switch (text.trim().toLowerCase(Locale.ROOT)) {
      case "udp":
        return Optional.of(UDP);
      case "tcp":
        return Optional.of(TCP);
      case "http":
        return Optional.of(HTTP);
      default:
        return Optional.empty();
    }
  }

  @Override
  public String toString() {
    return wire;
  }
}
