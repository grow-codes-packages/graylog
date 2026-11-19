package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.ValidationException;

/** Graylog input type classes used by the admin helpers. */
public final class InputTypes {
  /** GELF UDP input. */
  public static final String GELF_UDP = "org.graylog2.inputs.gelf.udp.GELFUDPInput";

  /** GELF TCP input. */
  public static final String GELF_TCP = "org.graylog2.inputs.gelf.tcp.GELFTCPInput";

  /** GELF HTTP input. */
  public static final String GELF_HTTP = "org.graylog2.inputs.gelf.http.GELFHttpInput";

  /** OpenTelemetry (gRPC) input. */
  public static final String OTEL_GRPC = "org.graylog.inputs.otel.OTelGrpcInput";

  /** Input state of a running input. */
  public static final String STATE_RUNNING = "RUNNING";

  /** Input state of an input that failed to start. */
  public static final String STATE_FAILED = "FAILED";

  private InputTypes() {}

  /**
   * Returns the GELF input class of a protocol.
   *
   * @param protocol UDP, TCP or HTTP
   * @return the class name
   * @throws ValidationException for OTLP or {@code null}
   */
  public static String gelf(GelfProtocol protocol) {
    if (protocol == GelfProtocol.UDP) {
      return GELF_UDP;
    }
    if (protocol == GelfProtocol.TCP) {
      return GELF_TCP;
    }
    if (protocol == GelfProtocol.HTTP) {
      return GELF_HTTP;
    }
    throw new ValidationException("ensureGelfInput: protocol must be udp, tcp or http");
  }
}
