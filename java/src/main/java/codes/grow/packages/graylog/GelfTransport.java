package codes.grow.packages.graylog;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Sends GELF messages to a Graylog input. Implementations are thread-safe.
 *
 * <p>Implementations: {@link GelfUdpTransport}, {@link GelfTcpTransport}, {@link
 * GelfHttpTransport}.
 */
public interface GelfTransport extends AutoCloseable {
  /**
   * Returns the protocol (UDP, TCP or HTTP).
   *
   * @return the protocol
   */
  GelfProtocol protocol();

  /**
   * Delivers messages in order. Network failures throw ({@code UnavailableException}, {@code
   * TimeoutException}, {@code CancelledException}); client-side rejections are counted in the
   * result. A closed transport throws {@code ConfigException}.
   *
   * @param messages messages to send
   * @param options per-call options
   * @return the result
   */
  GelfSendResult send(List<GelfMessage> messages, GelfSendOptions options);

  /**
   * Sends with default options.
   *
   * @param messages messages to send
   * @return the result
   */
  default GelfSendResult send(List<GelfMessage> messages) {
    return send(messages, GelfSendOptions.defaults());
  }

  /**
   * Asynchronous {@link #send(List, GelfSendOptions)}.
   *
   * @param messages messages to send
   * @param options per-call options
   * @return a future with the result
   */
  default CompletableFuture<GelfSendResult> sendAsync(
      List<GelfMessage> messages, GelfSendOptions options) {
    return CompletableFuture.supplyAsync(() -> send(messages, options), GelfIo.EXECUTOR);
  }

  /** Releases sockets. Idempotent. */
  @Override
  void close();
}
