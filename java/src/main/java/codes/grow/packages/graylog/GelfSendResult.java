package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.GraylogException;
import java.util.Optional;

/**
 * Outcome of {@link GelfTransport#send(java.util.List, GelfSendOptions)}.
 *
 * @param sent messages handed to the network
 * @param rejected messages rejected client-side (for example too large for UDP)
 * @param error why messages were rejected
 */
public record GelfSendResult(int sent, int rejected, Optional<GraylogException> error) {
  /** Normalises {@code null} to empty. */
  public GelfSendResult {
    error = error == null ? Optional.empty() : error;
  }

  /**
   * Returns a result where every message was sent.
   *
   * @param sent number of messages
   * @return the result
   */
  public static GelfSendResult ofSent(int sent) {
    return new GelfSendResult(sent, 0, Optional.empty());
  }
}
