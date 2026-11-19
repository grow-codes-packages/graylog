package codes.grow.packages.graylog;

/**
 * Result of {@link GraylogClient#ensureGelfInput(GelfProtocol, int, EnsureGelfInputOptions)}.
 *
 * @param input the running input
 * @param created whether this call created it
 */
public record EnsuredInput(GraylogInput input, boolean created) {
  /**
   * Returns the input id.
   *
   * @return the id
   */
  public String id() {
    return input.id();
  }
}
