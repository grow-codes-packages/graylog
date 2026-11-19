package codes.grow.packages.graylog;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Options of {@link GraylogClient#ensureGelfInput(GelfProtocol, int, EnsureGelfInputOptions)}. */
public final class EnsureGelfInputOptions {
  private final String title;
  private final String bindAddress;
  private final Map<String, Object> configuration;
  private final Duration timeout;
  private final Duration interval;

  private EnsureGelfInputOptions(Builder b) {
    this.title = b.title;
    this.bindAddress = b.bindAddress;
    this.configuration = Map.copyOf(b.configuration);
    this.timeout = b.timeout;
    this.interval = b.interval;
  }

  /**
   * Returns the defaults.
   *
   * @return default options
   */
  public static EnsureGelfInputOptions defaults() {
    return builder().build();
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the title of a new input (empty = {@code "grow-codes GELF <PROTOCOL> <port>"}).
   *
   * @return the title
   */
  public Optional<String> title() {
    return Optional.ofNullable(title);
  }

  /**
   * Returns the bind address (default {@code 0.0.0.0}).
   *
   * @return the bind address
   */
  public String bindAddress() {
    return bindAddress;
  }

  /**
   * Returns the configuration merged over the defaults of a new input.
   *
   * @return immutable map
   */
  public Map<String, Object> configuration() {
    return configuration;
  }

  /**
   * Returns how long to wait for the RUNNING state (default 30 s).
   *
   * @return the timeout
   */
  public Duration timeout() {
    return timeout;
  }

  /**
   * Returns the state poll interval (default 500 ms).
   *
   * @return the interval
   */
  public Duration interval() {
    return interval;
  }

  /** Builder of {@link EnsureGelfInputOptions}. */
  public static final class Builder {
    private String title;
    private String bindAddress = "0.0.0.0";
    private final Map<String, Object> configuration = new LinkedHashMap<>();
    private Duration timeout = Duration.ofSeconds(30);
    private Duration interval = Duration.ofMillis(500);

    private Builder() {}

    /**
     * Sets the title of a newly created input.
     *
     * @param title title
     * @return this builder
     */
    public Builder title(String title) {
      this.title = title;
      return this;
    }

    /**
     * Sets the bind address; an existing input matches when its bind address equals it.
     *
     * @param bindAddress address
     * @return this builder
     */
    public Builder bindAddress(String bindAddress) {
      this.bindAddress = bindAddress == null ? "0.0.0.0" : bindAddress;
      return this;
    }

    /**
     * Adds a configuration value merged over the defaults of a new input (e.g. {@code tls_enable}).
     *
     * @param key configuration key
     * @param value value
     * @return this builder
     */
    public Builder configuration(String key, Object value) {
      this.configuration.put(key, value);
      return this;
    }

    /**
     * Sets how long to wait for the RUNNING state.
     *
     * @param timeout positive duration
     * @return this builder
     */
    public Builder timeout(Duration timeout) {
      this.timeout = timeout == null ? Duration.ofSeconds(30) : timeout;
      return this;
    }

    /**
     * Sets the state poll interval.
     *
     * @param interval positive duration
     * @return this builder
     */
    public Builder interval(Duration interval) {
      this.interval = interval == null ? Duration.ofMillis(500) : interval;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public EnsureGelfInputOptions build() {
      return new EnsureGelfInputOptions(this);
    }
  }
}
