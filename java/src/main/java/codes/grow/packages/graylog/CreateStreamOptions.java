package codes.grow.packages.graylog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Options of {@link GraylogClient#createStream(CreateStreamOptions)}; {@code title} is required.
 */
public final class CreateStreamOptions {
  private final String title;
  private final String description;
  private final String indexSetId;
  private final List<StreamRule> rules;
  private final String matchingType;
  private final boolean removeMatchesFromDefaultStream;
  private final boolean start;

  private CreateStreamOptions(Builder b) {
    this.title = b.title;
    this.description = b.description;
    this.indexSetId = b.indexSetId;
    this.rules = List.copyOf(b.rules);
    this.matchingType = b.matchingType;
    this.removeMatchesFromDefaultStream = b.removeMatchesFromDefaultStream;
    this.start = b.start;
  }

  /**
   * Starts a builder.
   *
   * @param title stream title
   * @return a new builder
   */
  public static Builder builder(String title) {
    return new Builder(title);
  }

  /**
   * Returns the title.
   *
   * @return the title
   */
  public String title() {
    return title;
  }

  /**
   * Returns the description.
   *
   * @return the description
   */
  public String description() {
    return description;
  }

  /**
   * Returns the target index set (empty = the default index set, else the first one).
   *
   * @return the index set id
   */
  public Optional<String> indexSetId() {
    return Optional.ofNullable(indexSetId);
  }

  /**
   * Returns the rules.
   *
   * @return the rules
   */
  public List<StreamRule> rules() {
    return rules;
  }

  /**
   * Returns the matching type ({@code AND} or {@code OR}).
   *
   * @return the matching type
   */
  public String matchingType() {
    return matchingType;
  }

  /**
   * Returns whether matches leave the default stream.
   *
   * @return true when removed
   */
  public boolean removeMatchesFromDefaultStream() {
    return removeMatchesFromDefaultStream;
  }

  /**
   * Returns whether the new stream is resumed (Graylog creates streams paused).
   *
   * @return true to resume (default)
   */
  public boolean start() {
    return start;
  }

  /** Builder of {@link CreateStreamOptions}. */
  public static final class Builder {
    private final String title;
    private String description = "";
    private String indexSetId;
    private final List<StreamRule> rules = new ArrayList<>();
    private String matchingType = "AND";
    private boolean removeMatchesFromDefaultStream;
    private boolean start = true;

    private Builder(String title) {
      this.title = title;
    }

    /**
     * Sets the description.
     *
     * @param description text
     * @return this builder
     */
    public Builder description(String description) {
      this.description = description == null ? "" : description;
      return this;
    }

    /**
     * Sets the target index set.
     *
     * @param indexSetId index set id
     * @return this builder
     */
    public Builder indexSetId(String indexSetId) {
      this.indexSetId = indexSetId;
      return this;
    }

    /**
     * Sets the rules.
     *
     * @param rules rules
     * @return this builder
     */
    public Builder rules(StreamRule... rules) {
      this.rules.clear();
      this.rules.addAll(Arrays.asList(rules));
      return this;
    }

    /**
     * Sets the matching type: {@code AND} (default, all rules) or {@code OR}.
     *
     * @param matchingType matching type
     * @return this builder
     */
    public Builder matchingType(String matchingType) {
      this.matchingType = matchingType == null ? "AND" : matchingType;
      return this;
    }

    /**
     * Removes matches from the default stream.
     *
     * @param remove true to remove
     * @return this builder
     */
    public Builder removeMatchesFromDefaultStream(boolean remove) {
      this.removeMatchesFromDefaultStream = remove;
      return this;
    }

    /**
     * Resumes the new stream (default true; Graylog creates streams paused).
     *
     * @param start false to keep it paused
     * @return this builder
     */
    public Builder start(boolean start) {
      this.start = start;
      return this;
    }

    /**
     * Builds the options (validated by the create call).
     *
     * @return the options
     */
    public CreateStreamOptions build() {
      return new CreateStreamOptions(this);
    }
  }
}
