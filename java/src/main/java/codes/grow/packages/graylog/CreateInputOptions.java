package codes.grow.packages.graylog;

import java.util.Optional;

/**
 * Options of {@link GraylogClient#createInput(String, java.util.Map, CreateInputOptions)}.
 *
 * @param title title (empty = {@code "<class short name> (grow-codes)"})
 * @param node node id of a node-local input (empty = a global input)
 */
public record CreateInputOptions(Optional<String> title, Optional<String> node) {
  /** Normalises {@code null} to empty. */
  public CreateInputOptions {
    title = title == null ? Optional.empty() : title;
    node = node == null ? Optional.empty() : node;
  }

  /**
   * Returns the defaults (generated title, global).
   *
   * @return default options
   */
  public static CreateInputOptions defaults() {
    return new CreateInputOptions(Optional.empty(), Optional.empty());
  }

  /**
   * Returns options with a title.
   *
   * @param title title
   * @return the options
   */
  public static CreateInputOptions titled(String title) {
    return new CreateInputOptions(Optional.ofNullable(title), Optional.empty());
  }

  /**
   * Returns a copy that starts the input on one node only.
   *
   * @param node node id
   * @return the options
   */
  public CreateInputOptions withNode(String node) {
    return new CreateInputOptions(title, Optional.ofNullable(node));
  }
}
