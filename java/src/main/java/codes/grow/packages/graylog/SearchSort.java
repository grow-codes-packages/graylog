package codes.grow.packages.graylog;

import codes.grow.packages.graylog.logging.SortOrder;

/**
 * One sort key of {@link GraylogClient#search(String, MessageSearchOptions)}.
 *
 * @param field field to sort by
 * @param order order (default descending)
 */
public record SearchSort(String field, SortOrder order) {
  /** Defaults the order to descending. */
  public SearchSort {
    order = order == null ? SortOrder.DESC : order;
  }

  /**
   * Ascending sort on {@code field}.
   *
   * @param field field
   * @return the sort key
   */
  public static SearchSort asc(String field) {
    return new SearchSort(field, SortOrder.ASC);
  }

  /**
   * Descending sort on {@code field}.
   *
   * @param field field
   * @return the sort key
   */
  public static SearchSort desc(String field) {
    return new SearchSort(field, SortOrder.DESC);
  }
}
