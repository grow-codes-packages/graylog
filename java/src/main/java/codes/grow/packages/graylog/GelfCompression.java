package codes.grow.packages.graylog;

/** Payload compression of the GELF UDP transport (applied before chunking). */
public enum GelfCompression {
  /** gzip (magic {@code 1f 8b}), the default. */
  GZIP,
  /** zlib (magic {@code 78 ..}). */
  ZLIB,
  /** Plain JSON. */
  NONE
}
