package codes.grow.packages.graylog.core;

import java.nio.file.Path;
import javax.net.ssl.SSLContext;

/** Exposes the generated test certificates to the service tests in other packages. */
public final class CertsBridge {
  /**
   * A server TLS context and the PEM of its self-signed certificate.
   *
   * @param server server context
   * @param certPem certificate (CN=localhost, SAN 127.0.0.1)
   */
  public record Server(SSLContext server, String certPem) {}

  private CertsBridge() {}

  /**
   * Generates a self-signed server certificate.
   *
   * @param dir temporary directory
   * @return the server context and certificate
   * @throws Exception when keytool fails
   */
  public static Server server(Path dir) throws Exception {
    TestCerts c = TestCerts.generate(dir, "server", "EC");
    return new Server(c.serverContext(null), c.certPem);
  }
}
