package codes.grow.packages.graylog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.EnvReader;
import codes.grow.packages.graylog.core.Hooks;
import codes.grow.packages.graylog.core.Logger;
import codes.grow.packages.graylog.core.RetryPolicy;
import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.core.TlsOptions;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GraylogConfigTest {
  private static final String P = EnvReader.DEFAULT_PREFIX;

  @Test
  void defaults() {
    GraylogConfig c = GraylogConfig.builder().build();
    assertThat(c.url()).isEqualTo("http://127.0.0.1:9000");
    assertThat(c.apiToken()).isEmpty();
    assertThat(c.username()).isEmpty();
    assertThat(c.password()).isEmpty();
    assertThat(c.gelfHost()).isEqualTo("127.0.0.1");
    assertThat(c.gelfPort()).isEmpty();
    assertThat(c.gelfPortFor(GelfProtocol.TCP)).isEqualTo(12201);
    assertThat(c.gelfPortFor(GelfProtocol.UDP)).isEqualTo(12201);
    assertThat(c.gelfPortFor(GelfProtocol.HTTP)).isEqualTo(12202);
    assertThat(c.gelfProtocol()).isEqualTo(GelfProtocol.TCP);
    assertThat(c.gelfHttpUrl()).isEmpty();
    assertThat(c.gelfHttpEndpoint()).isEqualTo("http://127.0.0.1:12202/gelf");
    assertThat(c.gelfTls()).isFalse();
    assertThat(c.otlpEndpoint()).isEmpty();
    assertThat(c.otlpGrpcEndpoint()).isEqualTo("http://127.0.0.1:4317");
    assertThat(c.requestedBy()).isEqualTo("grow-codes-graylog");
    assertThat(c.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(c.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
    assertThat(c.totalTimeout()).isEqualTo(Duration.ofSeconds(120));
    assertThat(c.retry().maxRetries()).isEqualTo(RetryPolicy.DEFAULT_MAX_RETRIES);
    assertThat(c.tls()).isNotNull();
    assertThat(c.proxy()).isEmpty();
    assertThat(c.headers()).isEmpty();
    assertThat(c.userAgentSuffix()).isEmpty();
    assertThat(c.hooks()).isSameAs(Hooks.NONE);
    assertThat(c.logger()).isSameAs(Logger.NOOP);
    assertThat(c.basicCredentials()).isEmpty();
    assertThat(c.knownSecrets()).isEmpty();
    assertThat(c.toTransportConfig().baseUrl()).startsWith("http://127.0.0.1:9000");
  }

  @Test
  void envPrecedence() {
    Map<String, String> env = new HashMap<>();
    env.put("GRAYLOG_URL", "http://vendor:9000");
    env.put("GRAYLOG_API_TOKEN", "vendor-token");
    env.put("GRAYLOG_USER", "admin");
    env.put("GRAYLOG_PASSWORD", "vendor-pass");
    env.put("GRAYLOG_HOST", "platform-host");
    env.put("GRAYLOG_PORT", "1111");
    env.put("GRAYLOG_TRANSPORT", "udp");
    env.put("GRAYLOG_GELF_HTTP_URL", "http://vendor:12202/gelf");
    env.put("GRAYLOG_OTLP_GRPC_ENDPOINT", "http://vendor:4317");
    GraylogConfig c = GraylogConfig.fromEnv(env);
    assertThat(c.url()).isEqualTo("http://vendor:9000");
    assertThat(c.apiToken().get().reveal()).isEqualTo("vendor-token");
    assertThat(c.username()).contains("admin");
    assertThat(c.password().get().reveal()).isEqualTo("vendor-pass");
    assertThat(c.gelfHost()).isEqualTo("platform-host");
    assertThat(c.gelfPort()).hasValue(1111);
    assertThat(c.gelfPortFor(GelfProtocol.HTTP)).isEqualTo(1111);
    assertThat(c.gelfProtocol()).isEqualTo(GelfProtocol.UDP);
    assertThat(c.gelfHttpEndpoint()).isEqualTo("http://vendor:12202/gelf");
    assertThat(c.otlpGrpcEndpoint()).isEqualTo("http://vendor:4317");
    // the API token wins over username/password
    assertThat(c.basicCredentials())
        .contains(
            Base64.getEncoder()
                .encodeToString("vendor-token:token".getBytes(StandardCharsets.UTF_8)));
    assertThat(c.knownSecrets()).contains("vendor-token", "vendor-pass");

    env.put("GRAYLOG_GELF_HOST", "vendor-gelf");
    env.put("GRAYLOG_GELF_PORT", "2222");
    env.put("GRAYLOG_GELF_PROTOCOL", "HTTP");
    env.put(P + "URL", "https://sdk:9443");
    env.put(P + "API_TOKEN", "sdk-token");
    env.put(P + "GELF_HOST", "sdk-gelf");
    env.put(P + "GELF_PORT", "3333");
    env.put(P + "GELF_PROTOCOL", "tcp");
    env.put(P + "GELF_TLS", "true");
    env.put(P + "OTLP_ENDPOINT", "https://sdk:4317");
    env.put(P + "CONNECT_TIMEOUT", "2s");
    env.put(P + "REQUEST_TIMEOUT", "3s");
    env.put(P + "TOTAL_TIMEOUT", "4s");
    env.put(P + "MAX_RETRIES", "0");
    env.put(P + "PROXY", "http://proxy:3128");
    env.put(P + "INSECURE_SKIP_VERIFY", "true");
    c = GraylogConfig.fromEnv(env);
    assertThat(c.url()).isEqualTo("https://sdk:9443");
    assertThat(c.apiToken().get().reveal()).isEqualTo("sdk-token");
    assertThat(c.gelfHost()).isEqualTo("sdk-gelf");
    assertThat(c.gelfPort()).hasValue(3333);
    assertThat(c.gelfProtocol()).isEqualTo(GelfProtocol.TCP);
    assertThat(c.gelfTls()).isTrue();
    assertThat(c.otlpGrpcEndpoint()).isEqualTo("https://sdk:4317");
    assertThat(c.connectTimeout()).isEqualTo(Duration.ofSeconds(2));
    assertThat(c.requestTimeout()).isEqualTo(Duration.ofSeconds(3));
    assertThat(c.totalTimeout()).isEqualTo(Duration.ofSeconds(4));
    assertThat(c.retry().maxRetries()).isZero();
    assertThat(c.proxy()).contains("http://proxy:3128");
    assertThat(c.tls().insecureSkipVerify()).isTrue();

    // explicit builder values win over the environment
    GraylogConfig explicit =
        GraylogConfig.builder()
            .url("http://explicit:9000")
            .gelfPort(4444)
            .gelfProtocol(GelfProtocol.UDP)
            .gelfTls(false)
            .fromEnv(EnvReader.of(env))
            .build();
    assertThat(explicit.url()).isEqualTo("http://explicit:9000");
    assertThat(explicit.gelfPort()).hasValue(4444);
    assertThat(explicit.gelfProtocol()).isEqualTo(GelfProtocol.UDP);
    assertThat(explicit.gelfTls()).isFalse();
  }

  @Test
  void envErrorsNameTheVariable() {
    assertThatThrownBy(() -> GraylogConfig.fromEnv(Map.of("GRAYLOG_TRANSPORT", "smoke")))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("GRAYLOG_TRANSPORT")
        .hasMessageNotContaining("smoke");
    assertThatThrownBy(() -> GraylogConfig.fromEnv(Map.of(P + "GELF_PROTOCOL", "otlp")))
        .hasMessageContaining(P + "GELF_PROTOCOL");
    assertThatThrownBy(() -> GraylogConfig.fromEnv(Map.of("GRAYLOG_GELF_PORT", "abc")))
        .hasMessageContaining("GRAYLOG_GELF_PORT");
    assertThatThrownBy(() -> GraylogConfig.fromEnv(Map.of(P + "GELF_TLS", "maybe")))
        .hasMessageContaining(P + "GELF_TLS");
    assertThatThrownBy(() -> GraylogConfig.fromEnv(Map.of(P + "MAX_RETRIES", "-1")))
        .hasMessageContaining("MAX_RETRIES");
    assertThatThrownBy(() -> GraylogConfig.fromEnv(Map.of("GRAYLOG_USER", "admin")))
        .hasMessageContaining("together");
    GraylogConfig tls =
        GraylogConfig.fromEnv(
            Map.of(
                P + "CA_CERT",
                "/x/ca.pem",
                P + "CLIENT_CERT",
                "/x/c.pem",
                P + "CLIENT_KEY",
                "/x/k.pem"));
    assertThat(tls.tls().caCertPath()).isPresent();
  }

  @Test
  void validation() {
    assertThatThrownBy(() -> GraylogConfig.builder().url("ftp://x").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GraylogConfig.builder().url("http://").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GraylogConfig.builder().url("http://a b").build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> GraylogConfig.builder().connectTimeout(Duration.ZERO).build())
        .hasMessageContaining("connectTimeout");
    assertThatThrownBy(() -> GraylogConfig.builder().requestTimeout(Duration.ofSeconds(-1)).build())
        .hasMessageContaining("requestTimeout");
    assertThatThrownBy(() -> GraylogConfig.builder().totalTimeout(Duration.ZERO).build())
        .hasMessageContaining("totalTimeout");
    assertThatThrownBy(() -> GraylogConfig.builder().proxy("not a url").build())
        .hasMessageContaining("proxy");
    assertThatThrownBy(() -> GraylogConfig.builder().proxy("relative/path").build())
        .hasMessageContaining("proxy");
    assertThatThrownBy(() -> GraylogConfig.builder().gelfProtocol(GelfProtocol.OTLP).build())
        .hasMessageContaining("gelfProtocol");
    assertThatThrownBy(() -> GraylogConfig.builder().gelfPort(0).build())
        .hasMessageContaining("gelfPort");
    assertThatThrownBy(() -> GraylogConfig.builder().gelfPort(70000).build())
        .hasMessageContaining("gelfPort");
    assertThatThrownBy(() -> GraylogConfig.builder().gelfHost(" ").build())
        .hasMessageContaining("gelfHost");
    assertThatThrownBy(() -> GraylogConfig.builder().gelfHttpUrl("udp://x").build())
        .hasMessageContaining("gelfHttpUrl");
    assertThatThrownBy(() -> GraylogConfig.builder().otlpEndpoint("x").build())
        .hasMessageContaining("otlpEndpoint");
    assertThatThrownBy(() -> GraylogConfig.builder().apiToken(" ").build())
        .hasMessageContaining("apiToken");
    assertThatThrownBy(() -> GraylogConfig.builder().basicAuth("u", (String) null).build())
        .hasMessageContaining("together");
    assertThatThrownBy(() -> GraylogConfig.builder().basicAuth(" ", "p").build())
        .hasMessageContaining("username");
    assertThatThrownBy(() -> GraylogConfig.builder().requestedBy(" ").build())
        .hasMessageContaining("requestedBy");
    assertThat(GraylogConfig.builder().apiToken((String) null).build().apiToken()).isEmpty();
    assertThat(GraylogConfig.isHttpUrl(null)).isFalse();
  }

  @Test
  void derivedEndpointsAndRedaction() {
    GraylogConfig c =
        GraylogConfig.builder()
            .url("https://[::1]:9000")
            .basicAuth("admin", Secret.of("pa55word"))
            .gelfTls(true)
            .gelfHttpUrl(null)
            .requestedBy("me")
            .header("Authorization", "Bearer abc")
            .header("X-Plain", "v")
            .userAgentSuffix("suffix")
            .proxy("http://user:pw@proxy:3128")
            .gelfHttpUrl("https://u:p@gelf.example/gelf")
            .otlpEndpoint("https://otel.example:4317")
            .retry(RetryPolicy.none())
            .tls(TlsOptions.defaults())
            .hooks(Hooks.NONE)
            .logger(Logger.NOOP)
            .build();
    assertThat(c.gelfHost()).isEqualTo("::1");
    assertThat(GraylogConfig.hostPort("::1", 1)).isEqualTo("[::1]:1");
    assertThat(GraylogConfig.hostPort("h", 1)).isEqualTo("h:1");
    assertThat(c.requestedBy()).isEqualTo("me");
    assertThat(c.basicCredentials())
        .contains(
            Base64.getEncoder().encodeToString("admin:pa55word".getBytes(StandardCharsets.UTF_8)));
    String s = c.toString();
    assertThat(s)
        .doesNotContain("pa55word", "Bearer abc", ":pw@", "u:p@")
        .contains("admin", "[REDACTED]");

    GraylogConfig tls =
        GraylogConfig.builder().url("http://h:9000").gelfTls(true).gelfPort(5555).build();
    assertThat(tls.gelfHttpEndpoint()).isEqualTo("https://h:5555/gelf");
    GraylogConfig copy = c.toBuilder().build();
    assertThat(copy.headers()).isEqualTo(c.headers());
    assertThat(copy.gelfHttpUrl()).isEqualTo(c.gelfHttpUrl());
    assertThat(copy.username()).isEqualTo(c.username());
    assertThat(GraylogConfig.builder().build().toString())
        .contains("apiToken=null", "password=null");
  }
}
