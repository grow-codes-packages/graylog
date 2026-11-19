package graylog

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a client for url with fast retries and an API token;
// mutate adjusts the config.
func newTestClient(t *testing.T, url string, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{CommonConfig: CommonConfig{URL: url, Retry: fastRetry(3)}, APIToken: NewSecret(testToken)}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestConfigFromEnv(t *testing.T) {
	t.Run("core.config.env-precedence", func(t *testing.T) {
		env := map[string]string{
			EnvPrefix + "URL": "http://grow:1", "GRAYLOG_URL": "http://vendor:2",
			"GRAYLOG_API_TOKEN": "vendor-token", "GRAYLOG_USER": "u", "GRAYLOG_PASSWORD": "p-secret",
			"GRAYLOG_HOST": "alias-host", "GRAYLOG_PORT": "1111", "GRAYLOG_TRANSPORT": "udp",
			"GRAYLOG_GELF_HTTP_URL": "http://gelf:12202/gelf", "GRAYLOG_OTLP_GRPC_ENDPOINT": "http://otlp:4317",
		}
		cfg, err := ConfigFromEnvWith(Config{}, env)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != "http://grow:1" || cfg.APIToken.Reveal() != "vendor-token" || cfg.Username != "u" || cfg.Password.Reveal() != "p-secret" {
			t.Fatalf("credentials: %s", cfg)
		}
		if cfg.GelfHost != "alias-host" || cfg.GelfPort != 1111 || cfg.GelfProtocol != GelfUDP {
			t.Fatalf("platform aliases: %s", cfg)
		}
		if cfg.GelfHTTPEndpoint() != "http://gelf:12202/gelf" || cfg.OTLPGRPCEndpoint() != "http://otlp:4317" {
			t.Fatalf("endpoints: %s %s", cfg.GelfHTTPEndpoint(), cfg.OTLPGRPCEndpoint())
		}
		env["GRAYLOG_GELF_HOST"], env["GRAYLOG_GELF_PORT"], env["GRAYLOG_GELF_PROTOCOL"] = "vendor-host", "2222", "HTTP"
		env[EnvPrefix+"API_TOKEN"], env[EnvPrefix+"GELF_TLS"] = "grow-token", "yes"
		cfg, err = ConfigFromEnvWith(Config{}, env)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.GelfHost != "vendor-host" || cfg.GelfPort != 2222 || cfg.GelfProtocol != GelfHTTP || cfg.APIToken.Reveal() != "grow-token" || !cfg.GelfTLS {
			t.Fatalf("vendor over alias, GROW over vendor: %s", cfg)
		}
		cfg, err = ConfigFromEnvWith(Config{GelfHost: "explicit", GelfPort: 3, GelfProtocol: GelfTCP, APIToken: NewSecret("explicit-token")}, env)
		if err != nil || cfg.GelfHost != "explicit" || cfg.GelfPort != 3 || cfg.GelfProtocol != GelfTCP || cfg.APIToken.Reveal() != "explicit-token" {
			t.Fatalf("explicit must win: %v %s", err, cfg)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		cfg, err := ConfigFromEnvWith(Config{}, map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != DefaultURL || cfg.GelfHost != "127.0.0.1" || cfg.GelfProtocol != GelfTCP || cfg.RequestedBy != DefaultRequestedBy {
			t.Fatalf("defaults: %s", cfg)
		}
		if cfg.GelfPortFor(GelfTCP) != 12201 || cfg.GelfPortFor(GelfUDP) != 12201 || cfg.GelfPortFor(GelfHTTP) != 12202 {
			t.Fatal("default ports")
		}
		if cfg.GelfHTTPEndpoint() != "http://127.0.0.1:12202/gelf" || cfg.OTLPGRPCEndpoint() != "http://127.0.0.1:4317" {
			t.Fatalf("default endpoints: %s %s", cfg.GelfHTTPEndpoint(), cfg.OTLPGRPCEndpoint())
		}
		tlsCfg := Config{GelfHost: "::1", GelfTLS: true}
		if got := tlsCfg.GelfHTTPEndpoint(); got != "https://[::1]:12202/gelf" {
			t.Fatalf("tls endpoint: %s", got)
		}
		if got := (Config{CommonConfig: CommonConfig{URL: "http://h:9000"}}).OTLPGRPCEndpoint(); got != "http://h:4317" {
			t.Fatalf("otlp from url host: %s", got)
		}
		if got := (Config{CommonConfig: CommonConfig{URL: "::bad"}}).gelfHost(); got != "127.0.0.1" {
			t.Fatalf("gelf host fallback: %s", got)
		}
	})

	t.Run("invalid values", func(t *testing.T) {
		cases := map[string]map[string]string{
			"GELF_PROTOCOL": {"GRAYLOG_GELF_PROTOCOL": "smtp-xyz"},
			"GELF_PORT":     {EnvPrefix + "GELF_PORT": "port-xyz"},
			"GELF_TLS":      {EnvPrefix + "GELF_TLS": "maybe-xyz"},
			"TOTAL_TIMEOUT": {EnvPrefix + "TOTAL_TIMEOUT": "forever-xyz"},
		}
		for name, env := range cases {
			_, err := ConfigFromEnvWith(Config{}, env)
			if !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), "xyz") {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{"GRAYLOG_GELF_PROTOCOL": "smtp"}); err == nil || !strings.Contains(err.Error(), "GRAYLOG_GELF_PROTOCOL") {
			t.Fatalf("variable name: %v", err)
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "URL": "ftp://nope"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid url: %v", err)
		}
		t.Setenv(EnvPrefix+"URL", "http://process-env:9")
		if cfg, err := ConfigFromEnv(); err != nil || cfg.URL != "http://process-env:9" {
			t.Fatalf("process env: %v %s", err, cfg.URL)
		}
	})

	t.Run("validate", func(t *testing.T) {
		bad := []Config{
			{GelfProtocol: "smtp"},
			{GelfProtocol: ProtocolOTLP},
			{GelfPort: 70000},
			{GelfPort: -1},
			{GelfHTTPURL: "ftp://x"},
			{OTLPEndpoint: "grpc://x"},
			{APIToken: NewSecret("   ")},
			{Username: "u"},
			{Password: NewSecret("p")},
			{RequestedBy: "  "},
			{CommonConfig: CommonConfig{URL: "mailto:x"}},
		}
		for i, c := range bad {
			if err := c.Validate(); !errors.Is(err, ErrConfig) {
				t.Fatalf("case %d (%s): %v", i, c, err)
			}
		}
		if err := (Config{Username: "u", Password: NewSecret("p")}).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("core.redaction.config", func(t *testing.T) {
		cfg := Config{
			CommonConfig: CommonConfig{URL: "https://h", Headers: map[string]string{"X-Api-Key": "hdr-xyz"}},
			APIToken:     NewSecret("tok-xyz"), Username: "admin", Password: NewSecret("pw-xyz"),
			OTLPEndpoint: "http://otlp:4317",
		}
		forms := fmt.Sprintf("%v|%+v|%#v|%s", cfg, cfg, cfg, cfg.String())
		if strings.Contains(forms, "tok-xyz") || strings.Contains(forms, "hdr-xyz") || strings.Contains(forms, "pw-xyz") ||
			!strings.Contains(forms, "APIToken:"+Redacted) || !strings.Contains(forms, "Username:admin") {
			t.Fatalf("forms: %s", forms)
		}
	})
}

func TestClientSurface(t *testing.T) {
	var authSeen []string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, n int) {
		authSeen = append(authSeen, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case pathLBStatus:
			if r.Header.Get("Accept") != "text/plain" || r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			loadFixture(t, "health.ok").write(w)
		case pathSystem:
			switch r.Header.Get("Authorization") {
			case basicAuth(testToken, "token"):
				loadFixture(t, "ping.ok_token").write(w)
			case basicAuth("admin", "pw-1234"):
				loadFixture(t, "ping.ok_password").write(w)
			default:
				loadFixture(t, "ping.unauthorized").write(w)
			}
		case pathFields:
			loadFixture(t, "listLabels.ok").write(w)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("health ping version info", func(t *testing.T) {
		c := newTestClient(t, ts.URL, nil)
		hs, err := c.Health(t.Context())
		if err != nil || !hs.Healthy || hs.Status != "ok" || hs.Details["lb_status"] != "ALIVE" {
			t.Fatalf("health %+v %v", hs, err)
		}
		if d, err := c.Ping(t.Context()); err != nil || d <= 0 {
			t.Fatalf("ping %s %v", d, err)
		}
		if v, err := c.ServerVersion(t.Context()); err != nil || v != "7.0.16+58e0f6e" {
			t.Fatalf("version %q %v", v, err)
		}
		info, err := c.SystemInfo(t.Context())
		if err != nil || info.NodeID == "" || !info.IsLeader || info.StartedAt.IsZero() || info.Codename != "Noir" {
			t.Fatalf("systemInfo %+v %v", info, err)
		}
		fields, err := c.ListFields(t.Context())
		if err != nil || len(fields) < 10 || fields[0] > fields[1] {
			t.Fatalf("listFields %v %v", fields, err)
		}
		if c.Config().GelfHost != "127.0.0.1" {
			t.Fatalf("Config(): %s", c.Config())
		}
	})

	t.Run("password auth", func(t *testing.T) {
		c := newTestClient(t, ts.URL, func(cfg *Config) { cfg.APIToken = Secret{}; cfg.Username, cfg.Password = "admin", NewSecret("pw-1234") })
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("authentication errors", func(t *testing.T) {
		bad := newTestClient(t, ts.URL, func(cfg *Config) { cfg.APIToken = NewSecret("wrong-token") })
		_, err := bad.Ping(t.Context())
		if !errors.Is(err, ErrAuthentication) || strings.Contains(err.Error(), "wrong-token") {
			t.Fatalf("bad token: %v", err)
		}
		none := newTestClient(t, ts.URL, func(cfg *Config) { cfg.APIToken = Secret{} })
		if _, err := none.Ping(t.Context()); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("no token: %v", err)
		}
		if _, err := none.ServerVersion(t.Context()); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("version: %v", err)
		}
	})

	t.Run("health states", func(t *testing.T) {
		cases := []struct {
			status        int
			body, want    string
			healthy       bool
			wantLB        string
			ifContentType string
		}{
			{429, "THROTTLED", "degraded", false, "THROTTLED", ""},
			{503, "DEAD", "unhealthy", false, "DEAD", ""},
			{200, "STARTING", "unhealthy", false, "STARTING", ""},
			{500, "", "unhealthy", false, "HTTP 500", ""},
		}
		for _, tc := range cases {
			srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			hs, err := newTestClient(t, srv.URL, nil).Health(t.Context())
			if err != nil || hs.Healthy != tc.healthy || hs.Status != tc.want || hs.Details["lb_status"] != tc.wantLB {
				t.Fatalf("%d: %+v %v", tc.status, hs, err)
			}
		}
	})

	t.Run("core.health.unreachable", func(t *testing.T) {
		c := newTestClient(t, "http://"+closedAddr(t), func(cfg *Config) { cfg.ConnectTimeout = time.Second })
		if hs, err := c.Health(t.Context()); err != nil || hs.Healthy || hs.Status != "unreachable" {
			t.Fatalf("hs=%+v err=%v", hs, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.Health(ctx); !errors.Is(err, ErrCancelled) {
			t.Fatalf("cancelled health: %v", err)
		}
	})

	t.Run("server version errors", func(t *testing.T) {
		empty := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte(`{"version":""}`)) })
		if _, err := newTestClient(t, empty.URL, nil).ServerVersion(t.Context()); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("empty version: %v", err)
		}
		html := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html>MongoTimeoutException</html>"))
		})
		c := newTestClient(t, html.URL, func(cfg *Config) { cfg.Retry = fastRetry(0) })
		_, err := c.ServerVersion(t.Context())
		if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "html") {
			t.Fatalf("html 500: %v", err)
		}
		bad := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte("nope")) })
		if _, err := newTestClient(t, bad.URL, nil).ListFields(t.Context()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("decode: %v", err)
		}
		nullFields := newTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte(`{}`)) })
		if f, err := newTestClient(t, nullFields.URL, nil).ListFields(t.Context()); err != nil || f == nil || len(f) != 0 {
			t.Fatalf("empty fields: %v %v", f, err)
		}
	})

	t.Run("core.close.idempotent", func(t *testing.T) {
		c := newTestClient(t, ts.URL, nil)
		var closed int
		c.onClose(func() { closed++ })
		first, second := c.Close(), c.Close()
		if first != nil || second != nil || closed != 1 {
			t.Fatal("close")
		}
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("after close: %v", err)
		}
		c.onClose(func() { closed++ })
		if closed != 2 {
			t.Fatal("onClose after close must run at once")
		}
	})

	t.Run("from env and invalid config", func(t *testing.T) {
		t.Setenv(EnvPrefix+"URL", ts.URL)
		t.Setenv("GRAYLOG_API_TOKEN", testToken)
		c, err := NewClientFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvPrefix+"URL", "mailto:x")
		if _, err := NewClientFromEnv(); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad env: %v", err)
		}
		if _, err := NewClient(Config{CommonConfig: CommonConfig{TLS: TLSConfig{CACertPEM: "bad"}}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad TLS: %v", err)
		}
		if _, err := NewClient(Config{GelfProtocol: "x"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad protocol: %v", err)
		}
	})

	t.Run("csrf header on writes only", func(t *testing.T) {
		c := newTestClient(t, ts.URL, func(cfg *Config) { cfg.RequestedBy = "my-app" })
		if h := c.headers(http.MethodGet); h.Get(HeaderRequestedBy) != "" {
			t.Fatal("GET must not send X-Requested-By")
		}
		if h := c.headers(http.MethodPost); h.Get(HeaderRequestedBy) != "my-app" {
			t.Fatal("POST must send X-Requested-By")
		}
	})
	_ = authSeen
}
