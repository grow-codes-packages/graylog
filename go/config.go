package graylog

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// DefaultURL is the default REST endpoint of Graylog Open.
const DefaultURL = "http://127.0.0.1:9000"

// Default ports of the ingest inputs.
const (
	// DefaultGelfPort is the default GELF UDP and TCP port.
	DefaultGelfPort = 12201
	// DefaultGelfHTTPPort is the default GELF HTTP port (Graylog has no fixed
	// one; 12202 is the common choice).
	DefaultGelfHTTPPort = 12202
	// DefaultOTLPGRPCPort is the default port of the OpenTelemetry (gRPC) input.
	DefaultOTLPGRPCPort = 4317
)

// DefaultRequestedBy is the default X-Requested-By value (Graylog requires
// the header on every non-GET request).
const DefaultRequestedBy = "grow-codes-graylog"

// GelfProtocol selects the GELF transport used by Client.NewLogClient.
type GelfProtocol string

// GELF transports.
const (
	// GelfUDP sends one (possibly chunked and compressed) datagram per message.
	// Delivery is best-effort.
	GelfUDP GelfProtocol = "udp"
	// GelfTCP sends NUL-terminated JSON frames over one connection (default).
	GelfTCP GelfProtocol = "tcp"
	// GelfHTTP posts messages to the GELF HTTP input (newline-delimited bulk, gzip).
	GelfHTTP GelfProtocol = "http"
	// ProtocolOTLP selects the OTLP/gRPC exporter in LogOptions.Protocol (not a
	// GELF transport; invalid in Config.GelfProtocol).
	ProtocolOTLP GelfProtocol = "otlp"
)

// DefaultGelfProtocol is the protocol used when none is configured.
const DefaultGelfProtocol = GelfTCP

// vendorEnv lists the vendor variables consulted after GROW_GRAYLOG_*.
var vendorEnv = VendorEnv{URL: []string{"GRAYLOG_URL"}}

// Vendor variables (in precedence order) and platform stack aliases (last)
// for the service-specific fields.
var (
	vendorAPITokenEnv     = []string{"GRAYLOG_API_TOKEN"}
	vendorUserEnv         = []string{"GRAYLOG_USER"}
	vendorPasswordEnv     = []string{"GRAYLOG_PASSWORD"}
	vendorGelfHostEnv     = []string{"GRAYLOG_GELF_HOST", "GRAYLOG_HOST"}
	vendorGelfPortEnv     = []string{"GRAYLOG_GELF_PORT", "GRAYLOG_PORT"}
	vendorGelfProtocolEnv = []string{"GRAYLOG_GELF_PROTOCOL", "GRAYLOG_TRANSPORT"}
	vendorGelfHTTPURLEnv  = []string{"GRAYLOG_GELF_HTTP_URL"}
	vendorOTLPEndpointEnv = []string{"GRAYLOG_OTLP_GRPC_ENDPOINT"}
)

// Config configures a Client. Build it with a struct literal or ConfigFromEnv;
// zero values mean "use the default". Call Validate to check it.
//
// REST credentials: APIToken (sent as HTTP Basic "<token>:token") wins over
// Username/Password. The GELF fields configure the ingest transports of
// NewLogClient; empty values default to the host of URL, TCP, port 12201
// (12202 for HTTP, see GelfPortFor) and http://<GelfHost>:<port>/gelf (see
// GelfHTTPEndpoint).
type Config struct {
	CommonConfig

	// APIToken is a Graylog access token (env GROW_GRAYLOG_API_TOKEN, GRAYLOG_API_TOKEN).
	APIToken Secret
	// Username for HTTP Basic auth (env GROW_GRAYLOG_USER, GRAYLOG_USER).
	Username string
	// Password for HTTP Basic auth (env GROW_GRAYLOG_PASSWORD, GRAYLOG_PASSWORD).
	Password Secret

	// GelfHost is the host of the GELF input (env GROW_GRAYLOG_GELF_HOST,
	// GRAYLOG_GELF_HOST, GRAYLOG_HOST; default the host of URL).
	GelfHost string
	// GelfPort is the port of the GELF input (env GROW_GRAYLOG_GELF_PORT,
	// GRAYLOG_GELF_PORT, GRAYLOG_PORT; 0 = 12201 for UDP/TCP, 12202 for HTTP).
	GelfPort int
	// GelfProtocol is udp, tcp or http (env GROW_GRAYLOG_GELF_PROTOCOL,
	// GRAYLOG_GELF_PROTOCOL, GRAYLOG_TRANSPORT; default tcp).
	GelfProtocol GelfProtocol
	// GelfHTTPURL is the full URL of the GELF HTTP input (env
	// GROW_GRAYLOG_GELF_HTTP_URL, GRAYLOG_GELF_HTTP_URL; default see
	// GelfHTTPEndpoint).
	GelfHTTPURL string
	// GelfTLS enables TLS for the GELF TCP transport and https for the default
	// GELF HTTP URL, using the TLS settings of CommonConfig (env
	// GROW_GRAYLOG_GELF_TLS).
	GelfTLS bool
	// OTLPEndpoint is the http(s) URL of an OpenTelemetry (gRPC) input (env
	// GROW_GRAYLOG_OTLP_ENDPOINT, GRAYLOG_OTLP_GRPC_ENDPOINT; default
	// http://<GelfHost>:4317, see OTLPGRPCEndpoint).
	OTLPEndpoint string
	// RequestedBy is the X-Requested-By value of non-GET requests (default
	// "grow-codes-graylog").
	RequestedBy string
}

// ConfigFromEnv reads the configuration from the process environment.
func ConfigFromEnv() (Config, error) { return ConfigFromEnvWith(Config{}, nil) }

// ConfigFromEnvWith resolves explicit values > GROW_GRAYLOG_* > vendor
// variables (GRAYLOG_*) > platform aliases (GRAYLOG_HOST, GRAYLOG_PORT,
// GRAYLOG_TRANSPORT) > defaults. env replaces the process environment when
// non-nil.
func ConfigFromEnvWith(explicit Config, env map[string]string) (Config, error) {
	r := NewEnvReader(EnvPrefix, env)
	c := explicit
	if err := c.applyEnv(r, vendorEnv); err != nil {
		return Config{}, err
	}
	setSecret := func(dst *Secret, name string, vendor []string) {
		if dst.IsZero() {
			if v, ok := r.String(name, vendor...); ok {
				*dst = NewSecret(v)
			}
		}
	}
	setString := func(dst *string, name string, vendor []string) {
		if *dst == "" {
			if v, ok := r.String(name, vendor...); ok {
				*dst = v
			}
		}
	}
	setSecret(&c.APIToken, "API_TOKEN", vendorAPITokenEnv)
	setString(&c.Username, "USER", vendorUserEnv)
	setSecret(&c.Password, "PASSWORD", vendorPasswordEnv)
	setString(&c.GelfHost, "GELF_HOST", vendorGelfHostEnv)
	setString(&c.GelfHTTPURL, "GELF_HTTP_URL", vendorGelfHTTPURLEnv)
	setString(&c.OTLPEndpoint, "OTLP_ENDPOINT", vendorOTLPEndpointEnv)
	if c.GelfProtocol == "" {
		if v, ok := r.String("GELF_PROTOCOL", vendorGelfProtocolEnv...); ok {
			c.GelfProtocol = GelfProtocol(strings.ToLower(strings.TrimSpace(v)))
			if c.GelfProtocol != GelfUDP && c.GelfProtocol != GelfTCP && c.GelfProtocol != GelfHTTP {
				return Config{}, ConfigError("invalid value in environment variable " + envName(r, "GELF_PROTOCOL", vendorGelfProtocolEnv) + ": expected udp, tcp or http")
			}
		}
	}
	if !c.GelfTLS {
		v, ok, err := r.Bool("GELF_TLS")
		if err != nil {
			return Config{}, err
		}
		c.GelfTLS = ok && v
	}
	if c.GelfPort == 0 {
		n, ok, err := r.Int("GELF_PORT", vendorGelfPortEnv...)
		if err != nil {
			return Config{}, err
		}
		if ok {
			c.GelfPort = n
		}
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c.withServiceDefaults(), nil
}

// withServiceDefaults returns a copy with the common and GELF defaults applied.
// It must only be called on a validated config.
func (c Config) withServiceDefaults() Config {
	c.CommonConfig = c.withDefaults(DefaultURL)
	if c.GelfHost == "" {
		if u, err := url.Parse(c.URL); err == nil {
			c.GelfHost = u.Hostname()
		}
	}
	if c.GelfProtocol == "" {
		c.GelfProtocol = DefaultGelfProtocol
	}
	if c.RequestedBy == "" {
		c.RequestedBy = DefaultRequestedBy
	}
	return c
}

// GelfPortFor returns the GELF port used for protocol: GelfPort when set,
// else 12202 for HTTP and 12201 otherwise.
func (c Config) GelfPortFor(protocol GelfProtocol) int {
	switch {
	case c.GelfPort != 0:
		return c.GelfPort
	case protocol == GelfHTTP:
		return DefaultGelfHTTPPort
	}
	return DefaultGelfPort
}

// GelfHTTPEndpoint returns the effective GELF HTTP URL: GelfHTTPURL when set,
// else http(s)://<GelfHost>:<GelfPortFor(http)>/gelf (https with GelfTLS).
func (c Config) GelfHTTPEndpoint() string {
	if c.GelfHTTPURL != "" {
		return c.GelfHTTPURL
	}
	scheme := "http"
	if c.GelfTLS {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(c.gelfHost(), strconv.Itoa(c.GelfPortFor(GelfHTTP))) + "/gelf"
}

// OTLPGRPCEndpoint returns the effective OTLP/gRPC endpoint: OTLPEndpoint
// when set, else http://<GelfHost>:4317.
func (c Config) OTLPGRPCEndpoint() string {
	if c.OTLPEndpoint != "" {
		return c.OTLPEndpoint
	}
	return "http://" + net.JoinHostPort(c.gelfHost(), strconv.Itoa(DefaultOTLPGRPCPort))
}

// gelfHost is GelfHost or the host of URL.
func (c Config) gelfHost() string {
	if c.GelfHost != "" {
		return c.GelfHost
	}
	if u, err := url.Parse(c.withDefaults(DefaultURL).URL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "127.0.0.1"
}

// envName returns the name of the variable that supplied name (for messages).
func envName(r *EnvReader, name string, vendor []string) string {
	_, variable, _ := r.find(name, vendor)
	return variable
}

// Validate checks the configuration and returns a CONFIG error.
func (c Config) Validate() error {
	if err := c.withDefaults(DefaultURL).validate(); err != nil {
		return err
	}
	switch c.GelfProtocol {
	case "", GelfUDP, GelfTCP, GelfHTTP:
	default:
		return ConfigError("gelfProtocol must be udp, tcp or http")
	}
	if c.GelfPort < 0 || c.GelfPort > 65535 {
		return ConfigError("gelfPort must be an integer 1..65535")
	}
	if c.GelfHTTPURL != "" && !isHTTPURL(c.GelfHTTPURL) {
		return ConfigError("gelfHttpUrl must be an http(s) URL")
	}
	if c.OTLPEndpoint != "" && !isHTTPURL(c.OTLPEndpoint) {
		return ConfigError("otlpEndpoint must be an http(s) URL")
	}
	if !c.APIToken.IsZero() && strings.TrimSpace(c.APIToken.Reveal()) == "" {
		return ConfigError("apiToken must not be blank")
	}
	if (c.Username == "") != c.Password.IsZero() {
		return ConfigError("username and password must be given together")
	}
	if c.RequestedBy != "" && strings.TrimSpace(c.RequestedBy) == "" {
		return ConfigError("requestedBy must not be blank")
	}
	return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// String renders the configuration with every credential redacted.
func (c Config) String() string {
	user := ""
	if c.Username != "" {
		user = " Username:" + c.Username
	}
	return fmt.Sprintf("Config{%s APIToken:%s%s Password:%s GelfHost:%s GelfPort:%d GelfProtocol:%s GelfHTTPURL:%s GelfTLS:%t OTLPEndpoint:%s RequestedBy:%s}",
		c.describe(), c.APIToken, user, c.Password, c.GelfHost, c.GelfPort, c.GelfProtocol, RedactURL(c.GelfHTTPURL), c.GelfTLS,
		RedactURL(c.OTLPEndpoint), c.RequestedBy)
}

// GoString renders the configuration with every credential redacted.
func (c Config) GoString() string { return c.String() }
