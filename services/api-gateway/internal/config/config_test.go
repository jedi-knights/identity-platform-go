//go:build unit

package config_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
)

func TestConfig_ToDomainRoutes_MapsAllFields(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Name: "identity",
				Match: config.MatchConfig{
					PathPrefix: "/api/identity",
					Methods:    []string{"GET", "POST"},
					Headers:    map[string]string{"X-Version": "v2"},
				},
				Upstream: config.UpstreamConfig{
					URL:         "http://identity-service:8080",
					StripPrefix: "/api/identity",
				},
			},
		},
	}

	routes := cfg.ToDomainRoutes()

	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	r := routes[0]
	if r.Name != "identity" {
		t.Errorf("Name = %q, want %q", r.Name, "identity")
	}
	if r.Match.PathPrefix != "/api/identity" {
		t.Errorf("PathPrefix = %q, want %q", r.Match.PathPrefix, "/api/identity")
	}
	if len(r.Match.Methods) != 2 {
		t.Errorf("Methods count = %d, want 2", len(r.Match.Methods))
	}
	if r.Match.Headers["X-Version"] != "v2" {
		t.Errorf("Headers[X-Version] = %q, want %q", r.Match.Headers["X-Version"], "v2")
	}
	if r.Upstream.URL != "http://identity-service:8080" {
		t.Errorf("Upstream.URL = %q, want %q", r.Upstream.URL, "http://identity-service:8080")
	}
	if r.Upstream.StripPrefix != "/api/identity" {
		t.Errorf("Upstream.StripPrefix = %q, want %q", r.Upstream.StripPrefix, "/api/identity")
	}
}

func TestConfig_ToDomainRoutes_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	routes := cfg.ToDomainRoutes()
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestConfig_ToDomainRoutes_MultipleRoutes(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{Name: "svc-a", Upstream: config.UpstreamConfig{URL: "http://a:8080"}},
			{Name: "svc-b", Upstream: config.UpstreamConfig{URL: "http://b:8080"}},
			{Name: "svc-c", Upstream: config.UpstreamConfig{URL: "http://c:8080"}},
		},
	}

	routes := cfg.ToDomainRoutes()

	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	for i, want := range []string{"svc-a", "svc-b", "svc-c"} {
		if routes[i].Name != want {
			t.Errorf("routes[%d].Name = %q, want %q", i, routes[i].Name, want)
		}
	}
}

func TestConfig_ToDomainRoutes_NilHeadersArePropagated(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Name:     "no-headers",
				Match:    config.MatchConfig{PathPrefix: "/api"},
				Upstream: config.UpstreamConfig{URL: "http://svc:8080"},
			},
		},
	}

	routes := cfg.ToDomainRoutes()

	if routes[0].Match.Headers != nil {
		t.Errorf("expected nil headers, got %v", routes[0].Match.Headers)
	}
}

func TestConfig_ToDomainRoutes_WebSocketFieldPropagated(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Name:     "ws-route",
				Upstream: config.UpstreamConfig{URL: "http://svc:8080", WebSocket: true},
			},
			{
				Name:     "http-route",
				Upstream: config.UpstreamConfig{URL: "http://svc:8080", WebSocket: false},
			},
		},
	}

	routes := cfg.ToDomainRoutes()

	if !routes[0].Upstream.WebSocket {
		t.Error("ws-route: expected WebSocket=true, got false")
	}
	if routes[1].Upstream.WebSocket {
		t.Error("http-route: expected WebSocket=false, got true")
	}
}

// TestConfig_ToDomainRoutes_MethodsNormalizedToUppercase verifies that lowercase or
// mixed-case HTTP methods in the config are normalized to uppercase by ToDomainRoutes.
// The domain layer uses exact-string comparison (==) for method matching, so this
// normalization must happen at the config boundary.
func TestConfig_ToDomainRoutes_MethodsNormalizedToUppercase(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Name: "svc",
				Match: config.MatchConfig{
					Methods: []string{"get", "Post", "DELETE"},
				},
				Upstream: config.UpstreamConfig{URL: "http://svc:8080"},
			},
		},
	}

	// Act
	routes := cfg.ToDomainRoutes()

	// Assert
	want := []string{"GET", "POST", "DELETE"}
	got := routes[0].Match.Methods
	if len(got) != len(want) {
		t.Fatalf("methods count = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("methods[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// --- TLS config validation ---

// tlsEnvTest runs Load() with the given environment variables set and returns
// whatever Load returned. t.Setenv automatically restores each variable after
// the test. The working directory during tests is the package source directory,
// which has no gateway.yaml, so viper falls through to the ConfigFileNotFoundError
// branch and continues with defaults + env vars only.
func tlsEnvTest(t *testing.T, env map[string]string) error {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	_, err := config.Load()
	return err
}

// TestLoad_TLSCertWithoutKeyReturnsError verifies that providing tls_cert_file
// without tls_key_file is rejected at startup so the operator gets an explicit
// error instead of a silent HTTP-only fallback.
func TestLoad_TLSCertWithoutKeyReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_SERVER_TLS_CERT_FILE": "/path/cert.pem",
		// GATEWAY_SERVER_TLS_KEY_FILE deliberately not set
	})
	if err == nil {
		t.Fatal("expected error when tls_cert_file is set without tls_key_file, got nil")
	}
}

// TestLoad_TLSKeyWithoutCertReturnsError verifies that providing tls_key_file
// without tls_cert_file is also rejected.
func TestLoad_TLSKeyWithoutCertReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_SERVER_TLS_KEY_FILE": "/path/key.pem",
		// GATEWAY_SERVER_TLS_CERT_FILE deliberately not set
	})
	if err == nil {
		t.Fatal("expected error when tls_key_file is set without tls_cert_file, got nil")
	}
}

// TestLoad_TLSBothFieldsSetIsAccepted verifies that when both cert and key are
// provided the TLS validation passes (the file existence is not checked here).
func TestLoad_TLSBothFieldsSetIsAccepted(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_SERVER_TLS_CERT_FILE": "/path/cert.pem",
		"GATEWAY_SERVER_TLS_KEY_FILE":  "/path/key.pem",
	})
	if err != nil {
		t.Fatalf("expected no error when both TLS fields are set, got: %v", err)
	}
}

// --- Rate limit validation tests ---

func TestLoad_UnknownRateLimitStrategyReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_RATE_LIMIT_ENABLED":  "true",
		"GATEWAY_RATE_LIMIT_STRATEGY": "typo_bucket",
	})
	if err == nil {
		t.Fatal("expected error for unrecognised strategy, got nil")
	}
}

func TestLoad_KnownStrategiesAreAccepted(t *testing.T) {
	strategies := []string{
		"token_bucket", "fixed_window", "sliding_window_log",
		"sliding_window_counter", "leaky_bucket", "concurrency",
	}
	for _, s := range strategies {
		t.Run(s, func(t *testing.T) {
			err := tlsEnvTest(t, map[string]string{
				"GATEWAY_RATE_LIMIT_ENABLED":  "true",
				"GATEWAY_RATE_LIMIT_STRATEGY": s,
			})
			if err != nil {
				t.Errorf("strategy %q rejected unexpectedly: %v", s, err)
			}
		})
	}
}

func TestLoad_TokenBucketZeroBurstSizeReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_RATE_LIMIT_ENABLED":             "true",
		"GATEWAY_RATE_LIMIT_STRATEGY":            "token_bucket",
		"GATEWAY_RATE_LIMIT_REQUESTS_PER_SECOND": "10",
		"GATEWAY_RATE_LIMIT_BURST_SIZE":          "0",
	})
	if err == nil {
		t.Fatal("expected error for burst_size=0, got nil")
	}
}

func TestLoad_TokenBucketZeroRateReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_RATE_LIMIT_ENABLED":             "true",
		"GATEWAY_RATE_LIMIT_STRATEGY":            "token_bucket",
		"GATEWAY_RATE_LIMIT_REQUESTS_PER_SECOND": "0",
		"GATEWAY_RATE_LIMIT_BURST_SIZE":          "10",
	})
	if err == nil {
		t.Fatal("expected error for requests_per_second=0, got nil")
	}
}

func TestLoad_WindowStrategyZeroWindowSecsReturnsError(t *testing.T) {
	for _, s := range []string{"fixed_window", "sliding_window_log", "sliding_window_counter"} {
		t.Run(s, func(t *testing.T) {
			err := tlsEnvTest(t, map[string]string{
				"GATEWAY_RATE_LIMIT_ENABLED":             "true",
				"GATEWAY_RATE_LIMIT_STRATEGY":            s,
				"GATEWAY_RATE_LIMIT_REQUESTS_PER_WINDOW": "10",
				"GATEWAY_RATE_LIMIT_WINDOW_SECS":         "0",
			})
			if err == nil {
				t.Fatalf("strategy %q: expected error for window_secs=0, got nil", s)
			}
		})
	}
}

func TestLoad_LeakyBucketZeroDrainRateReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_RATE_LIMIT_ENABLED":               "true",
		"GATEWAY_RATE_LIMIT_STRATEGY":              "leaky_bucket",
		"GATEWAY_RATE_LIMIT_DRAIN_RATE_PER_SECOND": "0",
		"GATEWAY_RATE_LIMIT_QUEUE_DEPTH":           "10",
	})
	if err == nil {
		t.Fatal("expected error for drain_rate_per_second=0, got nil")
	}
}

func TestLoad_ConcurrencyZeroMaxInFlightReturnsError(t *testing.T) {
	err := tlsEnvTest(t, map[string]string{
		"GATEWAY_RATE_LIMIT_ENABLED":      "true",
		"GATEWAY_RATE_LIMIT_STRATEGY":     "concurrency",
		"GATEWAY_RATE_LIMIT_MAX_IN_FLIGHT": "0",
	})
	if err == nil {
		t.Fatal("expected error for max_in_flight=0, got nil")
	}
}
