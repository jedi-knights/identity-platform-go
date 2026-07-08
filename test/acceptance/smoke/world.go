package smoke

import (
	"net/http"
	"os"
	"time"
)

// smokeWorld holds the fixed-port service URLs and last-response state
// every step needs. Unlike the main acceptance suite's support.World,
// there is exactly one of these for the whole suite run (see main_test.go's
// serial-concurrency rationale) — no per-scenario isolation is needed
// since nothing here mutates shared state across scenarios beyond minting
// fresh tokens, which is inherently safe to repeat.
type smokeWorld struct {
	HTTPClient *http.Client

	AuthServerURL          string
	IdentityServiceURL     string
	ClientRegistryURL      string
	LoginUIURL             string
	TokenIntrospectionURL  string
	AuthorizationPolicyURL string
	ExampleResourceURL     string

	LastResponse *http.Response
	LastBody     []byte
	Vars         map[string]string
}

// newSmokeWorld resolves every service's base URL from an env var,
// defaulting to the host port docker-compose.yml maps it to, so
// `task test:smoke` works against the standard compose file with zero
// required env vars beyond the dev-client secret (which is generated
// fresh per run — see Taskfile.yml's test:smoke task).
func newSmokeWorld() *smokeWorld {
	return &smokeWorld{
		HTTPClient:             &http.Client{Timeout: 10 * time.Second},
		AuthServerURL:          envOrDefault("SMOKE_AUTH_SERVER_URL", "http://localhost:9080"),
		IdentityServiceURL:     envOrDefault("SMOKE_IDENTITY_SERVICE_URL", "http://localhost:9081"),
		ClientRegistryURL:      envOrDefault("SMOKE_CLIENT_REGISTRY_URL", "http://localhost:9082"),
		LoginUIURL:             envOrDefault("SMOKE_LOGIN_UI_URL", "http://localhost:9087"),
		TokenIntrospectionURL:  envOrDefault("SMOKE_TOKEN_INTROSPECTION_URL", "http://localhost:9083"),
		AuthorizationPolicyURL: envOrDefault("SMOKE_AUTHORIZATION_POLICY_URL", "http://localhost:9084"),
		ExampleResourceURL:     envOrDefault("SMOKE_EXAMPLE_RESOURCE_URL", "http://localhost:9085"),
		Vars:                   map[string]string{},
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
