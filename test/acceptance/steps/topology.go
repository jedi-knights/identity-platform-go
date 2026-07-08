package steps

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// topologyStarters maps each `@topology:*` tag to the function that
// starts its service combination. Add an entry here (and tag the
// corresponding feature file) as new feature files need a different
// service combination — this is a lookup, not a switch, so adding
// topologies never grows startTopologyForTags's own complexity.
var topologyStarters = map[string]func(context.Context, *support.World) error{
	"@topology:auth-client-registry":               startAuthAndClientRegistry,
	"@topology:auth-client-registry-introspection": startAuthClientRegistryIntrospection,
	"@topology:auth-client-registry-resource":      startAuthClientRegistryResource,
	"@topology:auth-server-only":                   startAuthServerOnly,
	"@topology:auth-server-rotating-keys":          startAuthServerRotatingKeys,
}

// startTopologyForTags creates this scenario's temp dir and starts
// exactly the service processes its feature file's `@topology:*` tag
// declares — not the full platform — so scenarios stay fast.
func startTopologyForTags(ctx context.Context, world *support.World, sc *godog.Scenario, redisURL func() string) error {
	tempDir, err := os.MkdirTemp("", "acceptance-scenario-")
	if err != nil {
		return fmt.Errorf("creating scenario temp dir: %w", err)
	}
	world.TempDir = tempDir

	for _, tag := range sc.Tags {
		start, ok := topologyStarters[tag.Name]
		if !ok {
			continue
		}
		if err := start(ctx, world); err != nil {
			return fmt.Errorf("starting topology %q: %w", tag.Name, err)
		}
	}
	return nil
}

// startAuthAndClientRegistry builds and starts auth-server and
// client-registry-service for one scenario, wiring auth-server's
// AUTH_CLIENT_REGISTRY_URL at client-registry-service's freshly-allocated
// port.
//
// client-registry-service intentionally uses its in-memory adapter here
// (CLIENT_DATABASE_URL unset) rather than the SQLite adapter from
// services/client-registry-service/internal/adapters/outbound/sqlite —
// that adapter's container.go DSN-scheme dispatch is not on `main` yet at
// the time this feature file was written (it ships in a separate PR).
// In-memory is a fully supported, zero-external-dependency adapter in its
// own right, so this is not a workaround so much as the correct default;
// once the SQLite-dispatch PR lands, a later feature can set
// CLIENT_DATABASE_URL=file:... to exercise that path specifically.
func startAuthAndClientRegistry(ctx context.Context, world *support.World) error {
	_, err := startAuthAndClientRegistryServices(ctx, world)
	return err
}

// startAuthAndClientRegistryServices is the shared base every
// auth-server-centric topology builds on — it returns the started
// auth-server process so callers that layer on more services (like
// introspection) can point them at it without re-parsing world.Services.
func startAuthAndClientRegistryServices(ctx context.Context, world *support.World) (*support.RunningService, error) {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return nil, err
	}
	world.Services["client-registry-service"] = clientRegistry

	authServer, err := startAuthServer(ctx, clientRegistry.BaseURL)
	if err != nil {
		return nil, err
	}
	world.Services["auth-server"] = authServer
	return authServer, nil
}

// startAuthClientRegistryIntrospection layers token-introspection-service
// on top of the auth+client-registry pair, pointing it at auth-server's
// JWKS endpoint (RS256 is the default signing algorithm per ADR-0008) so
// it can validate real tokens auth-server issues, and giving it a
// pre-shared introspection secret every scenario using this topology
// shares — safe because each scenario gets its own freshly-spawned
// process, so there is no cross-scenario secret reuse to worry about.
func startAuthClientRegistryIntrospection(ctx context.Context, world *support.World) error {
	authServer, err := startAuthAndClientRegistryServices(ctx, world)
	if err != nil {
		return err
	}

	introspection, err := startTokenIntrospectionService(ctx, authServer.BaseURL)
	if err != nil {
		return err
	}
	world.Services["token-introspection-service"] = introspection
	return nil
}

// introspectionSecret is the pre-shared secret token-introspection-service
// requires callers to present. See startAuthClientRegistryIntrospection's
// doc comment for why a shared constant is safe here.
const introspectionSecret = "acceptance-test-introspection-secret"

func startTokenIntrospectionService(ctx context.Context, authServerURL string) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("token-introspection-service")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "token-introspection-service", bin, port, []string{
		"INTROSPECT_SERVER_PORT=" + strconv.Itoa(port),
		"INTROSPECT_JWT_JWKS_URL=" + authServerURL + "/.well-known/jwks.json",
		"INTROSPECT_INTROSPECTION_SECRET=" + introspectionSecret,
	})
}

// startAuthClientRegistryResource layers example-resource-service on top
// of the auth+client-registry pair, pointing it at auth-server's JWKS
// endpoint so RS256AuthMiddleware validates real tokens auth-server
// issues locally — no introspection or policy service configured, so
// scope alone gates access (RESOURCE_POLICY_URL unset) and revocation
// isn't checked here (that's what token_revocation.feature's own
// introspection-based scenario already covers).
func startAuthClientRegistryResource(ctx context.Context, world *support.World) error {
	authServer, err := startAuthAndClientRegistryServices(ctx, world)
	if err != nil {
		return err
	}

	resourceService, err := startExampleResourceService(ctx, authServer.BaseURL)
	if err != nil {
		return err
	}
	world.Services["example-resource-service"] = resourceService
	return nil
}

func startExampleResourceService(ctx context.Context, authServerURL string) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("example-resource-service")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "example-resource-service", bin, port, []string{
		"RESOURCE_SERVER_PORT=" + strconv.Itoa(port),
		"RESOURCE_JWT_JWKS_URL=" + authServerURL + "/.well-known/jwks.json",
	})
}

func startClientRegistryService(ctx context.Context) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("client-registry-service")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "client-registry-service", bin, port, []string{
		"CLIENT_SERVER_PORT=" + strconv.Itoa(port),
	})
}

// loginUIServiceToken is the pre-shared bearer secret authorization_code_
// steps.go presents to auth-server's POST /internal/issue-code — the
// endpoint login-ui would call after a real sign-in. This suite bypasses
// login-ui entirely (see authorization_code_pkce.feature's header
// comment for why) and calls issue-code directly, so AUTH_LOGIN_UI_URL
// below is never actually dereferenced by anything in this topology —
// its only effect is enabling /oauth/authorize and /internal/issue-code
// (both 501/404 when unset), which is harmless for every other feature
// using this topology since none of them call those two endpoints.
const loginUIServiceToken = "acceptance-test-login-ui-service-token"

// startAuthServer starts auth-server. extraEnv is appended after the base
// env, so a caller wiring a rotation keyset (see startAuthServerRotatingKeys)
// can override the default ephemeral-key behavior.
func startAuthServer(ctx context.Context, clientRegistryURL string, extraEnv ...string) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("auth-server")
	if err != nil {
		return nil, err
	}
	env := append([]string{
		"AUTH_SERVER_PORT=" + strconv.Itoa(port),
		"AUTH_CLIENT_REGISTRY_URL=" + clientRegistryURL,
		"AUTH_LOGIN_UI_URL=http://127.0.0.1:1",
		"AUTH_LOGIN_UI_SERVICE_TOKEN=" + loginUIServiceToken,
	}, extraEnv...)
	return support.StartService(ctx, "auth-server", bin, port, env)
}

// startAuthServerOnly starts a standalone auth-server with no
// client-registry-service — for scenarios that only exercise the JWKS
// endpoint or introspection with a pre-obtained token, where client
// registration isn't part of what's being tested. AUTH_CLIENT_REGISTRY_URL
// is left empty, which falls back to auth-server's in-memory client
// adapter (see CLAUDE.md's "Fallback behavior").
func startAuthServerOnly(ctx context.Context, world *support.World) error {
	authServer, err := startAuthServer(ctx, "")
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

// startAuthServerRotatingKeys starts a standalone auth-server configured
// with all three ADR-0008 key slots (current, retiring, next), each a
// freshly generated 2048-bit RSA keypair — fresh per scenario since these
// run as isolated subprocesses, not shared state, so there's no need to
// treat them as a fixture requiring support.RandomID-style uniqueness.
func startAuthServerRotatingKeys(ctx context.Context, world *support.World) error {
	current, err := support.GenerateRSAKeyPEM()
	if err != nil {
		return fmt.Errorf("generating current signing key: %w", err)
	}
	previous, err := support.GenerateRSAKeyPEM()
	if err != nil {
		return fmt.Errorf("generating previous signing key: %w", err)
	}
	next, err := support.GenerateRSAKeyPEM()
	if err != nil {
		return fmt.Errorf("generating next signing key: %w", err)
	}

	authServer, err := startAuthServer(ctx, "",
		"AUTH_JWT_RSA_PRIVATE_KEY_PEM="+current,
		"AUTH_JWT_RSA_PRIVATE_KEY_PEM_PREVIOUS="+previous,
		"AUTH_JWT_RSA_PRIVATE_KEY_PEM_NEXT="+next,
	)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}
