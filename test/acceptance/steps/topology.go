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
	"@topology:auth-client-registry-oidc":          startAuthClientRegistryOIDC,
	"@topology:auth-client-registry-identity-oidc": startAuthClientRegistryIdentityOIDC,
	"@topology:auth-metadata":                      startAuthMetadataOnly,
	"@topology:auth-metadata-full":                 startAuthMetadataFull,
	"@topology:client-registry-dcr":                startClientRegistryDCR,
	"@topology:auth-client-registry-short-ttl":     startAuthClientRegistryShortChallengeTTL,
	"@topology:login-challenge-handoff-e2e":        startLoginChallengeHandoffE2E,
	"@topology:auth-client-registry-saml-bearer":   startAuthClientRegistrySAMLBearer,
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

// startAuthClientRegistrySAMLBearer layers client-registry-service under
// auth-server with AUTH_METADATA_PUBLIC_BASE_URL set self-referentially
// (mirrors startAuthServerMetadata's pattern) — RFC 7522 (ADR-0026)
// scenarios need this because the saml2-bearer grant's expected assertion
// audience/recipient is this auth-server's own token endpoint URL, which
// application.SAMLBearerStrategy resolves from that config value rather
// than from any per-request context. startAuthAndClientRegistryServices
// deliberately does not set it — most scenarios using that topology assert
// metadata endpoints are absent/disabled, so this is its own topology
// rather than a change to the shared one.
func startAuthClientRegistrySAMLBearer(ctx context.Context, world *support.World) error {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	port, err := support.FreePort()
	if err != nil {
		return err
	}
	bin, err := support.BuildBinary("auth-server")
	if err != nil {
		return err
	}
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	env := []string{
		"AUTH_SERVER_PORT=" + strconv.Itoa(port),
		"AUTH_CLIENT_REGISTRY_URL=" + clientRegistry.BaseURL,
		"AUTH_LOGIN_UI_URL=http://127.0.0.1:1",
		"AUTH_LOGIN_UI_SERVICE_TOKEN=" + loginUIServiceToken,
		"AUTH_METADATA_PUBLIC_BASE_URL=" + baseURL,
	}
	authServer, err := support.StartService(ctx, "auth-server", bin, port, env)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
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

// startClientRegistryDCR starts a standalone client-registry-service with
// CLIENT_REGISTRATION_BASE_URL set to its own freshly-allocated address —
// required for the RFC 7591 /register and RFC 7592 /register/{client_id}
// routes to be registered at all (see registrationServiceProvider's nil
// return when unset). The registration_client_uri each /register response
// carries is built from this same base URL, so it must be self-referential
// like the metadata topology's AUTH_METADATA_PUBLIC_BASE_URL.
func startClientRegistryDCR(ctx context.Context, world *support.World) error {
	port, err := support.FreePort()
	if err != nil {
		return err
	}
	bin, err := support.BuildBinary("client-registry-service")
	if err != nil {
		return err
	}
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	clientRegistry, err := support.StartService(ctx, "client-registry-service", bin, port, []string{
		"CLIENT_SERVER_PORT=" + strconv.Itoa(port),
		"CLIENT_REGISTRATION_BASE_URL=" + baseURL,
	})
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry
	return nil
}

// loginUIServiceToken is the pre-shared bearer secret authorization_code_
// steps.go and oidc_core_steps.go present to auth-server's POST
// /internal/issue-code — the endpoint login-ui would call after a real
// sign-in (ADR-0011). This suite bypasses login-ui entirely and calls
// issue-code directly, so AUTH_LOGIN_UI_URL is never actually
// dereferenced by anything in this topology — its only effect is
// unlocking /oauth/authorize and /internal/issue-code (both 501/404 when
// unset), which is harmless for every other feature using this topology
// since none of them call those two endpoints.
const loginUIServiceToken = "acceptance-test-login-ui-service-token"

// startAuthServer starts auth-server. extraEnv is appended after the base
// env, so a caller wiring a rotation keyset (see startAuthServerRotatingKeys)
// or OIDC (see startAuthClientRegistryOIDC) can add to it without every
// other caller needing to know about those signals.
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

// oidcIssuer is the AUTH_JWT_OIDC_ISSUER value every OIDC-enabled auth-server
// instance in this suite uses. A shared constant is safe here — it never
// needs to be unique per scenario, it just needs to be non-empty and RS256
// mode active for idTokenGeneratorProvider to wire the id-token generator
// and the /userinfo route (see container.go).
const oidcIssuer = "https://acceptance-test.identity-platform.local"

// startAuthClientRegistryOIDC starts auth-server + client-registry-service
// with OIDC enabled (AUTH_JWT_OIDC_ISSUER set) but no identity-service —
// AUTH_IDENTITY_SERVICE_URL stays unset, so /userinfo's claims fetcher is
// nil and every /userinfo call 503s. That's the correct topology for
// scenarios about id_token issuance itself and about /userinfo's
// auth/scope checks, which don't need real claims.
func startAuthClientRegistryOIDC(ctx context.Context, world *support.World) error {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	authServer, err := startAuthServer(ctx, clientRegistry.BaseURL,
		"AUTH_JWT_OIDC_ISSUER="+oidcIssuer,
	)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

// startAuthClientRegistryIdentityOIDC layers identity-service on top of
// startAuthClientRegistryOIDC's topology, pointing AUTH_IDENTITY_SERVICE_URL
// at it so /userinfo's claims fetcher is live — for the scenario proving a
// real end-to-end claims round trip.
func startAuthClientRegistryIdentityOIDC(ctx context.Context, world *support.World) error {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	identity, err := startIdentityService(ctx)
	if err != nil {
		return err
	}
	world.Services["identity-service"] = identity

	authServer, err := startAuthServer(ctx, clientRegistry.BaseURL,
		"AUTH_JWT_OIDC_ISSUER="+oidcIssuer,
		"AUTH_IDENTITY_SERVICE_URL="+identity.BaseURL,
	)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

// startAuthServerMetadata starts a standalone auth-server (no
// client-registry-service — the metadata document doesn't depend on any
// registered client) with AUTH_METADATA_PUBLIC_BASE_URL set to its own
// freshly-allocated address, since RFC 8414 endpoint URLs are absolute and
// self-referential. extraEnv layers on the optional signals
// (AUTH_JWT_OIDC_ISSUER, AUTH_IDENTITY_SERVICE_URL, AUTH_LOGIN_UI_URL,
// AUTH_METADATA_REGISTRATION_ENDPOINT) that make additional metadata
// fields appear.
func startAuthServerMetadata(ctx context.Context, extraEnv ...string) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("auth-server")
	if err != nil {
		return nil, err
	}
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	env := append([]string{
		"AUTH_SERVER_PORT=" + strconv.Itoa(port),
		"AUTH_METADATA_PUBLIC_BASE_URL=" + baseURL,
	}, extraEnv...)
	return support.StartService(ctx, "auth-server", bin, port, env)
}

// startAuthMetadataOnly starts auth-server with only AUTH_METADATA_PUBLIC_BASE_URL
// set — the minimal config that populates the RFC 8414 document's required
// fields (issuer, authorization_endpoint, token_endpoint, jwks_uri — RS256
// is the default signing alg) while leaving every OIDC-only field absent.
func startAuthMetadataOnly(ctx context.Context, world *support.World) error {
	authServer, err := startAuthServerMetadata(ctx)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

// startAuthMetadataFull layers identity-service, OIDC, login-ui, and a
// registration_endpoint on top of startAuthMetadataOnly's topology — for
// scenarios asserting the OIDC discovery document's optional fields
// (userinfo_endpoint, end_session_endpoint, registration_endpoint) appear.
func startAuthMetadataFull(ctx context.Context, world *support.World) error {
	identity, err := startIdentityService(ctx)
	if err != nil {
		return err
	}
	world.Services["identity-service"] = identity

	authServer, err := startAuthServerMetadata(ctx,
		"AUTH_LOGIN_UI_URL=http://127.0.0.1:1",
		"AUTH_JWT_OIDC_ISSUER="+oidcIssuer,
		"AUTH_IDENTITY_SERVICE_URL="+identity.BaseURL,
		"AUTH_METADATA_REGISTRATION_ENDPOINT=https://clients.example.com/register",
	)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

func startIdentityService(ctx context.Context) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("identity-service")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "identity-service", bin, port, []string{
		"IDENTITY_SERVER_PORT=" + strconv.Itoa(port),
	})
}

// startAuthClientRegistryShortChallengeTTL is startAuthAndClientRegistryServices
// with a 1-second login-challenge TTL, so a scenario can observe real expiry
// (ADR-0011) by sleeping just past it rather than waiting out the 300-second
// production default. The memory adapter enforces expiry itself on every
// Get/Consume call — no Redis container is needed to see this behavior.
func startAuthClientRegistryShortChallengeTTL(ctx context.Context, world *support.World) error {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	authServer, err := startAuthServer(ctx, clientRegistry.BaseURL, "AUTH_LOGIN_CHALLENGE_TTL_SECONDS=1")
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

// loginUIAuthServerServiceToken is the pre-shared bearer secret login-ui
// itself presents to auth-server's POST /internal/issue-code in the real
// end-to-end topology below. Distinct from loginUIServiceToken (which
// every other topology's bypass-and-call-issue-code-directly steps
// present) purely to keep the two paths from being confused when reading
// this file — the value has no special meaning.
const loginUIAuthServerServiceToken = "acceptance-test-login-ui-e2e-service-token"

// startLoginChallengeHandoffE2E starts the full real ADR-0011 chain:
// identity-service (real user sign-in), client-registry-service,
// auth-server (with AUTH_LOGIN_UI_URL pointing at the real login-ui
// started here, not the dummy unreachable URL every other topology
// uses), and login-ui itself. Every other feature bypasses login-ui by
// calling /internal/issue-code directly — this topology exists
// specifically to prove the real /oauth/authorize → login-ui /sign-in →
// /internal/issue-code chain works end-to-end, since that chain is
// exactly what the bypass pattern cannot catch a regression in.
func startLoginChallengeHandoffE2E(ctx context.Context, world *support.World) error {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	identity, err := startIdentityService(ctx)
	if err != nil {
		return err
	}
	world.Services["identity-service"] = identity

	authServerPort, loginUIPort, err := freePortPair()
	if err != nil {
		return err
	}
	loginUIBaseURL := "http://127.0.0.1:" + strconv.Itoa(loginUIPort)

	authServer, err := startAuthServerForHandoffE2E(ctx, authServerPort, clientRegistry.BaseURL, loginUIBaseURL)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer

	loginUI, err := startLoginUIForHandoffE2E(ctx, loginUIPort, identity.BaseURL, authServer.BaseURL)
	if err != nil {
		return err
	}
	world.Services["login-ui"] = loginUI
	return nil
}

func freePortPair() (int, int, error) {
	a, err := support.FreePort()
	if err != nil {
		return 0, 0, err
	}
	b, err := support.FreePort()
	if err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

func startAuthServerForHandoffE2E(ctx context.Context, port int, clientRegistryURL, loginUIBaseURL string) (*support.RunningService, error) {
	bin, err := support.BuildBinary("auth-server")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "auth-server", bin, port, []string{
		"AUTH_SERVER_PORT=" + strconv.Itoa(port),
		"AUTH_CLIENT_REGISTRY_URL=" + clientRegistryURL,
		"AUTH_LOGIN_UI_URL=" + loginUIBaseURL,
		"AUTH_LOGIN_UI_SERVICE_TOKEN=" + loginUIAuthServerServiceToken,
	})
}

func startLoginUIForHandoffE2E(ctx context.Context, port int, identityServiceURL, authServerURL string) (*support.RunningService, error) {
	bin, err := support.BuildBinary("login-ui")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "login-ui", bin, port, []string{
		"LOGIN_UI_SERVER_PORT=" + strconv.Itoa(port),
		"LOGIN_UI_IDENTITY_SERVICE_URL=" + identityServiceURL,
		"LOGIN_UI_AUTH_SERVER_URL=" + authServerURL,
		"LOGIN_UI_AUTH_SERVER_SERVICE_TOKEN=" + loginUIAuthServerServiceToken,
	})
}
