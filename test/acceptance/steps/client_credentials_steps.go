// Package steps contains godog step definitions, one file per feature
// area. Each file's Before/After hooks start exactly the service
// processes that feature needs — not the full platform — so scenarios
// stay fast. See support.World's doc comment for the isolation
// guarantees every step definition here must uphold: never hardcode a
// fixture ID, never share a World across scenarios.
package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// InitializeScenario registers every step definition and the Before/After
// hooks that start and stop this scenario's service processes. redisURL
// returns the shared suite-wide Redis container's connection string,
// resolved lazily since the container starts in TestSuiteInitializer
// after ScenarioInitializer has already registered this callback.
func InitializeScenario(sctx *godog.ScenarioContext, redisURL func() string) {
	var world *support.World

	sctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		world = support.NewWorld()
		if err := startClientCredentialsTopology(ctx, world, redisURL()); err != nil {
			return ctx, fmt.Errorf("starting service topology: %w", err)
		}
		return ctx, nil
	})

	sctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if world != nil {
			world.Close()
		}
		return ctx, nil
	})

	sctx.Step(`^a registered confidential OAuth client with scopes "([^"]*)" and grant type "([^"]*)"$`,
		func(ctx context.Context, scopes, grantType string) error {
			return stepRegisterClient(ctx, world, scopes, grantType)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with scope "([^"]*)"$`,
		func(ctx context.Context, scope string) error {
			return stepRequestClientCredentialsToken(ctx, world, world.Vars["client_secret"], scope)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with client_secret "([^"]*)" and scope "([^"]*)"$`,
		func(ctx context.Context, clientSecret, scope string) error {
			return stepRequestClientCredentialsToken(ctx, world, clientSecret, scope)
		})

	sctx.Step(`^the response status is (\d+)$`, func(want int) error {
		return stepAssertStatus(world, want)
	})

	sctx.Step(`^the response has a non-empty "([^"]*)"$`, func(field string) error {
		return stepAssertNonEmpty(world, field)
	})

	sctx.Step(`^the response "([^"]*)" is "([^"]*)"$`, func(field, want string) error {
		return stepAssertField(world, field, want)
	})

	sctx.Step(`^the response header "([^"]*)" is "([^"]*)"$`, func(header, want string) error {
		return stepAssertHeader(world, header, want)
	})
}

// startClientCredentialsTopology builds and starts auth-server and
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
func startClientCredentialsTopology(ctx context.Context, world *support.World, redisURL string) error {
	tempDir, err := os.MkdirTemp("", "acceptance-scenario-")
	if err != nil {
		return fmt.Errorf("creating scenario temp dir: %w", err)
	}
	world.TempDir = tempDir

	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	authServer, err := startAuthServer(ctx, clientRegistry.BaseURL)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer

	_ = redisURL // not needed for this feature; kept in the signature for the shared hook shape other feature files will use
	return nil
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

func startAuthServer(ctx context.Context, clientRegistryURL string) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("auth-server")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "auth-server", bin, port, []string{
		"AUTH_SERVER_PORT=" + strconv.Itoa(port),
		"AUTH_CLIENT_REGISTRY_URL=" + clientRegistryURL,
	})
}

// stepRegisterClient calls client-registry-service's POST /clients and
// captures the returned client_id/client_secret into world.Vars. Always
// mints a fresh random name+ID via support.RandomID — never a hardcoded
// fixture — per World's isolation contract.
func stepRegisterClient(ctx context.Context, world *support.World, scopesStr, grantType string) error {
	body := map[string]any{
		"name":        support.RandomID("acceptance-client"),
		"client_type": "confidential",
		"scopes":      strings.Fields(scopesStr),
		"grant_types": []string{grantType},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshalling create-client request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["client-registry-service"].BaseURL+"/clients", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling client-registry-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var created struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return fmt.Errorf("decoding create-client response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create-client: want 201, got %d", resp.StatusCode)
	}

	world.Vars["client_id"] = created.ClientID
	world.Vars["client_secret"] = created.ClientSecret
	return nil
}

// stepRequestClientCredentialsToken posts to auth-server's /oauth/token
// and stores the response for later "Then" assertions.
func stepRequestClientCredentialsToken(ctx context.Context, world *support.World, clientSecret, scope string) error {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {world.Vars["client_id"]},
		"client_secret": {clientSecret},
		"scope":         {scope},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["auth-server"].BaseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling auth-server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading auth-server response body: %w", err)
	}

	world.LastResponse = resp
	world.LastBody = body
	return nil
}

func stepAssertStatus(world *support.World, want int) error {
	if world.LastResponse.StatusCode != want {
		return fmt.Errorf("status: want %d, got %d — body: %s", want, world.LastResponse.StatusCode, world.LastBody)
	}
	return nil
}

func stepAssertNonEmpty(world *support.World, field string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	v, ok := decoded[field]
	if !ok {
		return fmt.Errorf("field %q not present in response: %s", field, world.LastBody)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return fmt.Errorf("field %q: want non-empty string, got %v", field, v)
	}
	return nil
}

func stepAssertField(world *support.World, field, want string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	got, _ := decoded[field].(string)
	if got != want {
		return fmt.Errorf("field %q: want %q, got %q — body: %s", field, want, got, world.LastBody)
	}
	return nil
}

func stepAssertHeader(world *support.World, header, want string) error {
	got := world.LastResponse.Header.Get(header)
	if got != want {
		return fmt.Errorf("header %q: want %q, got %q", header, want, got)
	}
	return nil
}
