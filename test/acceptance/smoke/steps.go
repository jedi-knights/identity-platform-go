package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cucumber/godog"
)

// InitializeTestSuite is a no-op — unlike the main acceptance suite, the
// smoke suite starts nothing itself (no testcontainers, no subprocess
// binaries). `task test:smoke` brings the real docker-compose stack up
// before running this binary and tears it down after, so there is no
// suite-level setup/teardown to hook here.
func InitializeTestSuite(_ *godog.TestSuiteContext) {}

// InitializeScenario registers every step against one smokeWorld shared
// across the whole suite run — see smokeWorld's doc comment for why a
// single shared instance is safe here, unlike the main suite's
// per-scenario World.
func InitializeScenario(sctx *godog.ScenarioContext) {
	world := newSmokeWorld()

	sctx.Step(`^([a-z-]+) is healthy$`, func(ctx context.Context, service string) error {
		return stepHealthCheck(ctx, world, service)
	})

	sctx.Step(`^the seeded test-client requests a token using the client_credentials grant with scope "([^"]*)"$`,
		func(ctx context.Context, scope string) error {
			return stepRequestToken(ctx, world, scope)
		})

	sctx.Step(`^auth-server issues a token$`, func(ctx context.Context) error {
		return stepRequestToken(ctx, world, "read")
	})

	sctx.Step(`^the response status is (\d+)$`, func(want int) error {
		return stepAssertStatus(world, want)
	})

	sctx.Step(`^the response has a non-empty "([^"]*)"$`, func(field string) error {
		return stepAssertNonEmpty(world, field)
	})

	sctx.Step(`^the "([^"]*)" from the last response is captured as "([^"]*)"$`, func(field, key string) error {
		return stepCaptureField(world, field, key)
	})

	sctx.Step(`^the client introspects the access_token via auth-server$`, func(ctx context.Context) error {
		return stepIntrospect(ctx, world, world.Vars["access_token"])
	})

	sctx.Step(`^the response "([^"]*)" is (true|false)$`, func(field, want string) error {
		return stepAssertBoolField(world, field, want == "true")
	})

	sctx.Step(`^the client revokes the access_token via auth-server$`, func(ctx context.Context) error {
		return stepRevoke(ctx, world, world.Vars["access_token"])
	})

	sctx.Step(`^the client fetches auth-server's JWKS document$`, func(ctx context.Context) error {
		return stepFetchJWKS(ctx, world)
	})

	sctx.Step(`^the response "([^"]*)" array is non-empty$`, func(field string) error {
		return stepAssertArrayNonEmpty(world, field)
	})

	sctx.Step(`^at least one key in the "([^"]*)" array has "([^"]*)" "([^"]*)"$`,
		func(arrayField, keyField, want string) error {
			return stepAssertArrayItemFieldEquals(world, arrayField, keyField, want)
		})
}

// serviceURLs maps the step-text service name to its base URL, resolved
// from smokeWorld — used only by stepHealthCheck, which is the one step
// parameterized across every service.
func serviceURLs(world *smokeWorld) map[string]string {
	return map[string]string{
		"auth-server":                  world.AuthServerURL,
		"identity-service":             world.IdentityServiceURL,
		"client-registry-service":      world.ClientRegistryURL,
		"login-ui":                     world.LoginUIURL,
		"token-introspection-service":  world.TokenIntrospectionURL,
		"authorization-policy-service": world.AuthorizationPolicyURL,
		"example-resource-service":     world.ExampleResourceURL,
	}
}

func stepHealthCheck(ctx context.Context, world *smokeWorld, service string) error {
	base, ok := serviceURLs(world)[service]
	if !ok {
		return fmt.Errorf("unknown service %q — not in serviceURLs", service)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", service, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s /health: want 200, got %d — body: %s", service, resp.StatusCode, body)
	}
	return nil
}

// devClientSecret returns the dev-seed client's secret — generated fresh
// per `task test:smoke` run and passed through via SMOKE_DEV_CLIENT_SECRET,
// never a hardcoded value, since it's a real credential the real
// auth-server image is configured with.
func devClientSecret() string {
	return os.Getenv("SMOKE_DEV_CLIENT_SECRET")
}

// stepRequestToken exercises the plan's "one representative scenario":
// the seeded test-client obtains a client_credentials token from the
// real auth-server image, which itself calls the real
// client-registry-service image to validate the client — over the
// actual compose network, not a subprocess or httptest.Server.
func stepRequestToken(ctx context.Context, world *smokeWorld, scope string) error {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {devClientSecret()},
		"scope":         {scope},
	}
	return postForm(ctx, world, world.AuthServerURL+"/oauth/token", form)
}

func stepIntrospect(ctx context.Context, world *smokeWorld, token string) error {
	form := url.Values{
		"token":         {token},
		"client_id":     {"test-client"},
		"client_secret": {devClientSecret()},
	}
	return postForm(ctx, world, world.AuthServerURL+"/oauth/introspect", form)
}

func stepRevoke(ctx context.Context, world *smokeWorld, token string) error {
	form := url.Values{
		"token":         {token},
		"client_id":     {"test-client"},
		"client_secret": {devClientSecret()},
	}
	return postForm(ctx, world, world.AuthServerURL+"/oauth/revoke", form)
}

func stepFetchJWKS(ctx context.Context, world *smokeWorld) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, world.AuthServerURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return err
	}
	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling auth-server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	world.LastResponse = resp
	world.LastBody = body
	return nil
}

func postForm(ctx context.Context, world *smokeWorld, targetURL string, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", targetURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	world.LastResponse = resp
	world.LastBody = body
	return nil
}

func stepAssertStatus(world *smokeWorld, want int) error {
	if world.LastResponse.StatusCode != want {
		return fmt.Errorf("status: want %d, got %d — body: %s", want, world.LastResponse.StatusCode, world.LastBody)
	}
	return nil
}

func stepAssertNonEmpty(world *smokeWorld, field string) error {
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

func stepAssertBoolField(world *smokeWorld, field string, want bool) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	got, ok := decoded[field].(bool)
	if !ok {
		return fmt.Errorf("field %q: want bool, got %v — body: %s", field, decoded[field], world.LastBody)
	}
	if got != want {
		return fmt.Errorf("field %q: want %v, got %v", field, want, got)
	}
	return nil
}

func stepAssertArrayNonEmpty(world *smokeWorld, field string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	items, ok := decoded[field].([]any)
	if !ok || len(items) == 0 {
		return fmt.Errorf("field %q: want non-empty array, got %v — body: %s", field, decoded[field], world.LastBody)
	}
	return nil
}

func stepAssertArrayItemFieldEquals(world *smokeWorld, arrayField, keyField, want string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	items, ok := decoded[arrayField].([]any)
	if !ok {
		return fmt.Errorf("field %q: want array, got %v — body: %s", arrayField, decoded[arrayField], world.LastBody)
	}
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := obj[keyField].(string); got == want {
			return nil
		}
	}
	return fmt.Errorf("no item in %q has %q = %q — body: %s", arrayField, keyField, want, world.LastBody)
}

func stepCaptureField(world *smokeWorld, field, key string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	v, ok := decoded[field].(string)
	if !ok || v == "" {
		return fmt.Errorf("field %q not present or empty in response: %s", field, world.LastBody)
	}
	world.Vars[key] = v
	return nil
}
