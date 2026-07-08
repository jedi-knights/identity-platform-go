package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// registerCommonSteps wires the generic HTTP-response assertions every
// feature file reuses — status code, field presence/value, header value.
// Grant-specific "Given"/"When" steps live in their own per-feature files.
func registerCommonSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the response status is (\d+)$`, func(want int) error {
		return stepAssertStatus(world(), want)
	})

	sctx.Step(`^the response has a non-empty "([^"]*)"$`, func(field string) error {
		return stepAssertNonEmpty(world(), field)
	})

	sctx.Step(`^the response "([^"]*)" is "([^"]*)"$`, func(field, want string) error {
		return stepAssertField(world(), field, want)
	})

	// The wanted value uses a greedy (.+) rather than [^"]* — header values
	// like WWW-Authenticate legitimately contain embedded double quotes
	// (Bearer realm="..."), and Gherkin step text is not escape-aware, so
	// the feature file writes them as literal unescaped quotes. Greedy
	// backtracking correctly finds the *last* quote before end-of-line as
	// the closing delimiter instead of stopping at the first embedded one.
	sctx.Step(`^the response header "([^"]*)" is "(.+)"$`, func(header, want string) error {
		return stepAssertHeader(world(), header, want)
	})

	sctx.Step(`^the response "([^"]*)" is (true|false)$`, func(field, want string) error {
		return stepAssertBoolField(world(), field, want == "true")
	})

	sctx.Step(`^the "([^"]*)" from the last response is captured as "([^"]*)"$`, func(field, key string) error {
		return captureField(world(), field, key)
	})

	sctx.Step(`^the response does not have a "([^"]*)" field$`, func(field string) error {
		return stepAssertFieldAbsent(world(), field)
	})

	sctx.Step(`^the response "([^"]*)" array contains "([^"]*)"$`, func(field, want string) error {
		return stepAssertArrayContains(world(), field, want)
	})

	sctx.Step(`^the client sends a GET request to "([^"]*)"$`, func(ctx context.Context, path string) error {
		return stepGetPath(ctx, world(), path)
	})
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

func stepAssertBoolField(world *support.World, field string, want bool) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	got, ok := decoded[field].(bool)
	if !ok {
		return fmt.Errorf("field %q: want bool, got %v (body: %s)", field, decoded[field], world.LastBody)
	}
	if got != want {
		return fmt.Errorf("field %q: want %v, got %v", field, want, got)
	}
	return nil
}

func stepAssertFieldAbsent(world *support.World, field string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	if v, ok := decoded[field]; ok {
		return fmt.Errorf("field %q: want absent, got %v — body: %s", field, v, world.LastBody)
	}
	return nil
}

func stepAssertArrayContains(world *support.World, field, want string) error {
	var decoded map[string]any
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	items, ok := decoded[field].([]any)
	if !ok {
		return fmt.Errorf("field %q: want array, got %v — body: %s", field, decoded[field], world.LastBody)
	}
	for _, item := range items {
		if s, ok := item.(string); ok && s == want {
			return nil
		}
	}
	return fmt.Errorf("field %q: %q not found in %v — body: %s", field, want, items, world.LastBody)
}

func stepAssertHeader(world *support.World, header, want string) error {
	got := world.LastResponse.Header.Get(header)
	if got != want {
		return fmt.Errorf("header %q: want %q, got %q", header, want, got)
	}
	return nil
}

// postForm posts form to the given path on auth-server and stores the
// response for later "Then" assertions. Shared by every auth-server
// endpoint step file (token, revoke, introspect, ...).
func postForm(ctx context.Context, world *support.World, path string, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["auth-server"].BaseURL+path, strings.NewReader(form.Encode()))
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

// stepGetPath sends an unauthenticated GET to the given path on auth-server
// and stores the response for later "Then" assertions — used by endpoints
// that don't take a body (JWKS, metadata, userinfo-without-token).
func stepGetPath(ctx context.Context, world *support.World, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		world.Services["auth-server"].BaseURL+path, nil)
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

// captureField stashes a string field from the last response body into
// world.Vars under key, for later steps to reference (e.g. capturing
// refresh_token from a client_credentials response to use in a
// subsequent refresh_token grant request).
func captureField(world *support.World, field, key string) error {
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
