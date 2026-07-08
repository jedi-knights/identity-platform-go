package steps

import (
	"context"
	"encoding/base64"
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

	sctx.Step(`^the response body contains "([^"]*)"$`, func(want string) error {
		return stepAssertBodyContains(world(), want)
	})

	sctx.Step(`^the redirect Location's "([^"]*)" query parameter is "([^"]*)"$`, func(param, want string) error {
		return stepAssertRedirectQueryParam(world(), param, want)
	})

	sctx.Step(`^the "([^"]*)" JWT's "([^"]*)" claim equals the captured "([^"]*)"$`,
		func(jwtVar, claimPath, capturedVar string) error {
			return stepAssertJWTClaimEqualsCaptured(world(), jwtVar, claimPath, capturedVar)
		})

	sctx.Step(`^the "([^"]*)" JWT's "([^"]*)" claim equals "([^"]*)"$`,
		func(jwtVar, claimPath, want string) error {
			return stepAssertJWTClaimEquals(world(), jwtVar, claimPath, want)
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

// stepAssertBodyContains checks a raw substring of the response body —
// for HTML responses (login-ui's sign-in re-render on bad credentials)
// where there's no JSON field to inspect.
func stepAssertBodyContains(world *support.World, want string) error {
	if !strings.Contains(string(world.LastBody), want) {
		return fmt.Errorf("response body does not contain %q — body: %s", want, world.LastBody)
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

// stepAssertRedirectQueryParam checks one query parameter on the last
// response's Location header, without following the redirect — the
// generic form of the same check rich_authorization_requests_steps.go's
// stepAssertRedirectError hardcodes to the "error" parameter alone (e.g.
// RFC 9207's "iss").
func stepAssertRedirectQueryParam(world *support.World, param, want string) error {
	location := world.LastResponse.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("no Location header on last response (status %d) — body: %s", world.LastResponse.StatusCode, world.LastBody)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("parsing Location header %q: %w", location, err)
	}
	got := parsed.Query().Get(param)
	if got != want {
		return fmt.Errorf("redirect query %q: want %q, got %q — Location: %s", param, want, got, location)
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

// stepAssertJWTClaimEqualsCaptured decodes the JWT captured in
// world.Vars[jwtVar] and compares the claim at claimPath (dot-separated,
// e.g. "act.sub") against the plain string captured in
// world.Vars[capturedVar] — used to check a delegated token's sub/act
// claims against a client_id captured before the client that generated
// it got overwritten in world.Vars.
func stepAssertJWTClaimEqualsCaptured(world *support.World, jwtVar, claimPath, capturedVar string) error {
	want := world.Vars[capturedVar]
	if want == "" {
		return fmt.Errorf("captured var %q is empty — was it captured before being overwritten?", capturedVar)
	}
	return assertJWTClaimEquals(world, jwtVar, claimPath, want)
}

// stepAssertJWTClaimEquals is stepAssertJWTClaimEqualsCaptured's
// literal-value counterpart, for asserting against a fixed expected
// string written directly in the feature file rather than one captured
// from an earlier response — e.g. RFC 9068's `scope` claim, which is
// exactly the space-delimited string the request asked for.
func stepAssertJWTClaimEquals(world *support.World, jwtVar, claimPath, want string) error {
	return assertJWTClaimEquals(world, jwtVar, claimPath, want)
}

func assertJWTClaimEquals(world *support.World, jwtVar, claimPath, want string) error {
	payload, err := decodeJWTPayload(world.Vars[jwtVar])
	if err != nil {
		return fmt.Errorf("decoding %q: %w", jwtVar, err)
	}
	claim, err := walkClaimPath(payload, claimPath)
	if err != nil {
		return err
	}

	got, _ := claim.(string)
	if got != want {
		return fmt.Errorf("JWT claim %q: want %q, got %v — payload: %v", claimPath, want, claim, payload)
	}
	return nil
}

func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: want 3 dot-separated parts, got %d", len(parts))
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("unmarshalling payload: %w", err)
	}
	return payload, nil
}

// walkClaimPath descends a decoded JWT payload map along a dot-separated
// path (e.g. "act.sub"), returning an error that names the exact segment
// that failed rather than a generic not-found message.
func walkClaimPath(payload map[string]any, claimPath string) (any, error) {
	var cursor any = payload
	for _, key := range strings.Split(claimPath, ".") {
		m, ok := cursor.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("claim path %q: %q is not an object", claimPath, key)
		}
		cursor, ok = m[key]
		if !ok {
			return nil, fmt.Errorf("claim path %q: no %q key in payload: %v", claimPath, key, payload)
		}
	}
	return cursor, nil
}
