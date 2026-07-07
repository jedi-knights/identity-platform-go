package steps

import (
	"encoding/json"
	"fmt"

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

	sctx.Step(`^the response header "([^"]*)" is "([^"]*)"$`, func(header, want string) error {
		return stepAssertHeader(world(), header, want)
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

func stepAssertHeader(world *support.World, header, want string) error {
	got := world.LastResponse.Header.Get(header)
	if got != want {
		return fmt.Errorf("header %q: want %q, got %q", header, want, got)
	}
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
