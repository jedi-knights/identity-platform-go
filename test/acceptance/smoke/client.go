package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// smokeClient is the OAuth client every scenario authenticates as. It is
// registered through client-registry-service's real API before the scenarios
// run, because the compose stack has no seeded client: auth-server delegates
// client authentication to client-registry-service whenever
// AUTH_CLIENT_REGISTRY_URL is set, and in that mode AUTH_DEV_SEED_CLIENTS is
// ignored.
var smokeClient struct {
	ID, Secret string
	Err        error // registration failure, reported by the first step that needs the client
}

// registrationTimeout bounds the one suite-level registration call.
const registrationTimeout = 15 * time.Second

// registerSmokeClient creates a confidential client_credentials client with
// the "read" scope and stores its credentials in smokeClient.
func registerSmokeClient(world *smokeWorld) {
	id, secret, err := createClient(world)
	smokeClient.ID, smokeClient.Secret, smokeClient.Err = id, secret, err
}

// createClient POSTs the registration and returns the issued credentials.
func createClient(world *smokeWorld) (id, secret string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), registrationTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]any{
		"name":        "smoke-test",
		"scopes":      []string{"read"},
		"grant_types": []string{"client_credentials"},
	})
	if err != nil {
		return "", "", fmt.Errorf("encoding client registration: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, world.ClientRegistryURL+"/clients", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("registering smoke client at %s: %w", world.ClientRegistryURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return parseRegistration(resp)
}

// parseRegistration extracts the credentials from a registration response.
func parseRegistration(resp *http.Response) (id, secret string, err error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("reading registration response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("registering smoke client: status %d — body: %s", resp.StatusCode, raw)
	}
	var created struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.ClientID == "" || created.ClientSecret == "" {
		return "", "", fmt.Errorf("registration response missing credentials: %s", raw)
	}
	return created.ClientID, created.ClientSecret, nil
}

// requireSmokeClient returns the registration error, if any.
func requireSmokeClient() error {
	return smokeClient.Err
}
