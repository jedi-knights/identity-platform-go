package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerClientCredentialsSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^a registered confidential OAuth client with scopes "([^"]*)" and grant type "([^"]*)"$`,
		func(ctx context.Context, scopes, grantType string) error {
			return stepRegisterClient(ctx, world(), scopes, grantType)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with scope "([^"]*)"$`,
		func(ctx context.Context, scope string) error {
			w := world()
			return stepRequestClientCredentialsToken(ctx, w, w.Vars["client_secret"], scope)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with client_secret "([^"]*)" and scope "([^"]*)"$`,
		func(ctx context.Context, clientSecret, scope string) error {
			return stepRequestClientCredentialsToken(ctx, world(), clientSecret, scope)
		})
}

// stepRegisterClient calls client-registry-service's POST /clients and
// captures the returned client_id/client_secret into world.Vars. Always
// mints a fresh random name+ID via support.RandomID — never a hardcoded
// fixture — per World's isolation contract.
func stepRegisterClient(ctx context.Context, world *support.World, scopesStr, grantType string) error {
	return registerClient(ctx, world, scopesStr, grantType, nil)
}

// registerClient is stepRegisterClient generalized with an optional
// redirect_uris list, for grant types (authorization_code) that need one
// registered before /oauth/authorize will accept it.
func registerClient(ctx context.Context, world *support.World, scopesStr, grantType string, redirectURIs []string) error {
	body := map[string]any{
		"name":          support.RandomID("acceptance-client"),
		"client_type":   "confidential",
		"scopes":        strings.Fields(scopesStr),
		"grant_types":   strings.Split(grantType, ","),
		"redirect_uris": redirectURIs,
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
	return postToken(ctx, world, form)
}

// postToken posts form to auth-server's /oauth/token and stores the
// response for later "Then" assertions.
func postToken(ctx context.Context, world *support.World, form url.Values) error {
	return postForm(ctx, world, "/oauth/token", form)
}
