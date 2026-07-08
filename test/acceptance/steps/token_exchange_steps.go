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

func registerTokenExchangeSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client's registration is captured as "([^"]*)"$`, func(role string) error {
		w := world()
		w.Vars[role+"_client_id"] = w.Vars["client_id"]
		w.Vars[role+"_client_secret"] = w.Vars["client_secret"]
		return nil
	})

	sctx.Step(`^a registered public OAuth client with grant type "([^"]*)"$`, func(ctx context.Context, grantType string) error {
		return stepRegisterPublicClient(ctx, world(), grantType)
	})

	sctx.Step(`^the client exchanges the "([^"]*)" for a new access_token$`, func(ctx context.Context, subjectVar string) error {
		w := world()
		return postTokenExchange(ctx, w, exchangeParams{
			clientID:     w.Vars["client_id"],
			clientSecret: w.Vars["client_secret"],
			subjectToken: w.Vars[subjectVar],
		})
	})

	sctx.Step(`^the client exchanges the "([^"]*)" for a new access_token with scope "([^"]*)"$`,
		func(ctx context.Context, subjectVar, scope string) error {
			w := world()
			return postTokenExchange(ctx, w, exchangeParams{
				clientID:     w.Vars["client_id"],
				clientSecret: w.Vars["client_secret"],
				subjectToken: w.Vars[subjectVar],
				scope:        scope,
			})
		})

	sctx.Step(`^the client authenticating as "([^"]*)" exchanges "([^"]*)" using "([^"]*)" as actor$`,
		func(ctx context.Context, role, subjectVar, actorVar string) error {
			w := world()
			return postTokenExchange(ctx, w, exchangeParams{
				clientID:     w.Vars[role+"_client_id"],
				clientSecret: w.Vars[role+"_client_secret"],
				subjectToken: w.Vars[subjectVar],
				actorToken:   w.Vars[actorVar],
			})
		})

	sctx.Step(`^the client exchanges a token with subject_token_type "([^"]*)"$`, func(ctx context.Context, subjectTokenType string) error {
		w := world()
		return postTokenExchange(ctx, w, exchangeParams{
			clientID:         w.Vars["client_id"],
			clientSecret:     w.Vars["client_secret"],
			subjectToken:     "irrelevant-for-this-check",
			subjectTokenType: subjectTokenType,
		})
	})

	sctx.Step(`^the client exchanges the "([^"]*)" requesting token type "([^"]*)"$`,
		func(ctx context.Context, subjectVar, requestedTokenType string) error {
			w := world()
			return postTokenExchange(ctx, w, exchangeParams{
				clientID:           w.Vars["client_id"],
				clientSecret:       w.Vars["client_secret"],
				subjectToken:       w.Vars[subjectVar],
				requestedTokenType: requestedTokenType,
			})
		})

}

// stepRegisterPublicClient calls client-registry-service's POST /clients
// with client_type "public" — token exchange's assertCanExchange applies
// an ownership restriction to public clients that confidential clients
// never hit, so this feature needs a public-client registration path the
// shared registerClient helper (always "confidential") doesn't cover.
func stepRegisterPublicClient(ctx context.Context, world *support.World, grantType string) error {
	body := map[string]any{
		"name":        support.RandomID("acceptance-public-client"),
		"client_type": "public",
		"grant_types": strings.Split(grantType, ","),
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
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return fmt.Errorf("decoding create-client response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create-client: want 201, got %d", resp.StatusCode)
	}

	world.Vars["client_id"] = created.ClientID
	world.Vars["client_secret"] = ""
	return nil
}

// exchangeParams holds the RFC 8693 §2.1 request fields postTokenExchange
// sends. Fields left empty are omitted from the form entirely, matching
// how a real client would only send parameters it has a value for.
type exchangeParams struct {
	clientID           string
	clientSecret       string
	subjectToken       string
	subjectTokenType   string
	actorToken         string
	requestedTokenType string
	scope              string
}

// postTokenExchange posts the urn:ietf:params:oauth:grant-type:token-exchange
// grant to auth-server's /oauth/token. subjectTokenType defaults to the
// only type this server accepts (access_token) when the caller doesn't
// override it, since every scenario except the unsupported-type ones
// wants the happy-path default.
func postTokenExchange(ctx context.Context, world *support.World, p exchangeParams) error {
	subjectTokenType := p.subjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {p.clientID},
		"subject_token":      {p.subjectToken},
		"subject_token_type": {subjectTokenType},
	}
	if p.clientSecret != "" {
		form.Set("client_secret", p.clientSecret)
	}
	if p.actorToken != "" {
		form.Set("actor_token", p.actorToken)
		form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	}
	if p.requestedTokenType != "" {
		form.Set("requested_token_type", p.requestedTokenType)
	}
	if p.scope != "" {
		form.Set("scope", p.scope)
	}
	return postToken(ctx, world, form)
}
