package steps

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// registerStepUpAuthenticationSteps wires the RFC 9470 (ADR-0024) steps —
// only the /oauth/authorize acr_values query param is feature-specific;
// everything downstream (login-ui sign-in, code exchange, introspection,
// generic field assertions) reuses steps already registered by
// registerLoginChallengeHandoffSteps, registerAuthorizationCodeSteps,
// registerRevocationSteps, and registerCommonSteps.
func registerStepUpAuthenticationSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client starts an authorization_code flow with redirect_uri "([^"]*)", scope "([^"]*)", and acr_values "([^"]*)"$`,
		func(ctx context.Context, redirectURI, scope, acrValues string) error {
			return stepStartAuthorizeWithAcrValues(ctx, world(), redirectURI, scope, acrValues)
		})
}

// stepStartAuthorizeWithAcrValues is stepStartAuthorize
// (authorization_code_steps.go) with an acr_values query param added —
// kept as its own function rather than adding an optional parameter to
// the shared helper, mirroring stepStartAuthorizeWithRAR's precedent
// (rich_authorization_requests_steps.go) for the same reason: only this
// feature needs it, and every other authorization_code caller should
// stay untouched.
func stepStartAuthorizeWithAcrValues(ctx context.Context, world *support.World, redirectURI, scope, acrValues string) error {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {world.Vars["client_id"]},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {support.RandomID("state")},
		"code_challenge":        {world.Vars["code_challenge"]},
		"code_challenge_method": {"S256"},
		"acr_values":            {acrValues},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		world.Services["auth-server"].BaseURL+"/oauth/authorize?"+q.Encode(), nil)
	if err != nil {
		return err
	}

	noRedirectClient := &http.Client{
		Timeout: world.HTTPClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirectClient.Do(req)
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
