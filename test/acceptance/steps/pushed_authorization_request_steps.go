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

func registerPushedAuthorizationRequestSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client pushes an authorization request with redirect_uri "([^"]*)" and scope "([^"]*)"$`,
		func(ctx context.Context, redirectURI, scope string) error {
			w := world()
			return postPAR(ctx, w, parParams{
				clientID:            w.Vars["client_id"],
				clientSecret:        w.Vars["client_secret"],
				redirectURI:         redirectURI,
				scope:               scope,
				codeChallenge:       w.Vars["code_challenge"],
				codeChallengeMethod: "S256",
			})
		})

	sctx.Step(`^the client pushes an authorization request with client_secret "([^"]*)", redirect_uri "([^"]*)", and scope "([^"]*)"$`,
		func(ctx context.Context, clientSecret, redirectURI, scope string) error {
			w := world()
			return postPAR(ctx, w, parParams{
				clientID:            w.Vars["client_id"],
				clientSecret:        clientSecret,
				redirectURI:         redirectURI,
				scope:               scope,
				codeChallenge:       w.Vars["code_challenge"],
				codeChallengeMethod: "S256",
			})
		})

	sctx.Step(`^the client pushes an authorization request without a code_challenge, redirect_uri "([^"]*)", and scope "([^"]*)"$`,
		func(ctx context.Context, redirectURI, scope string) error {
			w := world()
			return postPAR(ctx, w, parParams{
				clientID:     w.Vars["client_id"],
				clientSecret: w.Vars["client_secret"],
				redirectURI:  redirectURI,
				scope:        scope,
			})
		})

	sctx.Step(`^the client starts an authorization_code flow using the pushed request_uri$`, func(ctx context.Context) error {
		w := world()
		return stepStartAuthorizeWithRequestURI(ctx, w, w.Vars["request_uri"], w.Vars["client_id"])
	})

	sctx.Step(`^the client starts an authorization_code flow using request_uri "([^"]*)"$`, func(ctx context.Context, requestURI string) error {
		w := world()
		return stepStartAuthorizeWithRequestURI(ctx, w, requestURI, w.Vars["client_id"])
	})
}

// parParams holds POST /oauth/par's form fields. Fields left empty are
// omitted from the form entirely, matching how a real client would only
// send parameters it has a value for — this is what lets the
// "without a code_challenge" scenario actually omit it rather than send
// an empty string.
type parParams struct {
	clientID            string
	clientSecret        string
	redirectURI         string
	scope               string
	codeChallenge       string
	codeChallengeMethod string
}

// postPAR posts to auth-server's POST /oauth/par and stores the response
// for later "Then" assertions.
func postPAR(ctx context.Context, world *support.World, p parParams) error {
	form := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"redirect_uri":  {p.redirectURI},
		"scope":         {p.scope},
	}
	if p.codeChallenge != "" {
		form.Set("code_challenge", p.codeChallenge)
	}
	if p.codeChallengeMethod != "" {
		form.Set("code_challenge_method", p.codeChallengeMethod)
	}
	return postForm(ctx, world, "/oauth/par", form)
}

// stepStartAuthorizeWithRequestURI calls auth-server's GET /oauth/authorize
// with request_uri + client_id only (RFC 9126 §4) — no other authorize
// parameters, since a real client presenting a pushed request wouldn't
// send them either. Does not follow the redirect, mirroring
// stepStartAuthorize's rationale: both the success path (302 to login-ui)
// and the direct-render error path (400 for an unknown/mismatched
// request_uri) need to land in world.LastResponse/LastBody exactly as the
// real HTTP response.
func stepStartAuthorizeWithRequestURI(ctx context.Context, world *support.World, requestURI, clientID string) error {
	q := url.Values{
		"request_uri": {requestURI},
		"client_id":   {clientID},
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
