package steps

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

func registerAuthorizationCodeSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^a registered confidential OAuth client with scopes "([^"]*)", grant type "([^"]*)", and redirect_uri "([^"]*)"$`,
		func(ctx context.Context, scopes, grantType, redirectURI string) error {
			w := world()
			if err := registerClient(ctx, w, scopes, grantType, []string{redirectURI}); err != nil {
				return err
			}
			w.Vars["redirect_uri"] = redirectURI
			return nil
		})

	sctx.Step(`^the client generates a PKCE code_verifier and code_challenge$`, func() error {
		return stepGeneratePKCE(world())
	})

	sctx.Step(`^the client starts an authorization_code flow with redirect_uri "([^"]*)" and scope "([^"]*)"$`,
		func(ctx context.Context, redirectURI, scope string) error {
			return stepStartAuthorize(ctx, world(), redirectURI, scope)
		})

	sctx.Step(`^the login_challenge is captured from the redirect$`, func() error {
		return stepCaptureLoginChallenge(world())
	})

	sctx.Step(`^login-ui issues an authorization code for the login_challenge with consent "([^"]*)"$`,
		func(ctx context.Context, consent string) error {
			return stepIssueCode(ctx, world(), consent)
		})

	sctx.Step(`^the client exchanges the authorization code for a token$`, func(ctx context.Context) error {
		w := world()
		return stepExchangeCode(ctx, w, w.Vars["code"], w.Vars["code_verifier"])
	})

	sctx.Step(`^the client exchanges the authorization code for a token with an incorrect code_verifier$`,
		func(ctx context.Context) error {
			w := world()
			return stepExchangeCode(ctx, w, w.Vars["code"], "incorrect-"+w.Vars["code_verifier"])
		})
}

// stepGeneratePKCE generates an RFC 7636 §4.1-compliant code_verifier (43
// base64url characters from 32 random bytes, well within the 43-128
// length bound) and its S256 code_challenge, storing both in world.Vars.
func stepGeneratePKCE(world *support.World) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generating PKCE verifier entropy: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	world.Vars["code_verifier"] = verifier
	world.Vars["code_challenge"] = challenge
	return nil
}

// stepStartAuthorize calls auth-server's GET /oauth/authorize without
// following the redirect, so both the success path (302 to login-ui with
// a login_challenge) and the direct-render error path (400 for an
// unregistered redirect_uri) land in world.LastResponse/LastBody exactly
// as the real HTTP response, for the generic common_steps assertions to
// check.
func stepStartAuthorize(ctx context.Context, world *support.World, redirectURI, scope string) error {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {world.Vars["client_id"]},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {support.RandomID("state")},
		"code_challenge":        {world.Vars["code_challenge"]},
		"code_challenge_method": {"S256"},
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

// stepCaptureLoginChallenge parses the login_challenge query parameter
// out of the Location header stepStartAuthorize's redirect response
// carries, storing it in world.Vars for the issue-code step.
func stepCaptureLoginChallenge(world *support.World) error {
	location := world.LastResponse.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("no Location header on last response (status %d) — body: %s", world.LastResponse.StatusCode, world.LastBody)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("parsing Location header %q: %w", location, err)
	}
	challenge := parsed.Query().Get("login_challenge")
	if challenge == "" {
		return fmt.Errorf("location header %q has no login_challenge query parameter", location)
	}
	world.Vars["login_challenge"] = challenge
	return nil
}

// stepIssueCode calls auth-server's bearer-authed POST /internal/issue-code
// — the endpoint login-ui would call after a real sign-in — simulating a
// successful sign-in directly rather than running login-ui and
// identity-service (that handoff mechanic is login_challenge_handoff.feature's
// job; this feature is about the authorization_code + PKCE grant itself).
func stepIssueCode(ctx context.Context, world *support.World, consent string) error {
	body := map[string]any{
		"login_challenge": world.Vars["login_challenge"],
		"session_id":      support.RandomID("subject"),
		"consent_granted": strings.Fields(consent),
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["auth-server"].BaseURL+"/internal/issue-code", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginUIServiceToken)

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	world.LastResponse = resp
	world.LastBody = respBody

	if resp.StatusCode != http.StatusOK {
		return nil // let the scenario's own "Then" steps assert on the error
	}

	var decoded struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return fmt.Errorf("decoding issue-code response: %w — body: %s", err, respBody)
	}
	world.Vars["code"] = decoded.Code
	world.Vars["issued_redirect_uri"] = decoded.RedirectURI
	return nil
}

// stepExchangeCode posts the authorization_code grant to auth-server's
// /oauth/token, using the redirect_uri the client originally registered
// (and presented at /oauth/authorize) — RFC 6749 §4.1.3 requires it be
// presented again and matched byte-exact against the value stored with
// the code.
func stepExchangeCode(ctx context.Context, world *support.World, code, codeVerifier string) error {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {world.Vars["redirect_uri"]},
		"client_id":     {world.Vars["client_id"]},
		"client_secret": {world.Vars["client_secret"]},
	}
	return postToken(ctx, world, form)
}
