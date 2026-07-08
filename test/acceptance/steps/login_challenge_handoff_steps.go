package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerLoginChallengeHandoffSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^login-ui issues an authorization code for login_challenge "([^"]*)" with consent "([^"]*)"$`,
		func(ctx context.Context, loginChallenge, consent string) error {
			return stepIssueCodeRaw(ctx, world(), loginChallenge, support.RandomID("subject"), consent, loginUIServiceToken)
		})

	sctx.Step(`^login-ui issues an authorization code for the login_challenge without a valid bearer token$`,
		func(ctx context.Context) error {
			w := world()
			return stepIssueCodeRaw(ctx, w, w.Vars["login_challenge"], support.RandomID("subject"), "read", "not-the-real-token")
		})

	sctx.Step(`^(\d+) seconds pass$`, func(n int) error {
		time.Sleep(time.Duration(n) * time.Second)
		return nil
	})

	sctx.Step(`^a registered user in identity-service with email "([^"]*)" and password "([^"]*)"$`,
		func(ctx context.Context, email, password string) error {
			return stepRegisterHandoffUser(ctx, world(), email, password)
		})

	sctx.Step(`^the user signs in through login-ui with email "([^"]*)" and password "([^"]*)"$`,
		func(ctx context.Context, email, password string) error {
			return stepSignIn(ctx, world(), email, password)
		})

	sctx.Step(`^the redirect captures "code" and "state"$`, func() error {
		return stepCaptureCodeAndStateFromRedirect(world())
	})
}

// stepIssueCodeRaw posts to auth-server's POST /internal/issue-code with
// full control over every field, including a caller-chosen login_challenge
// (for the unknown/expired/replayed-challenge scenarios, which need a
// value the existing stepIssueCode helper — always world.Vars["login_challenge"]
// from a real /oauth/authorize call — can't supply) and bearer token (for
// the missing/wrong-bearer scenario).
func stepIssueCodeRaw(ctx context.Context, world *support.World, loginChallenge, sessionID, consent, bearerToken string) error {
	body := map[string]any{
		"login_challenge": loginChallenge,
		"session_id":      sessionID,
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
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

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
	return nil
}

// stepRegisterHandoffUser calls identity-service's POST /auth/register
// with the given email/password directly (not the random-email pattern
// registerClient uses for OAuth clients) — this scenario needs the exact
// email back to sign in through login-ui's real form.
func stepRegisterHandoffUser(ctx context.Context, world *support.World, email, password string) error {
	body := map[string]any{
		"email":    email,
		"password": password,
		"name":     "Handoff Test User",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["identity-service"].BaseURL+"/auth/register", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling identity-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register user: want 201, got %d — body: %s", resp.StatusCode, body)
	}
	return nil
}

// stepSignIn posts login-ui's real POST /sign-in form — the actual ADR-0011
// handoff this feature exists to prove works, as opposed to every other
// feature's direct call to auth-server's /internal/issue-code. Redirects
// are not followed so both the success path (302 back to the relying
// party with ?code=&state=) and the failure path (200, re-rendered form
// with an error message) land in world.LastResponse/LastBody exactly as
// the real HTTP response.
func stepSignIn(ctx context.Context, world *support.World, email, password string) error {
	form := url.Values{
		"login_challenge": {world.Vars["login_challenge"]},
		"email":           {email},
		"password":        {password},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["login-ui"].BaseURL+"/sign-in", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	noRedirectClient := &http.Client{
		Timeout: world.HTTPClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling login-ui: %w", err)
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

// stepCaptureCodeAndStateFromRedirect parses login-ui's redirect back to
// the relying party (?code=&state=) into world.Vars, so the existing
// authorization_code_steps.go exchange step (which reads world.Vars["code"])
// works unchanged against a code login-ui obtained, not one this suite's
// own bypass path obtained directly.
func stepCaptureCodeAndStateFromRedirect(world *support.World) error {
	location := world.LastResponse.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("no Location header on last response (status %d) — body: %s", world.LastResponse.StatusCode, world.LastBody)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("parsing Location header %q: %w", location, err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		return fmt.Errorf("location header %q has no code query parameter", location)
	}
	world.Vars["code"] = code
	world.Vars["state"] = parsed.Query().Get("state")
	return nil
}
