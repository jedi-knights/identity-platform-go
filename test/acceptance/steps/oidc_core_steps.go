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

func registerOIDCSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^a registered user in identity-service with email "([^"]*)" and name "([^"]*)"$`,
		func(ctx context.Context, email, name string) error {
			return stepRegisterOIDCUser(ctx, world(), email, name)
		})

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
		return stepOIDCGeneratePKCE(world())
	})

	sctx.Step(`^the client starts an authorization_code flow with redirect_uri "([^"]*)", scope "([^"]*)", and nonce "([^"]*)"$`,
		func(ctx context.Context, redirectURI, scope, nonce string) error {
			return stepOIDCStartAuthorize(ctx, world(), redirectURI, scope, nonce)
		})

	sctx.Step(`^the login_challenge is captured from the redirect$`, func() error {
		return stepOIDCCaptureLoginChallenge(world())
	})

	sctx.Step(`^login-ui issues an authorization code for the login_challenge for subject "([^"]*)" with consent "([^"]*)"$`,
		func(ctx context.Context, subject, consent string) error {
			return stepOIDCIssueCode(ctx, world(), subject, consent)
		})

	sctx.Step(`^login-ui issues an authorization code for the login_challenge for the registered user with consent "([^"]*)"$`,
		func(ctx context.Context, consent string) error {
			w := world()
			return stepOIDCIssueCode(ctx, w, w.Vars["user_id"], consent)
		})

	sctx.Step(`^the client exchanges the authorization code for a token$`, func(ctx context.Context) error {
		w := world()
		return stepOIDCExchangeCode(ctx, w, w.Vars["code"], w.Vars["code_verifier"])
	})

	sctx.Step(`^the client calls /userinfo with the access_token$`, func(ctx context.Context) error {
		w := world()
		return stepCallUserinfo(ctx, w, w.Vars["access_token"])
	})

	sctx.Step(`^the client calls /userinfo without an access_token$`, func(ctx context.Context) error {
		return stepCallUserinfo(ctx, world(), "")
	})

	sctx.Step(`^the id_token's "([^"]*)" claim is "([^"]*)"$`, func(claim, want string) error {
		return stepAssertIDTokenClaim(world(), claim, want)
	})
}

// stepRegisterOIDCUser calls identity-service's POST /auth/register and
// captures the returned user_id — used as the subject when issuing an
// authorization code, so /userinfo's identity-service-backed claims lookup
// resolves to a real user rather than the synthetic subject IDs every
// other acceptance feature uses.
func stepRegisterOIDCUser(ctx context.Context, world *support.World, email, name string) error {
	body := map[string]any{
		"email":    email,
		"password": "correct-horse-battery-staple-1",
		"name":     name,
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

	var decoded struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("decoding register response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register user: want 201, got %d", resp.StatusCode)
	}

	world.Vars["user_id"] = decoded.UserID
	world.Vars["user_email"] = decoded.Email
	world.Vars["user_name"] = decoded.Name
	return nil
}

// stepOIDCGeneratePKCE generates an RFC 7636 §4.1-compliant code_verifier
// and its S256 code_challenge — every authorization_code grant requires
// PKCE regardless of OIDC scope (ADR-0009), so OIDC scenarios need this
// exactly like authorization_code_pkce.feature does.
func stepOIDCGeneratePKCE(world *support.World) error {
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

// stepOIDCStartAuthorize calls auth-server's GET /oauth/authorize with a
// nonce query param (OIDC Core §3.1.2.1) in addition to the PKCE params
// every authorization_code request carries, without following the redirect.
func stepOIDCStartAuthorize(ctx context.Context, world *support.World, redirectURI, scope, nonce string) error {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {world.Vars["client_id"]},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {support.RandomID("state")},
		"nonce":                 {nonce},
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

func stepOIDCCaptureLoginChallenge(world *support.World) error {
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

// stepOIDCIssueCode calls auth-server's bearer-authed POST /internal/issue-code
// with the given subject as session_id — session_id is treated directly as
// the authorization code's subject (see handler.go's issueCodeRequest doc
// comment), which is what lets a subsequent /userinfo call resolve back to
// a real identity-service user when subject is that user's id.
func stepOIDCIssueCode(ctx context.Context, world *support.World, subject, consent string) error {
	body := map[string]any{
		"login_challenge": world.Vars["login_challenge"],
		"session_id":      subject,
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
		Code string `json:"code"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return fmt.Errorf("decoding issue-code response: %w — body: %s", err, respBody)
	}
	world.Vars["code"] = decoded.Code
	return nil
}

func stepOIDCExchangeCode(ctx context.Context, world *support.World, code, codeVerifier string) error {
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

// stepCallUserinfo calls auth-server's GET /userinfo with the given bearer
// token (RFC 6750). An empty token sends no Authorization header at all,
// for the "missing token" scenario.
func stepCallUserinfo(ctx context.Context, world *support.World, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		world.Services["auth-server"].BaseURL+"/userinfo", nil)
	if err != nil {
		return err
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling /userinfo: %w", err)
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

// stepAssertIDTokenClaim decodes the id_token captured into world.Vars
// (via "the ... from the last response is captured as ...") and checks a
// claim in its payload segment. Unverified decoding is safe here — the
// token was just issued to us by auth-server in this same scenario.
func stepAssertIDTokenClaim(world *support.World, claim, want string) error {
	parts := strings.SplitN(world.Vars["id_token"], ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed id_token: want 3 dot-separated parts, got %d", len(parts))
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decoding id_token payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return fmt.Errorf("unmarshalling id_token payload: %w", err)
	}

	v, ok := payload[claim]
	if !ok {
		return fmt.Errorf("id_token has no %q claim — payload: %s", claim, payloadJSON)
	}
	got, _ := v.(string)
	if got != want {
		return fmt.Errorf("id_token claim %q: want %q, got %v — payload: %s", claim, want, v, payloadJSON)
	}
	return nil
}
