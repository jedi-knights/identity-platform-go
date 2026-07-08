package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerDeviceAuthorizationSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client requests device authorization with scope "([^"]*)"$`, func(ctx context.Context, scope string) error {
		return stepRequestDeviceAuthorization(ctx, world(), scope)
	})

	sctx.Step(`^the device polls the token endpoint with the device_code$`, func(ctx context.Context) error {
		w := world()
		return stepPollDeviceToken(ctx, w, w.Vars["device_code"])
	})

	sctx.Step(`^the device polls the token endpoint with device_code "([^"]*)"$`, func(ctx context.Context, deviceCode string) error {
		return stepPollDeviceToken(ctx, world(), deviceCode)
	})

	sctx.Step(`^the user approves the device authorization on the verification page with email "([^"]*)" and password "([^"]*)"$`,
		func(ctx context.Context, email, password string) error {
			return stepDecideDevice(ctx, world(), email, password, "approve")
		})

	sctx.Step(`^the user denies the device authorization on the verification page$`, func(ctx context.Context) error {
		return stepDecideDevice(ctx, world(), "", "", "deny")
	})
}

// stepRequestDeviceAuthorization posts to auth-server's
// POST /device_authorization and captures device_code, user_code, and
// verification_uri into world.Vars — every downstream step (polling,
// approving via login-ui) needs at least one of them, matching the same
// auto-capture convention stepStartAuthorize/stepCaptureLoginChallenge use
// for the authorization_code flow.
func stepRequestDeviceAuthorization(ctx context.Context, world *support.World, scope string) error {
	form := url.Values{
		"client_id": {world.Vars["client_id"]},
		"scope":     {scope},
	}
	if world.Vars["client_secret"] != "" {
		form.Set("client_secret", world.Vars["client_secret"])
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["auth-server"].BaseURL+"/device_authorization", strings.NewReader(form.Encode()))
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
		return err
	}
	world.LastResponse = resp
	world.LastBody = body

	if resp.StatusCode != http.StatusOK {
		return nil // let the scenario's own "Then" steps assert on the error
	}

	var decoded struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("decoding device_authorization response: %w — body: %s", err, body)
	}
	world.Vars["device_code"] = decoded.DeviceCode
	world.Vars["user_code"] = decoded.UserCode
	world.Vars["verification_uri"] = decoded.VerificationURI
	return nil
}

// stepPollDeviceToken posts the device_code grant to auth-server's
// /oauth/token with the given device_code.
func stepPollDeviceToken(ctx context.Context, world *support.World, deviceCode string) error {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {world.Vars["client_id"]},
		"device_code": {deviceCode},
	}
	if world.Vars["client_secret"] != "" {
		form.Set("client_secret", world.Vars["client_secret"])
	}
	return postToken(ctx, world, form)
}

// stepDecideDevice posts login-ui's real POST /device form — the actual
// ADR-0022 verification page — with the user_code captured from the
// device_authorization response. email/password are ignored (and may be
// empty) when decision is "deny", mirroring how the real form only
// requires credentials to approve.
func stepDecideDevice(ctx context.Context, world *support.World, email, password, decision string) error {
	form := url.Values{
		"user_code": {world.Vars["user_code"]},
		"decision":  {decision},
	}
	if email != "" {
		form.Set("email", email)
	}
	if password != "" {
		form.Set("password", password)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["login-ui"].BaseURL+"/device", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := world.HTTPClient.Do(req)
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
