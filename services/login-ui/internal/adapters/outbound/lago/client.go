// Package lago is the [ports.BillingClient] implementation. It calls
// self-hosted Lago's REST API for plan listing, Stripe Checkout session
// creation via the Lago↔Stripe connector, and Stripe Customer Portal
// URL generation. login-ui never sees card data — Stripe's hosted UIs
// own that surface.
package lago

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// DefaultTimeout caps each Lago call. Lago is typically sub-100ms on a
// healthy region; the 5s ceiling forgives a cold start without letting
// a stuck connection pin the request.
const DefaultTimeout = 5 * time.Second

// Client is the HTTP client. baseURL is the Lago API root (e.g.
// https://lago-api.internal); apiKey authenticates calls via the
// Authorization: Bearer header.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Compile-time assertion.
var _ ports.BillingClient = (*Client)(nil)

// New constructs the Lago client. Empty baseURL / apiKey panic —
// composition errors are loud at startup. A nil http.Client falls back
// to one with [DefaultTimeout].
func New(baseURL, apiKey string, httpClient *http.Client) *Client {
	if baseURL == "" {
		panic("login-ui/lago: New called with empty baseURL")
	}
	if apiKey == "" {
		panic("login-ui/lago: New called with empty apiKey")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

// ListPlans calls Lago's GET /api/v1/plans and maps the response into
// the trimmed [ports.Plan] shape login-ui's selection page renders.
// Inactive plans are filtered out so the UI cannot surface a plan the
// operator has retired.
func (c *Client) ListPlans(ctx context.Context) ([]ports.Plan, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/plans", nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var wire struct {
		Plans []struct {
			Code        string `json:"code"`
			Name        string `json:"name"`
			Description string `json:"description"`
			AmountCents int64  `json:"amount_cents"`
			Currency    string `json:"amount_currency"`
			Interval    string `json:"interval"`
			Active      bool   `json:"active"`
		} `json:"plans"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("login-ui/lago: decoding plans response: %w", err)
	}
	out := make([]ports.Plan, 0, len(wire.Plans))
	for _, p := range wire.Plans {
		if !p.Active {
			continue
		}
		out = append(out, ports.Plan{
			Code:        p.Code,
			Name:        p.Name,
			Description: p.Description,
			AmountCents: p.AmountCents,
			Currency:    p.Currency,
			Interval:    p.Interval,
		})
	}
	return out, nil
}

// EnsureCustomer creates or updates the Lago customer keyed by
// req.ExternalID. Lago's POST /api/v1/customers upserts on
// external_id — a repeat call with the same key returns the existing
// row with 200, so this method is safely retriable at the caller.
// Email is only included in the body when supplied so we do not
// clobber a customer-managed value on a bare-bones re-provision.
func (c *Client) EnsureCustomer(ctx context.Context, in ports.EnsureCustomerRequest) error {
	if in.ExternalID == "" {
		return fmt.Errorf("login-ui/lago: EnsureCustomer requires external_id")
	}
	customer := map[string]any{"external_id": in.ExternalID}
	if in.Email != "" {
		customer["email"] = in.Email
	}
	body := map[string]any{"customer": customer}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/customers", body)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return err
	}
	return nil
}

// CreateSubscription opens a Lago subscription. ExternalID is the
// caller-supplied idempotency key — Lago rejects a duplicate with 422
// carrying an "external_id: value_already_exist" body. That case is
// mapped to a successful lookup: the existing subscription's Lago ID
// is returned so a lost-response retry converges rather than failing.
// Any other error surfaces as APIError.
func (c *Client) CreateSubscription(ctx context.Context, in ports.CreateSubscriptionRequest) (*ports.SubscriptionResult, error) {
	if err := validateCreateSubscription(in); err != nil {
		return nil, err
	}
	body := map[string]any{
		"subscription": map[string]any{
			"external_customer_id": in.CustomerExternalID,
			"plan_code":            in.PlanCode,
			"external_id":          in.ExternalID,
		},
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/subscriptions", body)
	if err != nil {
		return nil, err
	}
	respBody, err := c.do(req)
	if err != nil {
		if isDuplicateExternalID(err) {
			return c.findSubscriptionByExternalID(ctx, in.ExternalID)
		}
		return nil, err
	}
	return decodeSubscription(respBody)
}

// validateCreateSubscription enforces the required fields at the
// adapter boundary so a mis-composed request never hits Lago.
func validateCreateSubscription(in ports.CreateSubscriptionRequest) error {
	if in.CustomerExternalID == "" {
		return fmt.Errorf("login-ui/lago: CreateSubscription requires external_customer_id")
	}
	if in.PlanCode == "" {
		return fmt.Errorf("login-ui/lago: CreateSubscription requires plan_code")
	}
	if in.ExternalID == "" {
		return fmt.Errorf("login-ui/lago: CreateSubscription requires external_id (idempotency key)")
	}
	return nil
}

// isDuplicateExternalID reports whether err is Lago's 422 payload for a
// repeat external_id — the shape Lago returns is:
//
//	{"status":422,"error":"Unprocessable Entity","error_details":{"external_id":["value_already_exist"]}}
//
// We match on the substring rather than parsing because Lago's error
// envelope varies across resource endpoints; substring-matching the
// specific `"value_already_exist"` marker is stable enough for our
// retry loop and precise enough to avoid false positives.
func isDuplicateExternalID(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		return false
	}
	return strings.Contains(apiErr.Body, "value_already_exist") &&
		strings.Contains(apiErr.Body, "external_id")
}

// findSubscriptionByExternalID GETs /api/v1/subscriptions/{external_id}
// so a duplicate-key retry can converge on the existing subscription's
// Lago-side identifier. Lago's read endpoint accepts either the Lago
// ID or the caller-supplied external_id in the path.
func (c *Client) findSubscriptionByExternalID(ctx context.Context, externalID string) (*ports.SubscriptionResult, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/subscriptions/"+externalID, nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	return decodeSubscription(body)
}

// decodeSubscription reads Lago's subscription envelope. lago_id is
// the field the reconciliation flow keys off; a missing value surfaces
// as an error so a partial response cannot silently produce a row with
// an empty Lago identifier.
func decodeSubscription(body []byte) (*ports.SubscriptionResult, error) {
	var wire struct {
		Subscription struct {
			LagoID string `json:"lago_id"`
		} `json:"subscription"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("login-ui/lago: decoding subscription response: %w", err)
	}
	if wire.Subscription.LagoID == "" {
		return nil, fmt.Errorf("login-ui/lago: subscription response missing lago_id")
	}
	return &ports.SubscriptionResult{LagoID: wire.Subscription.LagoID}, nil
}

// CreateCheckoutSession asks Lago to create a Stripe Checkout session via
// its native Stripe connector. The customer must already exist in Lago;
// the handler is responsible for provisioning customers up front during
// the post-signin flow.
func (c *Client) CreateCheckoutSession(ctx context.Context, in ports.CheckoutSessionRequest) (*ports.CheckoutSession, error) {
	body := map[string]any{
		"checkout_session": map[string]any{
			"external_customer_id": in.CustomerID,
			"plan_code":            in.PlanCode,
			"success_url":          in.SuccessURL,
			"cancel_url":           in.CancelURL,
		},
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/checkout_sessions", body)
	if err != nil {
		return nil, err
	}
	respBody, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var wire struct {
		CheckoutSession struct {
			URL string `json:"url"`
		} `json:"checkout_session"`
	}
	if err := json.Unmarshal(respBody, &wire); err != nil {
		return nil, fmt.Errorf("login-ui/lago: decoding checkout response: %w", err)
	}
	if wire.CheckoutSession.URL == "" {
		return nil, fmt.Errorf("login-ui/lago: checkout response missing url")
	}
	return &ports.CheckoutSession{URL: wire.CheckoutSession.URL}, nil
}

// CreatePortalSession asks Lago for a Stripe Customer Portal URL.
func (c *Client) CreatePortalSession(ctx context.Context, customerID string) (*ports.PortalSession, error) {
	body := map[string]any{
		"customer_portal": map[string]any{
			"external_customer_id": customerID,
		},
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/customer_portals", body)
	if err != nil {
		return nil, err
	}
	respBody, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var wire struct {
		CustomerPortal struct {
			URL string `json:"url"`
		} `json:"customer_portal"`
	}
	if err := json.Unmarshal(respBody, &wire); err != nil {
		return nil, fmt.Errorf("login-ui/lago: decoding portal response: %w", err)
	}
	if wire.CustomerPortal.URL == "" {
		return nil, fmt.Errorf("login-ui/lago: portal response missing url")
	}
	return &ports.PortalSession{URL: wire.CustomerPortal.URL}, nil
}

// newRequest constructs an HTTP request with auth, content-type, and
// (when body is non-nil) a JSON-encoded body. Centralised here so the
// auth header is never forgotten on a new call site.
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("login-ui/lago: marshalling request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("login-ui/lago: constructing request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// do executes the request and returns the body on a 2xx response. Non-2xx
// responses surface as APIError with up to 1 KiB of the response body.
func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login-ui/lago: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, &APIError{
			Status: resp.StatusCode,
			Method: req.Method,
			Path:   req.URL.Path,
			Body:   strings.TrimSpace(string(body)),
		}
	}
	return body, nil
}

// APIError is returned for non-2xx Lago responses. Useful for logging
// and for handler-side fallback decisions (e.g. show the user a "billing
// temporarily unavailable" message on 5xx without exposing the raw body).
type APIError struct {
	Status int
	Method string
	Path   string
	Body   string
}

// Error formats the error for logs.
func (e *APIError) Error() string {
	return fmt.Sprintf("login-ui/lago: %s %s: status %d: %s",
		e.Method, e.Path, e.Status, e.Body)
}
