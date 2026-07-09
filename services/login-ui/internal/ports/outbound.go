// Package ports declares the outbound service interfaces login-ui depends
// on. Implementations live under internal/adapters/outbound/<service>.
// Following the hexagonal architecture rule (ADR-0001), the handler depends
// on these interfaces — never on a concrete HTTP client.
package ports

import "context"

// UserAuthenticator verifies end-user credentials against identity-service.
// On success the returned subjectID is the canonical user identifier the
// authorization-code grant will stamp onto the issued token's `sub` claim.
//
// Implementations return apperrors.ErrCodeUnauthorized for bad credentials
// and apperrors.ErrCodeInternal on infrastructure failure; login-ui surfaces
// the first as "invalid email or password" and renders a generic message
// for the second.
type UserAuthenticator interface {
	VerifyCredentials(ctx context.Context, email, password string) (subjectID string, err error)
}

// IssueCodeRequest captures the inputs login-ui sends to auth-server's
// /internal/issue-code endpoint after a successful sign-in and consent.
// ConsentGranted carries the scopes the user approved — it must be a
// subset of the scopes recorded on the login challenge.
type IssueCodeRequest struct {
	LoginChallenge string
	SessionID      string
	ConsentGranted []string
}

// IssueCodeResponse is the auth-server response to /internal/issue-code.
// RedirectURI and State come straight from the stored LoginChallenge — the
// handler never reads them from the form body, so a tampered POST cannot
// reach an unregistered URL.
type IssueCodeResponse struct {
	Code        string
	RedirectURI string
	State       string
	// Issuer becomes the `iss` query parameter on the redirect back to the
	// relying party (RFC 9207 §2), so a client talking to more than one
	// authorization server can detect a mix-up attack. Empty when
	// auth-server's AuthorizeConfig.Issuer is unset.
	Issuer string
}

// AuthCodeIssuer is the outbound port behind auth-server's
// /internal/issue-code endpoint. Implementations attach the shared service
// bearer token and decode the JSON response into IssueCodeResponse.
type AuthCodeIssuer interface {
	IssueCode(ctx context.Context, req IssueCodeRequest) (*IssueCodeResponse, error)
}

// DeviceDecisionRequest captures the inputs login-ui sends to auth-server's
// /internal/device/decision endpoint (RFC 8628, ADR-0022) after the user
// authenticates on the device verification page and clicks Approve or Deny.
// Subject is required when Approved is true — it is ignored on a Deny.
type DeviceDecisionRequest struct {
	UserCode string
	Subject  string
	Approved bool
}

// DeviceDecider is the outbound port behind auth-server's bearer-authed
// /internal/device/decision endpoint (ADR-0022). Implementations attach the
// shared service bearer token; the same token authenticates AuthCodeIssuer.
type DeviceDecider interface {
	Decide(ctx context.Context, req DeviceDecisionRequest) error
}

// Plan describes one of the catalog entries Lago publishes via its plans
// API. The shape is deliberately minimal — login-ui only needs enough to
// render the selection page and start a checkout session; the canonical
// representation lives in Lago.
type Plan struct {
	Code        string
	Name        string
	Description string
	// AmountCents is the headline price in the smallest currency unit
	// (cents). Zero is a valid value for free plans.
	AmountCents int64
	Currency    string
	Interval    string // monthly | yearly | weekly | pay-as-you-go
}

// CheckoutSessionRequest captures the inputs to CreateCheckoutSession.
type CheckoutSessionRequest struct {
	CustomerID string // Lago external_customer_id; today equals the user's subject_id
	PlanCode   string
	SuccessURL string
	CancelURL  string
}

// CheckoutSession is the result of asking Lago to start a Stripe Checkout
// flow for the given customer + plan. URL is the redirect login-ui sends
// the user to; the rest of the flow happens on Stripe's hosted page and
// returns via the configured success URL.
type CheckoutSession struct {
	URL string
}

// PortalSession is the result of asking Lago for a Stripe Customer Portal
// URL. The user manages cards, downloads invoices, and cancels subscriptions
// on Stripe's hosted page; login-ui never sees card data.
type PortalSession struct {
	URL string
}

// BillingClient is the outbound port for plan listing, checkout, and
// portal flows per identity-platform-go ADR-0019. The Lago HTTP adapter
// satisfies it; tests use a recording double.
type BillingClient interface {
	// ListPlans returns the active plans the user can subscribe to.
	// Implementations may cache responses at a short TTL so a Lago
	// outage degrades the selection page rather than blocking sign-in.
	ListPlans(ctx context.Context) ([]Plan, error)

	// CreateCheckoutSession asks Lago to start a Stripe Checkout flow for
	// the given subscription. successURL and cancelURL are the
	// post-payment redirect targets — Stripe sends the user back to one
	// of them; the handler then redeems the subscription state.
	CreateCheckoutSession(ctx context.Context, req CheckoutSessionRequest) (*CheckoutSession, error)

	// CreatePortalSession asks Lago for a Stripe Customer Portal URL.
	CreatePortalSession(ctx context.Context, customerID string) (*PortalSession, error)
}
