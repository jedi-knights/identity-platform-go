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

// RegisterRequest captures the inputs to UserRegistrar.Register.
type RegisterRequest struct {
	Email    string
	Password string
	Name     string
}

// RegisterResult is the login-ui-side projection of identity-service's
// RegisterResponse. AccountID is the entitlements-service personal
// account auto-created for the new user (E7-S1c) — empty when
// identity-service was deployed without IDENTITY_ENTITLEMENTS_SERVICE_URL.
// A future sign-up handler will thread AccountID through to a session
// so the plan-selection step (Epic 2/8) can look it up without a hop
// back to identity-service.
type RegisterResult struct {
	UserID    string
	Email     string
	Name      string
	AccountID string // "" when entitlements-service is not wired upstream
}

// UserRegistrar creates a new user account against identity-service.
// Implementations POST to /auth/register and decode the response into
// RegisterResult. Callers should treat empty AccountID as "entitlements
// not configured", not as failure.
type UserRegistrar interface {
	Register(ctx context.Context, req RegisterRequest) (*RegisterResult, error)
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

// AccountSeat is the login-ui-side projection of one row from
// entitlements-service's GET /users/{user_id}/seats endpoint (E7-S3b).
// Carries only the fields the account switcher needs to render.
type AccountSeat struct {
	SeatID             string
	AccountID          string
	AccountDisplayName string
	Role               string // owner | admin | member
	// PlanCode / PlanName are empty when the account has no
	// currently-active plan (fresh account before checkout, or a
	// lapsed subscription). The template renders "No plan" in that
	// case; login-ui does not decide policy.
	PlanCode string
	PlanName string
}

// SeatLister is the outbound port for reading the accounts a user
// occupies (E7-S3d). Backed by entitlements-service GET
// /users/{user_id}/seats. Empty slice (nil error) when the user has no
// seats — the switcher page renders an empty state, not an error.
type SeatLister interface {
	ListUserSeats(ctx context.Context, userID string) ([]AccountSeat, error)
}

// ActivatePlanRequest carries the fields entitlements-service needs to
// insert the account_plans row. LagoSubscriptionID is empty on the free-
// plan path and populated when the paid-plan flow returns a subscription
// identifier from Lago.
type ActivatePlanRequest struct {
	AccountID          string
	PlanCode           string
	LagoSubscriptionID string
}

// ActivatePlanResult is what the port returns after a successful
// activation. PlanTier is the entitlements-service catalog tier
// ("free" | "coach" | "club") so the checkout composite can branch on
// free vs paid without a second lookup (E5-S3).
type ActivatePlanResult struct {
	PlanTier string
}

// AccountPlanActivator is the outbound port for writing the account_plans
// row on the entitlements-service side (E5-S2). Backed by POST
// /accounts/{account_id}/plans. The remote endpoint is idempotent — a
// repeat with the same (account_id, plan_code) reuses the existing row —
// so login-ui's retry loop can safely re-invoke this after a lost
// response.
type AccountPlanActivator interface {
	ActivatePlan(ctx context.Context, req ActivatePlanRequest) (*ActivatePlanResult, error)
}

// ActiveAccountStore is the outbound port for reading and writing the
// user's currently-selected account preference (E7-S3d). Backed by
// identity-service GET/PUT /users/{id}/active-account (E7-S3a).
//
// GetActiveAccount returns "" (nil error) when the user has not chosen —
// the switcher renders every seat unselected. SetActiveAccount is
// idempotent — the server accepts a repeat-of-current value silently.
type ActiveAccountStore interface {
	GetActiveAccount(ctx context.Context, userID string) (accountID string, err error)
	SetActiveAccount(ctx context.Context, userID, accountID string) error
}

// EnsureCustomerRequest carries the fields Lago needs to upsert a
// customer keyed by ExternalID. Email is optional at the port level so
// the free-plan path can create a shell customer before we require
// billing details; adapters may still choose to POST it when known.
type EnsureCustomerRequest struct {
	ExternalID string
	Email      string
}

// CreateSubscriptionRequest carries the fields Lago needs to open a
// subscription. ExternalID is the caller-supplied idempotency key —
// login-ui composes it deterministically from (account_id, plan_code)
// so a retry after a lost response reuses the same key. PlanCode is
// the Lago plan.code the customer selected.
type CreateSubscriptionRequest struct {
	CustomerExternalID string
	PlanCode           string
	ExternalID         string
}

// SubscriptionResult is the trimmed shape login-ui records after a
// successful subscription create. LagoID is the Lago-side subscription
// identifier the account_plans row keys off for reconciliation.
type SubscriptionResult struct {
	LagoID string
}

// BillingClient is the outbound port for plan listing, checkout, and
// portal flows per identity-platform-go ADR-0019. The Lago HTTP adapter
// satisfies it; tests use a recording double.
type BillingClient interface {
	// ListPlans returns the active plans the user can subscribe to.
	// Implementations may cache responses at a short TTL so a Lago
	// outage degrades the selection page rather than blocking sign-in.
	ListPlans(ctx context.Context) ([]Plan, error)

	// EnsureCustomer creates or updates the Lago customer keyed by
	// ExternalID. Idempotent — Lago's POST /customers upserts on the
	// external_id key so a retry after a lost response is safe.
	EnsureCustomer(ctx context.Context, req EnsureCustomerRequest) error

	// CreateSubscription opens a subscription for the given customer +
	// plan. The caller supplies ExternalID as a deterministic
	// idempotency key so a retry after a lost response returns the
	// same subscription rather than creating a duplicate. Returns the
	// Lago-side subscription identifier so the caller can persist it
	// alongside the account_plans row for reconciliation.
	CreateSubscription(ctx context.Context, req CreateSubscriptionRequest) (*SubscriptionResult, error)

	// CreateCheckoutSession asks Lago to start a Stripe Checkout flow for
	// the given subscription. successURL and cancelURL are the
	// post-payment redirect targets — Stripe sends the user back to one
	// of them; the handler then redeems the subscription state.
	CreateCheckoutSession(ctx context.Context, req CheckoutSessionRequest) (*CheckoutSession, error)

	// CreatePortalSession asks Lago for a Stripe Customer Portal URL.
	CreatePortalSession(ctx context.Context, customerID string) (*PortalSession, error)
}
