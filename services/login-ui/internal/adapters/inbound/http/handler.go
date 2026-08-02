// Package http hosts the inbound HTTP surface for login-ui — the user-
// facing /sign-in screen (added in ADR-0011), the operational /health
// endpoint, and the /sign-up + /consent screens that land in follow-up
// commits.
package http

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

//go:embed templates/*.html
var templateFS embed.FS

// signInTemplate is parsed once at package init so each request renders
// without re-parsing. Failing at init keeps a malformed template from
// reaching production silently.
var signInTemplate = template.Must(template.ParseFS(templateFS, "templates/sign-in.html"))

// plansTemplate renders the post-signin plan-selection page (ADR-0019).
// Parsed once at init for the same reason as signInTemplate.
var plansTemplate = template.Must(template.ParseFS(templateFS, "templates/plans.html"))

// accountsTemplate renders the E7-S3d account switcher.
var accountsTemplate = template.Must(template.ParseFS(templateFS, "templates/accounts.html"))

// signUpTemplate renders the E5-S1 post-signup entry-point form. Parsed
// once at init for the same reason as its siblings.
var signUpTemplate = template.Must(template.ParseFS(templateFS, "templates/sign-up.html"))

// Handler bundles every HTTP handler login-ui owns. When userAuth and
// codeIssuer are nil the sign-in routes return 503 — letting /health remain
// reachable in environments where the outbound dependencies are not yet
// wired (compose smoke-tests, integration scaffolding).
//
// Audit is wired via [Handler.WithAudit]; when audit is not configured the
// handler uses a no-op emitter so tests and callers that pre-date the
// audit feature keep working.
type Handler struct {
	userAuth      ports.UserAuthenticator
	codeIssuer    ports.AuthCodeIssuer
	billing       ports.BillingClient
	deviceDecider ports.DeviceDecider
	logger        logging.Logger

	auditEmitter audit.Emitter
	auditService string

	// billingSuccessURL and billingCancelURL are passed to Lago when
	// creating a Stripe Checkout session — Stripe sends the user back to
	// one of them after Checkout completes / is abandoned.
	billingSuccessURL string
	billingCancelURL  string

	// seats and activeAccount back the E7-S3d account switcher.
	// Both nil = /accounts routes serve 503, matching how sign-in and
	// billing degrade when their outbound deps are unwired.
	seats         ports.SeatLister
	activeAccount ports.ActiveAccountStore

	// registrar backs the E5-S1 sign-up entry point. Nil = /sign-up
	// routes serve 503 (identity-service unwired).
	registrar ports.UserRegistrar

	// planActivator backs the E5-S2 plan-provisioning composite. Nil =
	// CheckoutPost skips the entitlements write and only touches Lago —
	// acceptable for local dev before entitlements-service is wired;
	// composition root sets it in every real deployment.
	planActivator ports.AccountPlanActivator
}

// WithRegistrar wires the outbound port the E5-S1 sign-up entry
// point depends on. Passing nil leaves the /sign-up routes disabled
// (503). Chainable; returns the receiver.
func (h *Handler) WithRegistrar(registrar ports.UserRegistrar) *Handler {
	h.registrar = registrar
	return h
}

// WithPlanActivator wires the outbound port the E5-S2 plan-provisioning
// composite depends on. Passing nil leaves the composite disabled —
// CheckoutPost falls back to the pre-E5-S2 direct-to-Stripe path so
// environments that pre-date entitlements-service still degrade
// visibly rather than 500ing. Chainable; returns the receiver.
func (h *Handler) WithPlanActivator(a ports.AccountPlanActivator) *Handler {
	h.planActivator = a
	return h
}

// provisionPlanMaxAttempts is the retry ceiling for the E5-S2 composite,
// per the acceptance criteria on issue #163.
const provisionPlanMaxAttempts = 3

// provisionPlanBaseBackoff is the first inter-attempt delay; each
// subsequent attempt doubles it. 200ms × 3 attempts (200 + 400) caps
// user-facing latency on the failure path at ~600ms of pure waiting.
const provisionPlanBaseBackoff = 200 * time.Millisecond

// provisionPlan is the E5-S2 composite: ensure the Lago customer,
// open a subscription against the chosen plan, then write the
// account_plans row on entitlements-service. Every step is
// individually idempotent, so a retry after a mid-composite failure
// converges rather than duplicating state.
//
// Returns the Lago subscription identifier so callers that also
// create a Stripe Checkout session can pass it through. Errors
// surface with the last per-attempt cause so the operator sees the
// underlying transport / 4xx that caused exhaustion.
func (h *Handler) provisionPlan(ctx context.Context, accountID, email, planCode string) (string, error) {
	if h.planActivator == nil {
		return "", fmt.Errorf("login-ui: plan activator not configured")
	}
	var lagoID string
	err := retryWithBackoff(ctx, provisionPlanMaxAttempts, provisionPlanBaseBackoff, func() error {
		return h.provisionOnce(ctx, accountID, email, planCode, &lagoID)
	})
	return lagoID, err
}

// provisionOnce runs one pass of the composite. Extracted so
// retryWithBackoff stays a small loop and the composite's step ordering
// is legible in one place.
func (h *Handler) provisionOnce(ctx context.Context, accountID, email, planCode string, lagoID *string) error {
	if err := h.billing.EnsureCustomer(ctx, ports.EnsureCustomerRequest{
		ExternalID: accountID,
		Email:      email,
	}); err != nil {
		return fmt.Errorf("ensure customer: %w", err)
	}
	sub, err := h.billing.CreateSubscription(ctx, ports.CreateSubscriptionRequest{
		CustomerExternalID: accountID,
		PlanCode:           planCode,
		ExternalID:         accountID + "-" + planCode,
	})
	if err != nil {
		return fmt.Errorf("create subscription: %w", err)
	}
	*lagoID = sub.LagoID
	if err := h.planActivator.ActivatePlan(ctx, ports.ActivatePlanRequest{
		AccountID:          accountID,
		PlanCode:           planCode,
		LagoSubscriptionID: sub.LagoID,
	}); err != nil {
		return fmt.Errorf("activate plan: %w", err)
	}
	return nil
}

// retryWithBackoff runs op up to attempts times with an exponentially-
// growing delay between failures. Returns the last error on exhaustion.
// Honours ctx cancellation between attempts — a cancelled context
// short-circuits the wait rather than dragging the request through the
// full backoff schedule.
func retryWithBackoff(ctx context.Context, attempts int, base time.Duration, op func() error) error {
	var last error
	delay := base
	for i := 0; i < attempts; i++ {
		last = op()
		if last == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return last
}

// WithAccounts wires the outbound ports the E7-S3d account switcher
// depends on. Both must be non-nil to enable the /accounts routes;
// passing nil to either leaves the feature disabled (503 on both
// AccountsGet and AccountsPost). Returns the receiver so composition-
// root construction chains cleanly.
func (h *Handler) WithAccounts(seats ports.SeatLister, activeAccount ports.ActiveAccountStore) *Handler {
	h.seats = seats
	h.activeAccount = activeAccount
	return h
}

// NewHandler returns a Handler wired with the outbound dependencies the
// sign-in flow needs. Either or both of userAuth and codeIssuer may be nil
// during local-only development; in that case the sign-in routes serve a
// stable 503 and /health continues to work.
func NewHandler(userAuth ports.UserAuthenticator, codeIssuer ports.AuthCodeIssuer, logger logging.Logger) *Handler {
	return &Handler{
		userAuth:     userAuth,
		codeIssuer:   codeIssuer,
		logger:       logger,
		auditEmitter: audit.New(audit.NoopSink{}),
		auditService: "login-ui",
	}
}

// WithBilling wires the [ports.BillingClient] and the Stripe Checkout
// return URLs. Returns the receiver to allow chained construction at the
// composition root.
//
// successURL is the public URL Stripe redirects the user to after
// Checkout completes; cancelURL is where the user lands when they abandon
// Checkout. Both may be relative paths on login-ui itself when the
// gateway terminates TLS — Stripe accepts any absolute URL the operator
// configures on the Lago plan.
//
// Passing nil billing disables the billing routes; they return 503 just
// like sign-in does when its outbound deps are nil. This is the documented
// degraded path for environments that haven't wired Lago yet.
func (h *Handler) WithBilling(billing ports.BillingClient, successURL, cancelURL string) *Handler {
	h.billing = billing
	h.billingSuccessURL = successURL
	h.billingCancelURL = cancelURL
	return h
}

// WithAudit configures the handler's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil. service is used as Event.Service on
// every emitted signin_completed event.
//
// Per ADR-0019 signin_completed is a billable web-app event — a
// durable-sink failure surfaces to the user as a generic
// "could not complete sign-in" rather than a partial redirect so the
// accounting cannot have gaps.
func (h *Handler) WithAudit(emitter audit.Emitter, service string) *Handler {
	if emitter == nil {
		panic("http: WithAudit called with nil emitter")
	}
	h.auditEmitter = emitter
	if service != "" {
		h.auditService = service
	}
	return h
}

// Health serves GET /health with a stable 200 + tiny JSON body so the
// docker-compose healthcheck and any orchestration probe can verify the
// process is up.
//
// @Summary      Health check
// @Description  Process liveness probe
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// signInView is the data the sign-in template renders against. Error is
// the only non-trivial field — populated when a prior POST failed so the
// user can correct their entry without losing the challenge.
type signInView struct {
	LoginChallenge string
	Error          string
}

// SignInGet renders the sign-in form. The login_challenge query parameter
// is required — a missing or empty value means the user landed on /sign-in
// outside an OAuth flow, which is a programming or routing error and
// surfaces as a 400.
//
// @Summary      Render sign-in page
// @Description  Renders the platform-wide sign-in form for ADR-0011 login
// @Tags         signin
// @Produce      html
// @Param        login_challenge  query  string  true  "Opaque login-challenge ID from auth-server"
// @Success      200  "HTML form"
// @Failure      400  "Missing login_challenge"
// @Router       /sign-in [get]
func (h *Handler) SignInGet(w http.ResponseWriter, r *http.Request) {
	if !h.signInWired(w) {
		return
	}
	loginChallenge := r.URL.Query().Get("login_challenge")
	if loginChallenge == "" {
		http.Error(w, "missing login_challenge", http.StatusBadRequest)
		return
	}
	h.renderSignIn(w, signInView{LoginChallenge: loginChallenge})
}

// SignInPost processes the sign-in form. Order of operations:
//  1. Parse and validate form fields.
//  2. Verify credentials against identity-service.
//  3. Call auth-server /internal/issue-code to redeem the challenge.
//  4. 302 to the RP's redirect_uri with ?code=&state=.
//
// Steps 2 and 3 each fail-closed: the user sees a generic "invalid email
// or password" on credential failure and a generic "could not complete
// sign-in" on infrastructure failure.
//
// @Summary      Submit sign-in
// @Description  Authenticates the user and redirects back to the relying party
// @Tags         signin
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        login_challenge  formData  string  true  "Login challenge ID"
// @Param        email            formData  string  true  "User email"
// @Param        password         formData  string  true  "User password"
// @Success      302  "Redirect to relying party"
// @Failure      400  "Missing fields"
// @Router       /sign-in [post]
func (h *Handler) SignInPost(w http.ResponseWriter, r *http.Request) {
	if !h.signInWired(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	loginChallenge := r.PostForm.Get("login_challenge")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	if loginChallenge == "" || email == "" || password == "" {
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "email, password and login_challenge are required"})
		return
	}
	subject, err := h.userAuth.VerifyCredentials(r.Context(), email, password)
	if err != nil {
		h.signInError(w, loginChallenge, err)
		return
	}
	h.redeemAndRedirect(w, r, loginChallenge, subject)
}

// signInWired guards both routes so the handler can degrade gracefully when
// either outbound dependency is nil.
func (h *Handler) signInWired(w http.ResponseWriter) bool {
	if h.userAuth == nil || h.codeIssuer == nil {
		http.Error(w, "sign-in not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// renderSignIn writes the sign-in page. Errors writing the template are
// logged but not returned to the user — there is nothing meaningful the
// caller can do with a half-written response.
func (h *Handler) renderSignIn(w http.ResponseWriter, view signInView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := signInTemplate.Execute(w, view); err != nil {
		h.logger.Error("sign-in: template execution failed", "error", err)
	}
}

// signInError maps the VerifyCredentials error to a user-safe message and
// re-renders the form so the user can retry without losing the challenge.
func (h *Handler) signInError(w http.ResponseWriter, loginChallenge string, err error) {
	if apperrors.IsUnauthorized(err) {
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "invalid email or password"})
		return
	}
	h.logger.Error("sign-in: credential verification failed", "error", err)
	h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "could not complete sign-in"})
}

// redeemAndRedirect calls auth-server's /internal/issue-code and bounces the
// user-agent to the RP. RedirectURI and State come from auth-server's
// response, which itself sourced them from the server-side LoginChallenge —
// login-ui never trusts the form body for either value.
func (h *Handler) redeemAndRedirect(w http.ResponseWriter, r *http.Request, loginChallenge, subject string) {
	resp, err := h.codeIssuer.IssueCode(r.Context(), ports.IssueCodeRequest{
		LoginChallenge: loginChallenge,
		SessionID:      subject,
		// Consent is wired up in the follow-up commit. For now request the
		// full scope set the challenge already records by sending nil —
		// auth-server treats nil as "grant the recorded scopes".
		ConsentGranted: nil,
	})
	if err != nil {
		h.logger.Error("sign-in: issue-code failed", "error", err)
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "could not complete sign-in"})
		return
	}
	target, err := url.Parse(resp.RedirectURI)
	if err != nil {
		h.logger.Error("sign-in: malformed redirect_uri", "error", err)
		http.Error(w, "could not complete sign-in", http.StatusInternalServerError)
		return
	}
	if err := h.emitSigninCompleted(r.Context(), subject, loginChallenge); err != nil {
		h.logger.Error("sign-in: audit emit failed", "error", err)
		h.renderSignIn(w, signInView{LoginChallenge: loginChallenge, Error: "could not complete sign-in"})
		return
	}
	q := target.Query()
	q.Set("code", resp.Code)
	if resp.State != "" {
		q.Set("state", resp.State)
	}
	if resp.Issuer != "" {
		q.Set("iss", resp.Issuer)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// --- Billing flows (ADR-0019) ---

// plansView is the template data for the plan-selection page.
// AccountID rides alongside Subject so the form POST can carry both
// through to CheckoutPost — the account_id is the Lago-side customer
// external_id per E5-S2, while subject remains for log correlation.
type plansView struct {
	Subject   string
	AccountID string
	Plans     []planRow
	Error     string
}

// planRow is the per-plan render shape — pre-formatted price string so
// the template stays presentation-only.
type planRow struct {
	Code         string
	Name         string
	Description  string
	DisplayPrice string
	Interval     string
}

// PlansGet renders the plan-selection page. The user's subject_id is
// expected on the `subject` query parameter today; production deployments
// will source it from a signed session cookie once login-ui owns one.
//
// Returns 503 when [Handler.WithBilling] was not called.
//
// @Summary      Render plan-selection page
// @Description  Lists active plans from Lago and renders a chooser
// @Tags         billing
// @Produce      html
// @Param        subject  query  string  true  "Authenticated subject id"
// @Success      200  "HTML page"
// @Failure      503  "Billing not configured"
// @Router       /billing/plans [get]
func (h *Handler) PlansGet(w http.ResponseWriter, r *http.Request) {
	if h.billing == nil {
		http.Error(w, "billing not configured", http.StatusServiceUnavailable)
		return
	}
	subject := r.URL.Query().Get("subject")
	accountID := r.URL.Query().Get("account")
	view := plansView{Subject: subject, AccountID: accountID}
	plans, err := h.billing.ListPlans(r.Context())
	if err != nil {
		h.logger.Error("billing: list plans failed", "error", err)
		view.Error = "Could not load plans. Please try again."
		h.renderPlans(w, view)
		return
	}
	view.Plans = toPlanRows(plans)
	h.renderPlans(w, view)
}

// CheckoutPost handles plan submission. The form must carry `account`
// (the Lago-side customer external_id per E5-S2 AC #163),
// `subject` (the user id, kept for logging + audit correlation until
// login-ui owns a signed session), and `plan_code`.
//
// When a plan activator is wired (E5-S2), the handler first runs the
// composite: ensure Lago customer → open subscription → activate plan
// on entitlements-service. That composite is idempotent and retried up
// to provisionPlanMaxAttempts with exponential backoff so a transient
// Lago blip does not surface as a 500 to the user. Only after the
// composite succeeds does the handler create the Stripe Checkout
// session — a paid-plan user redirects to Stripe with a real
// subscription already recorded on both sides.
//
// When the plan activator is unwired (local dev, unwired composition),
// the handler falls back to the pre-E5-S2 direct-to-Stripe path.
//
// Returns 503 when billing is not configured. 400 on missing fields, 500
// on a Lago failure that survives the backoff loop.
//
// @Summary      Start Stripe Checkout for the chosen plan
// @Description  Provisions the Lago customer + subscription + account_plans row, then redirects to Stripe Checkout
// @Tags         billing
// @Accept       application/x-www-form-urlencoded
// @Param        subject     formData  string  true  "Authenticated subject id"
// @Param        account     formData  string  true  "Account id (Lago external_customer_id)"
// @Param        plan_code   formData  string  true  "Lago plan code"
// @Success      302  "Redirect to Stripe Checkout"
// @Failure      400  "Missing required field"
// @Failure      500  "Provisioning failed after retry"
// @Failure      503  "Billing not configured"
// @Router       /billing/checkout [post]
func (h *Handler) CheckoutPost(w http.ResponseWriter, r *http.Request) {
	if h.billing == nil {
		http.Error(w, "billing not configured", http.StatusServiceUnavailable)
		return
	}
	form, ok := parseCheckoutForm(w, r)
	if !ok {
		return
	}
	if !h.provisionForCheckout(w, r, form) {
		return
	}
	h.redirectToStripe(w, r, form)
}

// checkoutForm is the parsed submission from the plan-selection page.
// Account is the Lago external_customer_id (E5-S2); Subject stays for
// log correlation until login-ui owns a signed session; Email is
// forwarded to Lago's EnsureCustomer when present.
type checkoutForm struct {
	Subject   string
	AccountID string
	PlanCode  string
	Email     string
}

// parseCheckoutForm reads the wire form and validates required fields.
// Writes the appropriate HTTP error and returns ok=false on any
// failure so the caller can return without further logic.
func parseCheckoutForm(w http.ResponseWriter, r *http.Request) (checkoutForm, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return checkoutForm{}, false
	}
	form := checkoutForm{
		Subject:   r.PostForm.Get("subject"),
		AccountID: r.PostForm.Get("account"),
		PlanCode:  r.PostForm.Get("plan_code"),
		Email:     r.PostForm.Get("email"),
	}
	// account carries the entitlements-service account_id; it is the
	// Lago external_customer_id per E5-S2. Empty falls back to subject
	// so environments that pre-date the account_id threading (E7-S1c)
	// still work in a degraded single-tenant mode.
	if form.AccountID == "" {
		form.AccountID = form.Subject
	}
	if form.Subject == "" || form.PlanCode == "" {
		http.Error(w, "subject and plan_code are required", http.StatusBadRequest)
		return checkoutForm{}, false
	}
	return form, true
}

// provisionForCheckout runs the E5-S2 composite when a plan activator
// is wired. Returns false when the caller should stop (an error was
// already written); true otherwise (including the unwired-activator
// pass-through path).
func (h *Handler) provisionForCheckout(w http.ResponseWriter, r *http.Request, form checkoutForm) bool {
	if h.planActivator == nil {
		return true
	}
	if _, err := h.provisionPlan(r.Context(), form.AccountID, form.Email, form.PlanCode); err != nil {
		h.logger.Error("billing: provision plan composite failed",
			"error", err, "account_id", form.AccountID)
		http.Error(w, "could not start checkout", http.StatusInternalServerError)
		return false
	}
	return true
}

// redirectToStripe creates the Lago-managed Stripe Checkout session and
// bounces the browser to it. Failure surfaces as a generic 500 —
// Lago-side detail lands in the log, not the response.
func (h *Handler) redirectToStripe(w http.ResponseWriter, r *http.Request, form checkoutForm) {
	session, err := h.billing.CreateCheckoutSession(r.Context(), ports.CheckoutSessionRequest{
		CustomerID: form.AccountID,
		PlanCode:   form.PlanCode,
		SuccessURL: h.billingSuccessURL,
		CancelURL:  h.billingCancelURL,
	})
	if err != nil {
		h.logger.Error("billing: create checkout session failed", "error", err)
		http.Error(w, "could not start checkout", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, session.URL, http.StatusFound)
}

// PortalGet redirects the authenticated user to Stripe's hosted Customer
// Portal so they can manage cards, download invoices, and cancel
// subscriptions without login-ui needing to render any of that surface.
//
// Returns 503 when billing is not configured. 400 when subject is empty.
// 500 on a Lago failure.
//
// @Summary      Redirect to Stripe Customer Portal
// @Description  Creates a Stripe Customer Portal session via Lago and redirects
// @Tags         billing
// @Param        subject  query  string  true  "Authenticated subject id"
// @Success      302  "Redirect to Stripe Customer Portal"
// @Failure      400  "Missing subject"
// @Failure      503  "Billing not configured"
// @Router       /billing/portal [get]
func (h *Handler) PortalGet(w http.ResponseWriter, r *http.Request) {
	if h.billing == nil {
		http.Error(w, "billing not configured", http.StatusServiceUnavailable)
		return
	}
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	session, err := h.billing.CreatePortalSession(r.Context(), subject)
	if err != nil {
		h.logger.Error("billing: create portal session failed", "error", err)
		http.Error(w, "could not open portal", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, session.URL, http.StatusFound)
}

func (h *Handler) renderPlans(w http.ResponseWriter, view plansView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := plansTemplate.Execute(w, view); err != nil {
		h.logger.Error("plans: template execution failed", "error", err)
	}
}

// toPlanRows maps the port-level [ports.Plan] type into the
// template-friendly [planRow] shape. Price formatting lives here so the
// template stays presentation-only.
func toPlanRows(plans []ports.Plan) []planRow {
	rows := make([]planRow, 0, len(plans))
	for _, p := range plans {
		rows = append(rows, planRow{
			Code:         p.Code,
			Name:         p.Name,
			Description:  p.Description,
			DisplayPrice: formatPrice(p.AmountCents, p.Currency),
			Interval:     p.Interval,
		})
	}
	return rows
}

// formatPrice converts cents + currency code to a human-readable string.
// Free plans show "Free"; other plans show "$N.NN" — currency code is
// rendered as a suffix when it is not USD so the page works in tests and
// staging without hard-coding the operator's currency.
func formatPrice(cents int64, currency string) string {
	if cents == 0 {
		return "Free"
	}
	whole := cents / 100
	fraction := cents % 100
	if currency == "" || currency == "USD" || currency == "usd" {
		return fmt.Sprintf("$%d.%02d", whole, fraction)
	}
	return fmt.Sprintf("%d.%02d %s", whole, fraction, currency)
}

// emitSigninCompleted emits a signin_completed audit event after the
// authorization code has been minted but before the user-agent is
// redirected to the relying party. resource_kind is application — the
// login-ui itself is a web application whose billable unit is a
// successful sign-in. Failed sign-ins (bad credentials, infrastructure
// errors) intentionally do not emit on this stream; they belong on a
// security-audit stream whose envelope is a separate concern.
func (h *Handler) emitSigninCompleted(ctx context.Context, subject, loginChallenge string) error {
	return h.auditEmitter.Emit(ctx, audit.Event{
		EventType:      "signin_completed",
		Service:        h.auditService,
		ActorType:      audit.ActorTypeUser,
		ActorID:        subject,
		SubjectID:      subject,
		Resource:       "application:signin",
		ResourceKind:   audit.ResourceKindApplication,
		ResourceID:     "signin",
		ResourceParent: h.auditService,
		ResourcePath:   h.auditService + "/application/signin",
		Action:         "signin",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"login_challenge": loginChallenge,
		},
	})
}
