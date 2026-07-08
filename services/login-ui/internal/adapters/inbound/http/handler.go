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
type plansView struct {
	Subject string
	Plans   []planRow
	Error   string
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
	view := plansView{Subject: subject}
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

// CheckoutPost handles plan submission. The form must carry `subject` and
// `plan_code`; the handler creates a Stripe Checkout session via Lago
// and redirects the user to Stripe's hosted page.
//
// Returns 503 when billing is not configured. 400 on missing fields, 500
// on a Lago failure.
//
// @Summary      Start Stripe Checkout for the chosen plan
// @Description  Creates a Stripe Checkout session via Lago and redirects
// @Tags         billing
// @Accept       application/x-www-form-urlencoded
// @Param        subject     formData  string  true  "Authenticated subject id"
// @Param        plan_code   formData  string  true  "Lago plan code"
// @Success      302  "Redirect to Stripe Checkout"
// @Failure      400  "Missing required field"
// @Failure      503  "Billing not configured"
// @Router       /billing/checkout [post]
func (h *Handler) CheckoutPost(w http.ResponseWriter, r *http.Request) {
	if h.billing == nil {
		http.Error(w, "billing not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	subject := r.PostForm.Get("subject")
	planCode := r.PostForm.Get("plan_code")
	if subject == "" || planCode == "" {
		http.Error(w, "subject and plan_code are required", http.StatusBadRequest)
		return
	}
	session, err := h.billing.CreateCheckoutSession(r.Context(), ports.CheckoutSessionRequest{
		CustomerID: subject,
		PlanCode:   planCode,
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
