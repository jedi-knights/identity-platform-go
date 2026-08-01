package http

import (
	"context"
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// accountsView is the data the accounts.html template renders against.
// Subject echoes the query param so the switcher's POST forms can
// re-attach it (the interim identity source until login-ui owns a
// signed session — same bridge /billing/plans uses).
//
// ActiveAccountID is the entitlements-service account currently marked
// active on the user's identity-service preference row (E7-S3a). The
// template compares it to each seat's AccountID to highlight the
// current selection.
type accountsView struct {
	Subject         string
	Seats           []ports.AccountSeat
	ActiveAccountID string
	Notice          string
	Error           string
}

// AccountsGet renders the E7-S3d account switcher. Subject sourced from
// ?subject=... matches the /billing/plans and /billing/portal
// convention documented on those handlers; both are placeholders until
// login-ui owns a session cookie.
//
// Behaviour:
//   - 503 when either outbound dependency is nil (matches other routes'
//     degradation)
//   - 400 when subject is missing
//   - 200 with an empty-state message when the user has 0 seats
//   - 200 with a single-account view when the user has exactly 1 seat
//     (switching is a no-op; the template hides the switch buttons)
//   - 200 with the switcher when the user has ≥ 2 seats
//
// changed=1 on the query string renders a confirmation banner — set
// by the redirect after a successful PUT.
//
// @Summary      Render account switcher
// @Description  Lists every account the user occupies, highlighting the current selection
// @Tags         accounts
// @Produce      html
// @Param        subject  query  string  true  "Authenticated subject id"
// @Param        changed  query  string  false "Set to 1 to render a switch-confirmed banner"
// @Success      200  "HTML page"
// @Failure      400  "Missing subject"
// @Failure      503  "Accounts not configured"
// @Router       /accounts [get]
func (h *Handler) AccountsGet(w http.ResponseWriter, r *http.Request) {
	if !h.accountsWired(w) {
		return
	}
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	view := accountsView{Subject: subject}
	if r.URL.Query().Get("changed") == "1" {
		view.Notice = "Active account updated. Your next token refresh will use the new selection."
	}
	h.populateAccountsView(r.Context(), &view, subject)
	h.renderAccounts(w, view)
}

// populateAccountsView performs the two fan-out reads (seats + active
// account) and writes them onto view. Individual failures degrade to
// an error banner rather than a 500 — the switcher UI should render
// even when one upstream is down. Extracted from AccountsGet to keep
// its cyclomatic complexity within budget.
func (h *Handler) populateAccountsView(ctx context.Context, view *accountsView, subject string) {
	seats, err := h.seats.ListUserSeats(ctx, subject)
	if err != nil {
		h.logger.Error("accounts: list seats failed", "error", err)
		view.Error = "Could not load your accounts. Please try again."
		return
	}
	view.Seats = seats
	active, err := h.activeAccount.GetActiveAccount(ctx, subject)
	if err != nil {
		// The list rendered; not being able to highlight the current
		// selection is a soft failure. Log and continue with an unset
		// ActiveAccountID — no banner (the seats are still usable).
		h.logger.Error("accounts: get active account failed", "error", err)
		return
	}
	view.ActiveAccountID = active
}

// AccountsPost applies a switcher selection. Reads `subject` from the
// query string (same source as AccountsGet) and `active_account_id`
// from the POST body. Success = 302 back to GET /accounts?subject=...
// &changed=1 so the confirmation banner renders after the round-trip.
//
// @Summary      Set active account
// @Description  PUTs the chosen account to identity-service, then redirects back
// @Tags         accounts
// @Accept       application/x-www-form-urlencoded
// @Param        subject           query     string  true  "Authenticated subject id"
// @Param        active_account_id formData  string  true  "Account to make active"
// @Success      302  "Redirect back to /accounts?subject=..."
// @Failure      400  "Missing subject or active_account_id"
// @Failure      503  "Accounts not configured"
// @Router       /accounts [post]
func (h *Handler) AccountsPost(w http.ResponseWriter, r *http.Request) {
	if !h.accountsWired(w) {
		return
	}
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	accountID := r.PostForm.Get("active_account_id")
	if accountID == "" {
		http.Error(w, "active_account_id is required", http.StatusBadRequest)
		return
	}
	if err := h.activeAccount.SetActiveAccount(r.Context(), subject, accountID); err != nil {
		h.logger.Error("accounts: set active account failed", "error", err)
		h.renderAccounts(w, accountsView{
			Subject: subject,
			Error:   "Could not switch account. Please try again.",
		})
		return
	}
	http.Redirect(w, r, "/accounts?subject="+subject+"&changed=1", http.StatusFound)
}

// accountsWired guards both routes so the handler can degrade
// gracefully when either outbound port is nil. Matches how signInWired
// and the WithBilling nil-check protect their sibling routes.
func (h *Handler) accountsWired(w http.ResponseWriter) bool {
	if h.seats == nil || h.activeAccount == nil {
		http.Error(w, "accounts not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (h *Handler) renderAccounts(w http.ResponseWriter, view accountsView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := accountsTemplate.Execute(w, view); err != nil {
		h.logger.Error("accounts: template execution failed", "error", err)
	}
}
