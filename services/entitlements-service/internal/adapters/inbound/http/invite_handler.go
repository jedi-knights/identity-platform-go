package http

import (
	"encoding/json"
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

// createInviteRequest is the wire-level shape POSTed to
// /accounts/{account_id}/invites. RequesterUserID is sourced from the
// X-Requester-User-ID header, not the body — bodies could be tampered
// before hitting the auth boundary.
type createInviteRequest struct {
	Email string `json:"email"`
}

// createInviteResponse is what the caller sees. token intentionally
// absent — the raw token is emailed only, per E7-S2 AC ("email sent
// with signup link").
type createInviteResponse struct {
	InviteID     string `json:"invite_id"`
	InvitedEmail string `json:"invited_email"`
	AccountID    string `json:"account_id"`
	ExpiresAt    string `json:"expires_at"`
}

// requesterHeader is the temporary bridge until auth-server's JWT
// integration lands. The composition root's HTTP middleware will
// eventually populate this from a validated token claim.
const requesterHeader = "X-Requester-User-ID"

// CreateInvite handles POST /accounts/{account_id}/invites.
//
// Status codes:
//   - 201 Created   — invite created and email sent
//   - 400 Bad Request — malformed body, missing email, or missing requester header
//   - 403 Forbidden — requester is not an owner-role seat on the account
//   - 409 Conflict — seat limit reached OR a duplicate open invite already exists
//   - 500 Internal Server Error — anything unexpected
func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	if accountID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "account_id path parameter is required")
		return
	}
	requesterUserID := r.Header.Get(requesterHeader)
	if requesterUserID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", requesterHeader+" header is required")
		return
	}
	var body createInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	inv, err := h.invites.Invite(r.Context(), application.InviteRequest{
		AccountID:       accountID,
		RequesterUserID: requesterUserID,
		InvitedEmail:    body.Email,
	})
	if err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, createInviteResponse{
		InviteID:     inv.ID,
		InvitedEmail: inv.InvitedEmail,
		AccountID:    inv.AccountID,
		ExpiresAt:    inv.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}
