package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

// requesterAuthTimeHeader carries the requester's most recent
// fresh-authentication timestamp. Formatted as RFC 3339 with fractional
// seconds (Go's time.RFC3339Nano). Interim bridge: once auth-server's
// JWT integration lands, the value will come from the token's
// auth_time claim rather than a client-supplied header. See the
// TransferOwnershipRequest docstring on the application layer.
const requesterAuthTimeHeader = "X-Requester-Auth-Time"

// transferOwnershipRequest is the wire-level shape POSTed to
// /accounts/{account_id}/transfer-ownership. TargetUserID names the
// existing seat that should be promoted to owner. The requester's
// identity + auth-time come from headers, not the body, so a
// tampered body cannot bypass the RBAC + freshness gates.
type transferOwnershipRequest struct {
	TargetUserID string `json:"target_user_id"`
}

// TransferOwnership handles POST /accounts/{account_id}/transfer-ownership.
//
// Status codes:
//   - 204 No Content — ownership transferred; ownership_transferred
//     audit event emitted
//   - 400 Bad Request — malformed body, missing path/header, or a
//     same-user transfer (requester == target)
//   - 403 Forbidden — requester lacks an owner-role seat OR the
//     fresh-auth window (5 min) has elapsed since the last login
//   - 404 Not Found — no seat for target_user_id on this account
//   - 409 Conflict — repo-level owner-role race (someone else
//     transferred first)
//   - 500 Internal Server Error — anything unexpected
//
// @Summary      Transfer account ownership to another seat
// @Description  Demotes the current owner to admin and promotes the target user to owner. Requires a fresh login within 5 minutes.
// @Tags         accounts
// @Accept       json
// @Param        account_id             path    string                    true  "Account ID"
// @Param        X-Requester-User-ID    header  string                    true  "Owner user_id (RBAC bridge)"
// @Param        X-Requester-Auth-Time  header  string                    true  "Requester last-authentication timestamp, RFC 3339"
// @Param        request                body    transferOwnershipRequest  true  "Transfer target"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /accounts/{account_id}/transfer-ownership [post]
func (h *Handler) TransferOwnership(w http.ResponseWriter, r *http.Request) {
	req, err := h.parseTransferRequest(r)
	if err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	if err := h.accounts.TransferOwnership(r.Context(), req); err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseTransferRequest pulls the path parameter, headers, and JSON
// body into an application.TransferOwnershipRequest. Extracted so the
// handler proper stays under the gocyclo cap and every validation
// branch has a single place to surface an apperror from.
func (h *Handler) parseTransferRequest(r *http.Request) (application.TransferOwnershipRequest, error) {
	accountID := r.PathValue("account_id")
	if accountID == "" {
		return application.TransferOwnershipRequest{},
			apperrors.New(apperrors.ErrCodeBadRequest, "account_id path parameter is required")
	}
	requesterUserID := r.Header.Get(requesterHeader)
	if requesterUserID == "" {
		return application.TransferOwnershipRequest{},
			apperrors.New(apperrors.ErrCodeBadRequest, requesterHeader+" header is required")
	}
	authTime, err := parseRequesterAuthTime(r.Header.Get(requesterAuthTimeHeader))
	if err != nil {
		return application.TransferOwnershipRequest{}, err
	}
	var body transferOwnershipRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return application.TransferOwnershipRequest{},
			apperrors.New(apperrors.ErrCodeBadRequest, "malformed JSON body")
	}
	return application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   requesterUserID,
		RequesterAuthTime: authTime,
		TargetUserID:      body.TargetUserID,
	}, nil
}

// parseRequesterAuthTime enforces the RFC 3339 shape on the
// X-Requester-Auth-Time header. Empty and malformed both surface as
// bad-request; the application layer separately rejects a zero
// timestamp so a header of "" and a header of "invalid" both flow
// through consistent boundaries.
func parseRequesterAuthTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{},
			apperrors.New(apperrors.ErrCodeBadRequest, requesterAuthTimeHeader+" header is required")
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{},
			apperrors.New(apperrors.ErrCodeBadRequest, requesterAuthTimeHeader+" must be RFC 3339")
	}
	return t, nil
}
