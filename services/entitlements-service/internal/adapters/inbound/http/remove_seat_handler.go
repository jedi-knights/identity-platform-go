package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

// RemoveSeat handles DELETE /accounts/{account_id}/seats/{user_id}.
//
// Status codes:
//   - 204 No Content — seat removed, seat_removed audit event emitted
//   - 400 Bad Request — missing path parameter or missing requester header
//   - 403 Forbidden — requester lacks an owner-role seat on the account
//   - 404 Not Found — no such seat on this account
//   - 409 Conflict — owner attempted to remove themselves; must
//     transfer ownership first (E7-S5)
//   - 500 Internal Server Error — anything unexpected
//
// Requester identity comes from the X-Requester-User-ID header — the
// same interim bridge the invite handler uses; replaced with a
// validated JWT claim once auth-server's token integration lands.
//
// @Summary      Remove a seat from an account
// @Description  Removes the seat identified by (account_id, user_id). Owner-only. Emits a seat_removed audit event.
// @Tags         accounts
// @Param        account_id           path    string  true  "Account ID"
// @Param        user_id              path    string  true  "Seat user_id to remove"
// @Param        X-Requester-User-ID  header  string  true  "Owner user_id (RBAC bridge)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /accounts/{account_id}/seats/{user_id} [delete]
func (h *Handler) RemoveSeat(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	if accountID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "account_id path parameter is required")
		return
	}
	targetUserID := r.PathValue("user_id")
	if targetUserID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "user_id path parameter is required")
		return
	}
	requesterUserID := r.Header.Get(requesterHeader)
	if requesterUserID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", requesterHeader+" header is required")
		return
	}
	if err := h.accounts.RemoveSeat(r.Context(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: requesterUserID,
		TargetUserID:    targetUserID,
	}); err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
