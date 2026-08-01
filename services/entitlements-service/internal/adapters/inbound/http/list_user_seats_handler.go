package http

import (
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// planSummaryDTO is the wire-level shape of a UserSeatSummary.Plan.
// Pointer receiver on the parent so a nil Plan serialises as JSON null,
// which login-ui uses to distinguish "no active plan yet" from
// "plan omitted".
type planSummaryDTO struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
}

// userSeatDTO is the wire-level shape of one entry in the switcher
// response. Plan is a pointer so an account with no active plan
// serialises as `"plan": null` rather than an empty object.
type userSeatDTO struct {
	SeatID             string          `json:"seat_id"`
	AccountID          string          `json:"account_id"`
	AccountDisplayName string          `json:"account_display_name"`
	Role               string          `json:"role"`
	Plan               *planSummaryDTO `json:"plan"`
}

// listUserSeatsResponse wraps the seats array in an object so
// pagination fields (cursor, next, etc.) can be added later without a
// breaking wire change — a bare top-level array offers no such
// expansion room.
type listUserSeatsResponse struct {
	Seats []userSeatDTO `json:"seats"`
}

// ListUserSeats handles GET /users/{user_id}/seats.
//
// Status codes:
//   - 200 OK — seats array (possibly empty)
//   - 400 Bad Request — missing path {user_id} or missing X-Requester-User-ID header
//   - 403 Forbidden — requester does not match {user_id}
//   - 500 Internal Server Error — anything unexpected
//
// The requester header is the same interim bridge the invite handler
// uses; auth-server JWT integration in E7-S3c will replace it with a
// validated claim.
//
// @Summary      List account seats a user occupies
// @Description  Returns every account seat userID has, with role and (nullable) currently-active plan. login-ui renders this as the account switcher.
// @Tags         users
// @Produce      json
// @Param        user_id              path    string  true  "User ID"
// @Param        X-Requester-User-ID  header  string  true  "Requester user ID (must equal path user_id)"
// @Success      200  {object}  listUserSeatsResponse
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /users/{user_id}/seats [get]
func (h *Handler) ListUserSeats(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("user_id")
	if userID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "user_id path parameter is required")
		return
	}
	requester := r.Header.Get(requesterHeader)
	if requester == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", requesterHeader+" header is required")
		return
	}
	if requester != userID {
		writeAppError(w, h.logger, apperrors.New(apperrors.ErrCodeForbidden, "requester may only list own seats"))
		return
	}
	rows, err := h.accounts.ListUserSeats(r.Context(), userID)
	if err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, listUserSeatsResponse{Seats: toUserSeatDTOs(rows)})
}

// toUserSeatDTOs projects the domain rows to their JSON wire form.
// Extracted from the handler so ListUserSeats stays under the gocyclo
// budget with the auth-check branches counted.
func toUserSeatDTOs(rows []domain.UserSeatSummary) []userSeatDTO {
	out := make([]userSeatDTO, 0, len(rows))
	for _, r := range rows {
		dto := userSeatDTO{
			SeatID:             r.SeatID,
			AccountID:          r.AccountID,
			AccountDisplayName: r.AccountDisplayName,
			Role:               string(r.Role),
		}
		if r.Plan != nil {
			dto.Plan = &planSummaryDTO{
				ID:          r.Plan.ID,
				Code:        r.Plan.Code,
				DisplayName: r.Plan.DisplayName,
			}
		}
		out = append(out, dto)
	}
	return out
}
