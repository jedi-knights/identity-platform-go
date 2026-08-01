package http

import (
	"encoding/json"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

// activatePlanRequest is the wire-level shape POSTed to
// /accounts/{account_id}/plans. plan_code matches the Lago plan.code
// the login-ui plan picker submitted; lago_subscription_id is the
// Lago-side identifier the login-ui composite handed back after
// Lago's subscription create — empty on the free-plan path.
type activatePlanRequest struct {
	PlanCode           string `json:"plan_code"`
	LagoSubscriptionID string `json:"lago_subscription_id"`
}

// activatePlanResponse is what /accounts/{account_id}/plans returns
// to the login-ui composite. account_plan_id lets the caller correlate
// this write with a subsequent audit or reconciliation lookup;
// created distinguishes a fresh insert (201) from an idempotent replay
// (200) without a timestamp sniff.
type activatePlanResponse struct {
	AccountPlanID string `json:"account_plan_id"`
	AccountID     string `json:"account_id"`
	PlanID        string `json:"plan_id"`
	Created       bool   `json:"created"`
}

// ActivatePlan handles POST /accounts/{account_id}/plans (E5-S2).
//
// Status codes:
//   - 201 Created — a new account_plans row was inserted; plan_activated
//     audit event emitted
//   - 200 OK — the account already had this plan active; idempotent
//     replay, no audit event
//   - 400 Bad Request — malformed body, missing account_id, empty
//     plan_code
//   - 404 Not Found — plan_code does not match any catalog row
//   - 409 Conflict — the account has a *different* plan already active
//     (plan change goes through a distinct future endpoint)
//   - 500 Internal Server Error — anything else
//
// @Summary      Activate a plan for an account
// @Description  Attaches a plan to an account, idempotently. Emits plan_activated on the create path.
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        account_id  path    string               true  "Account ID"
// @Param        request     body    activatePlanRequest  true  "Plan to activate"
// @Success      200  {object}  activatePlanResponse
// @Success      201  {object}  activatePlanResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /accounts/{account_id}/plans [post]
func (h *Handler) ActivatePlan(w http.ResponseWriter, r *http.Request) {
	req, err := parseActivatePlanRequest(r)
	if err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	row, created, err := h.accounts.ActivatePlan(r.Context(), req)
	if err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, activatePlanResponse{
		AccountPlanID: row.ID,
		AccountID:     row.AccountID,
		PlanID:        row.PlanID,
		Created:       created,
	})
}

// parseActivatePlanRequest pulls the path parameter and JSON body into
// an application.ActivatePlanRequest. Extracted so ActivatePlan stays
// under the gocyclo cap alongside future validation branches.
func parseActivatePlanRequest(r *http.Request) (application.ActivatePlanRequest, error) {
	accountID := r.PathValue("account_id")
	if accountID == "" {
		return application.ActivatePlanRequest{},
			apperrors.New(apperrors.ErrCodeBadRequest, "account_id path parameter is required")
	}
	var body activatePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return application.ActivatePlanRequest{},
			apperrors.New(apperrors.ErrCodeBadRequest, "malformed JSON body")
	}
	return application.ActivatePlanRequest{
		AccountID:          accountID,
		PlanCode:           body.PlanCode,
		LagoSubscriptionID: body.LagoSubscriptionID,
	}, nil
}
