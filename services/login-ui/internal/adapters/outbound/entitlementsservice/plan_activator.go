package entitlementsservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// Compile-time interface check — build fails if the port drifts.
var _ ports.AccountPlanActivator = (*PlanActivator)(nil)

// PlanActivator calls entitlements-service POST /accounts/{account_id}/plans.
// The remote endpoint is idempotent on (account_id, plan_code), so a
// caller-side retry after a lost response converges rather than
// producing a duplicate.
type PlanActivator struct {
	baseURL    string
	httpClient *http.Client
}

// NewPlanActivator returns a PlanActivator that calls the given
// entitlements-service base URL. baseURL must NOT include the
// /accounts/... path; the adapter appends it.
func NewPlanActivator(baseURL string, httpClient *http.Client) *PlanActivator {
	return &PlanActivator{baseURL: baseURL, httpClient: httpClient}
}

// activatePlanWireRequest mirrors entitlements-service's activatePlanRequest.
// Field shape must stay in lockstep; a break here is caught by the
// acceptance tests, not by the compiler.
type activatePlanWireRequest struct {
	PlanCode           string `json:"plan_code"`
	LagoSubscriptionID string `json:"lago_subscription_id,omitempty"`
}

// activatePlanWireResponse mirrors entitlements-service's
// activatePlanResponse. plan_tier lets the checkout composite branch
// on free vs paid (E5-S3) without a second lookup.
type activatePlanWireResponse struct {
	PlanTier string `json:"plan_tier"`
}

// ActivatePlan POSTs the plan-activation request. A 200 (idempotent
// replay) and 201 (fresh insert) both count as success — the endpoint
// distinguishes them via the created flag in the response body, which
// login-ui does not need at the port level. Anything else surfaces as
// an apperror. The returned PlanTier propagates to CheckoutPost so
// the free-plan branch can skip Stripe.
func (a *PlanActivator) ActivatePlan(ctx context.Context, req ports.ActivatePlanRequest) (*ports.ActivatePlanResult, error) {
	if err := validateActivatePlanRequest(req); err != nil {
		return nil, err
	}
	body, err := json.Marshal(activatePlanWireRequest{
		PlanCode:           req.PlanCode,
		LagoSubscriptionID: req.LagoSubscriptionID,
	})
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "encoding activate-plan request", err)
	}
	resp, err := a.doActivate(ctx, req.AccountID, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, apperrors.New(apperrors.ErrCodeInternal,
			"activate-plan: unexpected status "+resp.Status)
	}
	var wire activatePlanWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding activate-plan response", err)
	}
	return &ports.ActivatePlanResult{PlanTier: wire.PlanTier}, nil
}

// doActivate issues the POST with the interim service-to-service header
// and returns the raw response. The caller closes the body.
func (a *PlanActivator) doActivate(ctx context.Context, accountID string, body []byte) (*http.Response, error) {
	url := fmt.Sprintf("%s/accounts/%s/plans", a.baseURL, accountID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building activate-plan request", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "posting activate-plan", err)
	}
	return resp, nil
}

// validateActivatePlanRequest enforces required fields before the
// adapter builds a request. account_id and plan_code both propagate
// to the entitlements-service side, where they are again validated —
// checking here saves a network round-trip on the obvious cases.
func validateActivatePlanRequest(req ports.ActivatePlanRequest) error {
	if req.AccountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account_id is required")
	}
	if req.PlanCode == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "plan_code is required")
	}
	return nil
}
