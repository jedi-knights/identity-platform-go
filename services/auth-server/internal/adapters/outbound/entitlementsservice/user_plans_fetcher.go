// Package entitlementsservice contains outbound adapters that call
// entitlements-service from auth-server at token-issuance time.
package entitlementsservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Compile-time interface check — UserPlansFetcher must satisfy the
// outbound port the token strategies depend on for E8-S4 claim wiring.
var _ ports.UserPlansFetcher = (*UserPlansFetcher)(nil)

// planSummary mirrors entitlements-service's planSummaryDTO
// (services/entitlements-service internal/adapters/inbound/http/
// list_user_seats_handler.go). Only the ID is read today; Code /
// DisplayName are decoded for schema compatibility and future use.
type planSummary struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
}

// userSeat mirrors entitlements-service's userSeatDTO. Plan is a
// pointer so a seat with no active plan ("plan": null on the wire)
// decodes without producing a bogus zero-value plan.
type userSeat struct {
	SeatID             string       `json:"seat_id"`
	AccountID          string       `json:"account_id"`
	AccountDisplayName string       `json:"account_display_name"`
	Role               string       `json:"role"`
	Plan               *planSummary `json:"plan"`
}

// listUserSeatsResponse mirrors entitlements-service's
// listUserSeatsResponse — pagination-ready envelope around the seats
// array.
type listUserSeatsResponse struct {
	Seats []userSeat `json:"seats"`
}

// UserPlansFetcher implements ports.UserPlansFetcher by calling
// entitlements-service GET /users/{id}/seats. The adapter filters the
// returned seats down to the one matching activeAccountID and emits
// the plan ids on that seat. Entitlements-service returns at most one
// plan per seat today; the slice shape leaves room for add-on plans
// without a wire-breaking change.
type UserPlansFetcher struct {
	baseURL    string
	httpClient *http.Client
}

// NewUserPlansFetcher returns a UserPlansFetcher that calls the given
// entitlements-service base URL. baseURL must be the schemed root
// (e.g. http://jk-entitlements-service.internal:8086) with no trailing
// slash — fmt.Sprintf below composes the path verbatim.
func NewUserPlansFetcher(baseURL string, httpClient *http.Client) *UserPlansFetcher {
	return &UserPlansFetcher{baseURL: baseURL, httpClient: httpClient}
}

// GetUserPlans fetches the plan ids active on the user's selected
// account. Returns an empty slice (nil error) when any of:
//
//   - activeAccountID is empty (user has never selected an account)
//   - entitlements-service reports no seat on activeAccountID
//   - the matched seat has no active plan (JSON "plan": null)
//
// A non-nil error is a fetch failure (transport / non-2xx / decode);
// the caller logs and issues the token without the claim rather than
// coupling token issuance to entitlements-service availability.
//
// The interim RBAC bridge on entitlements-service (same convention as
// identity-service's E7-S3a) requires the X-Requester-User-ID header
// to match the path {user_id}. Auth-server sends the header set to
// userID — auth-server is trusted infrastructure speaking on the
// user's behalf.
func (f *UserPlansFetcher) GetUserPlans(ctx context.Context, userID, activeAccountID string) (_ []string, retErr error) {
	if userID == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "userID is required")
	}
	if activeAccountID == "" {
		// No account selected → no plan context → claim is omitted.
		return nil, nil
	}
	resp, err := f.doGetUserSeats(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing user-seats response", cerr)
		}
	}()
	return decodePlansForAccount(resp, activeAccountID)
}

// doGetUserSeats issues the GET and surfaces transport / status
// errors. Returns the response only when StatusCode == 200; callers
// must close the body.
func (f *UserPlansFetcher) doGetUserSeats(ctx context.Context, userID string) (*http.Response, error) {
	url := fmt.Sprintf("%s/users/%s/seats", f.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building user-seats request", err)
	}
	// Interim RBAC bridge: entitlements-service requires this header
	// to equal the path {user_id}, same convention identity-service's
	// E7-S3a uses.
	req.Header.Set("X-Requester-User-ID", userID)
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "fetching user seats", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("user-seats: unexpected status " + resp.Status)
	}
	return resp, nil
}

// decodePlansForAccount decodes the seats envelope and projects the
// plan ids on the seat whose account_id matches activeAccountID.
// Returns an empty slice (nil error) when the user has no seat on
// that account or the matched seat has no plan.
func decodePlansForAccount(resp *http.Response, activeAccountID string) ([]string, error) {
	var body listUserSeatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding user-seats response", err)
	}
	for _, seat := range body.Seats {
		if seat.AccountID != activeAccountID {
			continue
		}
		if seat.Plan == nil || seat.Plan.ID == "" {
			return nil, nil
		}
		return []string{seat.Plan.ID}, nil
	}
	return nil, nil
}
