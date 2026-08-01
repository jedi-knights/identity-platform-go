// Package entitlementsservice hosts login-ui's HTTP adapters for
// entitlements-service. Today it carries the SeatLister used by the
// E7-S3d account switcher; more will land as login-ui grows Epic 7
// UI surfaces (leave-account, transfer ownership, invite management).
package entitlementsservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// Compile-time interface check — build fails if the port drifts.
var _ ports.SeatLister = (*SeatLister)(nil)

// seatsWireResponse mirrors entitlements-service's listUserSeatsResponse
// (services/entitlements-service internal/adapters/inbound/http/
// list_user_seats_handler.go). Field shape must stay in lockstep — a
// break here is caught by the acceptance tests, not by the compiler.
type seatsWireResponse struct {
	Seats []seatWireDTO `json:"seats"`
}

type seatWireDTO struct {
	SeatID             string           `json:"seat_id"`
	AccountID          string           `json:"account_id"`
	AccountDisplayName string           `json:"account_display_name"`
	Role               string           `json:"role"`
	Plan               *planWireSummary `json:"plan"`
}

type planWireSummary struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
}

// SeatLister calls entitlements-service GET /users/{user_id}/seats.
type SeatLister struct {
	baseURL    string
	httpClient *http.Client
}

// NewSeatLister returns a SeatLister that calls the given
// entitlements-service base URL. baseURL must NOT include the
// /users/... path; the adapter appends it.
func NewSeatLister(baseURL string, httpClient *http.Client) *SeatLister {
	return &SeatLister{baseURL: baseURL, httpClient: httpClient}
}

// ListUserSeats fetches every seat for userID. Empty slice (nil error)
// on a 200 with an empty seats array — the switcher UI treats that as
// "empty state", not error. Non-200 statuses surface as ErrCodeInternal.
func (l *SeatLister) ListUserSeats(ctx context.Context, userID string) (_ []ports.AccountSeat, retErr error) {
	if userID == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "userID is required")
	}
	resp, err := l.doListSeats(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = apperrors.Wrap(apperrors.ErrCodeInternal, "closing list-seats response", cerr)
		}
	}()
	return decodeSeatsResponse(resp)
}

// doListSeats issues the GET with the interim X-Requester-User-ID
// header. Returns the response only when StatusCode == 200; callers
// must close the body.
func (l *SeatLister) doListSeats(ctx context.Context, userID string) (*http.Response, error) {
	url := fmt.Sprintf("%s/users/%s/seats", l.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "building list-seats request", err)
	}
	// entitlements-service's E7-S3b RBAC bridge requires this header
	// to equal the path {user_id}. login-ui is trusted infrastructure
	// speaking to entitlements-service on the user's behalf.
	req.Header.Set("X-Requester-User-ID", userID)
	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "fetching user seats", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("list-seats: unexpected status " + resp.Status)
	}
	return resp, nil
}

// decodeSeatsResponse projects the wire shape to ports.AccountSeat.
// Plan nil on the wire projects to empty PlanCode / PlanName; the
// template renders "No plan" in that case.
func decodeSeatsResponse(resp *http.Response) ([]ports.AccountSeat, error) {
	var body seatsWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "decoding list-seats response", err)
	}
	out := make([]ports.AccountSeat, 0, len(body.Seats))
	for _, s := range body.Seats {
		seat := ports.AccountSeat{
			SeatID:             s.SeatID,
			AccountID:          s.AccountID,
			AccountDisplayName: s.AccountDisplayName,
			Role:               s.Role,
		}
		if s.Plan != nil {
			seat.PlanCode = s.Plan.Code
			seat.PlanName = s.Plan.DisplayName
		}
		out = append(out, seat)
	}
	return out, nil
}
