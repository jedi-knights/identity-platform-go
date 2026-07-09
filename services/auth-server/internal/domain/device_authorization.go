package domain

import (
	"context"
	"errors"
	"time"
)

// ErrDeviceAuthorizationNotFound is returned by DeviceAuthorizationRepository
// lookups (FindByDeviceCode, FindByUserCode, Consume) when no record exists
// for the requested key. Both "never existed" and "expired" collapse to this
// sentinel — RFC 8628 §3.5 maps both to the same expired_token response, so
// callers do not need to distinguish them.
var ErrDeviceAuthorizationNotFound = errors.New("device authorization not found")

// DeviceAuthorizationStatus is the lifecycle state of a device authorization
// request, per RFC 8628 §3.5's polling outcomes.
type DeviceAuthorizationStatus string

const (
	// DeviceAuthorizationPending is the initial state — the user has not
	// yet visited the verification URI, or has visited it but not decided.
	DeviceAuthorizationPending DeviceAuthorizationStatus = "pending"
	// DeviceAuthorizationApproved is set by Approve once the user
	// authenticates and grants the request on the verification page.
	DeviceAuthorizationApproved DeviceAuthorizationStatus = "approved"
	// DeviceAuthorizationDenied is set by Deny when the user rejects the
	// request on the verification page.
	DeviceAuthorizationDenied DeviceAuthorizationStatus = "denied"
)

// DeviceAuthorization is the server-side record for an RFC 8628 device
// authorization request (§3.1-3.2). It is created by POST /device_authorization
// and looked up two ways for the rest of its lifecycle: by DeviceCode (the
// token endpoint polls this key) and by UserCode (the verification page
// looks up this key). ADR-0022 documents why this needs a two-key repository
// design, unlike AuthorizationCode's single-key Consume.
type DeviceAuthorization struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scope      string
	Status     DeviceAuthorizationStatus
	// Subject identifies the user who approved the request. Empty until
	// Approve sets it; ignored when Status is not approved.
	Subject string
	// Interval is the RFC 8628 §3.2 advertised minimum polling interval in
	// seconds, echoed back to the client in the device_authorization
	// response and stored here only so a future slow_down implementation
	// (out of scope per ADR-0022) would have somewhere to read it from.
	Interval  int
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpiredAt reports whether the record is past its expiry as of now. The
// boundary is inclusive on the expired side, matching AuthorizationCode's
// convention — a record whose ExpiresAt equals now is treated as expired.
func (d *DeviceAuthorization) IsExpiredAt(now time.Time) bool {
	return !now.Before(d.ExpiresAt)
}

// DeviceAuthorizationRepository is the persistence port for device
// authorization requests (RFC 8628). Implementations must satisfy:
//
//   - FindByDeviceCode and FindByUserCode are read-only lookups — the token
//     endpoint polls FindByDeviceCode repeatedly while the request is
//     pending, and must be able to observe "still pending" without
//     consuming the record.
//   - Approve and Deny are idempotent state transitions keyed by UserCode
//     (the value the human enters on the verification page).
//   - Consume atomically reads and deletes, keyed by DeviceCode, exactly
//     like AuthorizationCodeRepository.Consume — this is what makes token
//     issuance single-use even under concurrent polling.
type DeviceAuthorizationRepository interface {
	// Save persists a newly created device authorization request.
	Save(ctx context.Context, auth *DeviceAuthorization) error

	// FindByDeviceCode returns the record for deviceCode, or
	// ErrDeviceAuthorizationNotFound if it does not exist or has expired.
	// Does not delete — safe to call on every poll.
	FindByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuthorization, error)

	// FindByUserCode returns the record for userCode, or
	// ErrDeviceAuthorizationNotFound if it does not exist or has expired.
	// Backs the verification page's initial lookup before rendering the
	// approve/deny decision to the user.
	FindByUserCode(ctx context.Context, userCode string) (*DeviceAuthorization, error)

	// Approve transitions the record identified by userCode to Approved and
	// records subject as the approving principal. Returns
	// ErrDeviceAuthorizationNotFound if userCode is unknown or expired.
	Approve(ctx context.Context, userCode, subject string) error

	// Deny transitions the record identified by userCode to Denied. Returns
	// ErrDeviceAuthorizationNotFound if userCode is unknown or expired.
	Deny(ctx context.Context, userCode string) error

	// Consume atomically reads and deletes the record identified by
	// deviceCode. Returns ErrDeviceAuthorizationNotFound for unknown,
	// expired, or already-consumed codes. Called only once the token
	// endpoint has observed Status == approved via FindByDeviceCode, so a
	// racing second poll — or replay of an already-redeemed device_code —
	// sees not-found rather than issuing a second token pair.
	Consume(ctx context.Context, deviceCode string) (*DeviceAuthorization, error)
}
