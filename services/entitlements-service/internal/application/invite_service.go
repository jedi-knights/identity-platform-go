package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	"golang.org/x/crypto/bcrypt"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// InviteConfig configures InviteService. TTL is the lifetime of a
// fresh invite (7 days per E7-S2 AC by default at the composition
// root). SignupURLPattern is the template the email adapter fills in
// with the raw token; must contain the "{{token}}" placeholder.
type InviteConfig struct {
	TTL              time.Duration
	SignupURLPattern string
}

// InviteRequest is the shape the HTTP handler forwards to Invite. The
// requester's userID (from the request's authentication context —
// today an X-Requester-User-ID header; JWT claims when auth-server's
// token integration lands) is used for the owner-role check.
type InviteRequest struct {
	AccountID       string
	RequesterUserID string
	InvitedEmail    string
}

// InviteService is the E7-S2 use case: an owner-role seat on an
// account invites another email to occupy a new seat. Emits an
// invite_sent audit event per ADR-0018 + ADR-0019 (paid event because
// downstream Lago customer sync counts seats).
type InviteService struct {
	accounts ports.AccountRepository
	invites  ports.InviteRepository
	seats    ports.SeatRepository
	email    ports.EmailSender
	cfg      InviteConfig
	emitter  audit.Emitter
	service  string
}

// NewInviteService constructs an InviteService. accounts, invites,
// email must be non-nil. The account repository is expected to also
// implement ports.SeatRepository — the memory and postgres adapters
// both do so, since seat management is inseparable from account
// storage.
func NewInviteService(accounts ports.AccountRepository, invites ports.InviteRepository, email ports.EmailSender, cfg InviteConfig) *InviteService {
	if accounts == nil {
		panic("application: NewInviteService called with nil accounts repo")
	}
	if invites == nil {
		panic("application: NewInviteService called with nil invites repo")
	}
	if email == nil {
		panic("application: NewInviteService called with nil email sender")
	}
	seats, ok := accounts.(ports.SeatRepository)
	if !ok {
		panic("application: NewInviteService requires accounts repo to also satisfy SeatRepository")
	}
	return &InviteService{
		accounts: accounts,
		invites:  invites,
		seats:    seats,
		email:    email,
		cfg:      cfg,
		emitter:  audit.New(audit.NoopSink{}),
		service:  "entitlements-service",
	}
}

// WithAudit configures the service's audit emitter. Follows the
// pattern established by AuthService in identity-service — fluent
// setter with a nil-guard.
func (s *InviteService) WithAudit(emitter audit.Emitter, service string) *InviteService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// Invite creates and emails an invite. Returns the newly-created
// invite with RawToken populated (the caller sees the raw token; the
// persisted row stores only the bcrypt hash).
//
// Order of operations:
//  1. Validate input
//  2. RBAC — requester must be an owner-role seat on the account
//  3. Seat-allowance check — current seats + open invites < allowance
//  4. Generate raw token + hash
//  5. Insert invite row (may fail with conflict if an open invite for
//     the same email already exists — that's a duplicate-send)
//  6. Send email (failure surfaces to caller so state doesn't diverge
//     from what was notified)
//  7. Emit audit event
func (s *InviteService) Invite(ctx context.Context, req InviteRequest) (*domain.Invite, error) {
	if err := validateInviteRequest(req); err != nil {
		return nil, err
	}
	if err := s.assertOwnerAndCapacity(ctx, req); err != nil {
		return nil, err
	}
	inv, err := s.createInvite(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.sendInviteEmail(ctx, inv, req.InvitedEmail); err != nil {
		return nil, err
	}
	if err := s.emitInviteSent(ctx, inv); err != nil {
		return nil, err
	}
	return inv, nil
}

func validateInviteRequest(req InviteRequest) error {
	if req.AccountID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "account_id is required")
	}
	if req.RequesterUserID == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "requester_user_id is required")
	}
	if req.InvitedEmail == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "invited_email is required")
	}
	return nil
}

// assertOwnerAndCapacity runs both gate checks — RBAC and
// seat-allowance — so Invite stays under the gocyclo budget. Returns
// the resolved owner-seat ID on success via the request struct field
// (mutation kept internal to the service).
func (s *InviteService) assertOwnerAndCapacity(ctx context.Context, req InviteRequest) error {
	seats, err := s.seats.ListByAccount(ctx, req.AccountID)
	if err != nil {
		return fmt.Errorf("listing seats: %w", err)
	}
	if !isOwner(seats, req.RequesterUserID) {
		return apperrors.New(apperrors.ErrCodeForbidden, "only account owners can invite")
	}
	allowance, err := s.seats.SeatAllowance(ctx, req.AccountID)
	if err != nil {
		return fmt.Errorf("resolving seat allowance: %w", err)
	}
	openInvites, err := s.invites.CountOpen(ctx, req.AccountID)
	if err != nil {
		return fmt.Errorf("counting open invites: %w", err)
	}
	if len(seats)+openInvites >= allowance {
		return apperrors.New(apperrors.ErrCodeConflict,
			fmt.Sprintf("seat limit reached (allowance %d, current %d, pending invites %d) — upgrade plan to invite more members",
				allowance, len(seats), openInvites))
	}
	return nil
}

// isOwner returns true when userID is present in seats with the owner role.
func isOwner(seats []domain.Seat, userID string) bool {
	for _, s := range seats {
		if s.UserID == userID && s.Role == domain.RoleOwner {
			return true
		}
	}
	return false
}

// createInvite generates the raw + hashed token and persists the row.
func (s *InviteService) createInvite(ctx context.Context, req InviteRequest) (*domain.Invite, error) {
	rawToken, err := newInviteToken()
	if err != nil {
		return nil, fmt.Errorf("generating invite token: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hashing invite token: %w", err)
	}
	inviterSeatID, err := s.resolveInviterSeatID(ctx, req)
	if err != nil {
		return nil, err
	}
	stored, err := s.invites.Insert(ctx, domain.Invite{
		AccountID:       req.AccountID,
		InvitedBySeatID: inviterSeatID,
		InvitedEmail:    req.InvitedEmail,
		TokenHash:       string(hash),
		RawToken:        rawToken,
		ExpiresAt:       time.Now().UTC().Add(s.cfg.TTL),
	})
	if err != nil {
		return nil, fmt.Errorf("persisting invite: %w", err)
	}
	stored.RawToken = rawToken
	return stored, nil
}

// resolveInviterSeatID returns the owner seat ID for the requester,
// re-listing seats since the earlier list was inside another method.
// Cost is one map/index lookup per invite — acceptable for the low
// throughput of the invite endpoint.
func (s *InviteService) resolveInviterSeatID(ctx context.Context, req InviteRequest) (string, error) {
	seats, err := s.seats.ListByAccount(ctx, req.AccountID)
	if err != nil {
		return "", fmt.Errorf("re-listing seats for inviter lookup: %w", err)
	}
	for _, seat := range seats {
		if seat.UserID == req.RequesterUserID && seat.Role == domain.RoleOwner {
			return seat.ID, nil
		}
	}
	// Should be unreachable — assertOwnerAndCapacity already verified.
	return "", apperrors.New(apperrors.ErrCodeInternal, "inviter seat vanished between check and use")
}

func (s *InviteService) sendInviteEmail(ctx context.Context, inv *domain.Invite, invitedEmail string) error {
	msg := ports.InviteEmail{
		ToEmail:   invitedEmail,
		SignupURL: strings.ReplaceAll(s.cfg.SignupURLPattern, "{{token}}", inv.RawToken),
		ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
	}
	if err := s.email.SendInvite(ctx, msg); err != nil {
		return fmt.Errorf("sending invite email: %w", err)
	}
	return nil
}

// emitInviteSent emits the ADR-0018 invite_sent event. ActorID is the
// inviter seat's ID (identifies the person who initiated); SubjectID
// is the invite ID so downstream consumers can join to the row.
func (s *InviteService) emitInviteSent(ctx context.Context, inv *domain.Invite) error {
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "invite_sent",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        inv.InvitedBySeatID,
		SubjectID:      inv.ID,
		Resource:       "endpoint:accounts.invites",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "accounts.invites",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/accounts.invites",
		Action:         "create",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"account_id":    inv.AccountID,
			"invited_email": inv.InvitedEmail,
			"expires_at":    inv.ExpiresAt.Format(time.RFC3339),
		},
	}); err != nil {
		return fmt.Errorf("audit emit (invite_sent): %w", err)
	}
	return nil
}

// newInviteToken returns 32 hex-encoded random bytes (256 bits of
// entropy). Sourced from crypto/rand — the token is a bearer credential
// so it must be unguessable.
func newInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
