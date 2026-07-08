package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// DevicePollError is returned by DeviceCodeStrategy.Handle when the device
// authorization record exists but has not reached a terminal-success state.
// It wraps ErrInvalidGrant so existing errors.Is(err, ErrInvalidGrant) checks
// keep matching, while carrying the specific RFC 8628 §3.5 error code
// (authorization_pending / access_denied / expired_token) the HTTP layer
// must echo back verbatim — unlike the coarse-grained invalid_grant cases
// elsewhere in this file, these codes drive the client's poll/stop decision
// and are not interchangeable.
type DevicePollError struct {
	// Code is the RFC 8628 §3.5 error value: authorization_pending,
	// access_denied, or expired_token. slow_down is intentionally absent —
	// ADR-0022 scopes it out.
	Code string
}

// Error implements the error interface.
func (e *DevicePollError) Error() string {
	return fmt.Sprintf("%s: %s", ErrInvalidGrant, e.Code)
}

// Unwrap lets errors.Is(err, ErrInvalidGrant) match a *DevicePollError.
func (e *DevicePollError) Unwrap() error {
	return ErrInvalidGrant
}

// DeviceCodeStrategy handles the urn:ietf:params:oauth:grant-type:device_code
// grant (RFC 8628 §3.4-3.5, ADR-0022). Unlike every other strategy, the
// interesting authentication event already happened when the user approved
// the request on the verification page (login-ui, via auth-server's
// /internal/device/decision). This strategy's job at poll time is to
// authenticate the polling client and translate the stored
// DeviceAuthorization status into either an issued token pair or one of the
// RFC 8628 §3.5 poll-in-progress errors.
type DeviceCodeStrategy struct {
	clientAuth       ports.ClientAuthenticator
	deviceAuthRepo   domain.DeviceAuthorizationRepository
	tokenRepo        domain.TokenRepository
	refreshTokenRepo domain.RefreshTokenRepository
	tokenGen         TokenGenerator
	permsFetcher     ports.SubjectPermissionsFetcher
	ttl              time.Duration
	refreshTTL       time.Duration
}

// NewDeviceCodeStrategy creates a DeviceCodeStrategy. permsFetcher may be
// nil — when nil, tokens are issued without roles/permissions claims.
func NewDeviceCodeStrategy(
	clientAuth ports.ClientAuthenticator,
	deviceAuthRepo domain.DeviceAuthorizationRepository,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	ttl time.Duration,
	refreshTTL time.Duration,
) *DeviceCodeStrategy {
	return &DeviceCodeStrategy{
		clientAuth:       clientAuth,
		deviceAuthRepo:   deviceAuthRepo,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
	}
}

// Supports reports whether this strategy handles the given grant type.
func (s *DeviceCodeStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeDeviceCode
}

// Handle authenticates the polling client, resolves the device
// authorization's current status, and either issues tokens (approved) or
// returns the matching *DevicePollError (pending / denied / not found).
func (s *DeviceCodeStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	if req.DeviceCode == "" {
		return nil, fmt.Errorf("%w: device_code is required", ErrInvalidRequest)
	}
	client, err := s.validateClient(ctx, req)
	if err != nil {
		return nil, err
	}
	auth, err := s.findOwnedDeviceAuth(ctx, req.DeviceCode, client.ID)
	if err != nil {
		return nil, err
	}
	return s.resolveStatus(ctx, auth, client)
}

// validateClient authenticates the polling client and checks it is
// registered for the device_code grant. Extracted from Handle to keep its
// cyclomatic complexity within bounds.
func (s *DeviceCodeStrategy) validateClient(ctx context.Context, req domain.GrantRequest) (*domain.Client, error) {
	client, err := s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeDeviceCode) {
		return nil, apperrors.New(apperrors.ErrCodeForbidden, "grant type not allowed for client")
	}
	return client, nil
}

// findOwnedDeviceAuth looks up the device_code and verifies it was issued
// to clientID. A device_code issued to a different client is treated
// identically to "not found" — the poller must not be able to distinguish
// "wrong client" from "expired" for a code it doesn't own. Extracted from
// Handle to keep its cyclomatic complexity within bounds.
func (s *DeviceCodeStrategy) findOwnedDeviceAuth(ctx context.Context, deviceCode, clientID string) (*domain.DeviceAuthorization, error) {
	auth, err := s.deviceAuthRepo.FindByDeviceCode(ctx, deviceCode)
	if err != nil || auth.ClientID != clientID {
		return nil, &DevicePollError{Code: "expired_token"}
	}
	return auth, nil
}

// resolveStatus translates the device authorization's current status into
// either an issued token pair (approved) or the matching *DevicePollError.
// Extracted from Handle to keep its cyclomatic complexity within bounds.
func (s *DeviceCodeStrategy) resolveStatus(ctx context.Context, auth *domain.DeviceAuthorization, client *domain.Client) (*domain.GrantResponse, error) {
	switch auth.Status {
	case domain.DeviceAuthorizationPending:
		return nil, &DevicePollError{Code: "authorization_pending"}
	case domain.DeviceAuthorizationDenied:
		return nil, &DevicePollError{Code: "access_denied"}
	case domain.DeviceAuthorizationApproved:
		return s.issueForApproved(ctx, auth.DeviceCode, client)
	default:
		return nil, &DevicePollError{Code: "expired_token"}
	}
}

// issueForApproved consumes the approved record and issues the token pair.
// Extracted from Handle to keep its cyclomatic complexity within bounds.
func (s *DeviceCodeStrategy) issueForApproved(ctx context.Context, deviceCode string, client *domain.Client) (*domain.GrantResponse, error) {
	consumed, err := s.deviceAuthRepo.Consume(ctx, deviceCode)
	if err != nil {
		// Lost the race to another poller between FindByDeviceCode and
		// Consume — report the same outcome a genuinely expired code would.
		return nil, &DevicePollError{Code: "expired_token"}
	}

	scopes := strings.Fields(consumed.Scope)
	var roles, permissions []string
	if s.permsFetcher != nil {
		roles, permissions, _ = s.permsFetcher.GetSubjectPermissions(ctx, consumed.Subject)
	}

	now := time.Now()
	raw, err := s.issueAccessToken(ctx, client, consumed.Subject, scopes, roles, permissions, now)
	if err != nil {
		return nil, err
	}
	refreshRaw, err := s.issueRefreshToken(ctx, client.ID, consumed.Subject, scopes, now)
	if err != nil {
		return nil, err
	}

	return &domain.GrantResponse{
		AccessToken:  raw,
		TokenType:    string(domain.TokenTypeBearer),
		ExpiresIn:    int(s.ttl.Seconds()),
		RefreshToken: refreshRaw,
		Scope:        consumed.Scope,
		ActorType:    domain.ActorTypeUser,
		Subject:      consumed.Subject,
	}, nil
}

// issueAccessToken generates a token ID, builds the domain.Token for
// subject, signs it as a JWT, and persists it. No ID token is issued —
// device flow has no OIDC redirect leg to carry a nonce.
func (s *DeviceCodeStrategy) issueAccessToken(ctx context.Context, client *domain.Client, subject string, scopes, roles, permissions []string, now time.Time) (string, error) {
	tokenID, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating token id", err)
	}
	token := &domain.Token{
		ID:          tokenID,
		ClientID:    client.ID,
		Subject:     subject,
		Scopes:      scopes,
		Roles:       roles,
		Permissions: permissions,
		ActorType:   domain.ActorTypeUser,
		ExpiresAt:   now.Add(s.ttl),
		IssuedAt:    now,
		TokenType:   domain.TokenTypeBearer,
	}
	raw, err := s.tokenGen.Generate(ctx, token)
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "token generation failed", err)
	}
	token.Raw = raw
	if err := s.tokenRepo.Save(ctx, token); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "token save failed", err)
	}
	return raw, nil
}

// issueRefreshToken generates, persists, and returns a new opaque refresh
// token for subject.
func (s *DeviceCodeStrategy) issueRefreshToken(ctx context.Context, clientID, subject string, scopes []string, now time.Time) (string, error) {
	refreshRaw, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token raw value", err)
	}
	refreshID, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token id", err)
	}
	rt := &domain.RefreshToken{
		ID:        refreshID,
		Raw:       refreshRaw,
		ClientID:  clientID,
		Subject:   subject,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.refreshTTL),
	}
	if err := s.refreshTokenRepo.Save(ctx, rt); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "saving refresh token", err)
	}
	return refreshRaw, nil
}
