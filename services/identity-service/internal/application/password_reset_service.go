// Password reset flow. Mirror of email verification but with:
//
//   - Distinct token table (password_reset_tokens) so the two flows can have
//     independent TTL / rate-limit / revocation policies
//   - Distinct EmailSender method (SendPasswordResetEmail) so transactional
//     senders can render different copy and "Reset" vs "Verify" subjects
//   - Shorter default TTL (1h) — a reset link is a higher-value secret than
//     a verification link, so its window of usefulness should be smaller
//   - Minimum-password-length policy applied here so a service-level
//     password-policy change requires a single edit
package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// PasswordResetConfig holds tunables for the password-reset flow.
type PasswordResetConfig struct {
	// TokenTTL is how long a freshly issued reset token remains redeemable.
	// Defaults to 1 hour when zero.
	TokenTTL time.Duration

	// ResetURLTemplate is interpolated with the plaintext token and handed
	// to the EmailSender. Use "{{token}}" as the placeholder.
	//
	// Example: "https://app.example.com/reset-password?token={{token}}"
	ResetURLTemplate string

	// TokenByteLength is the size of the random token in bytes. Defaults
	// to 32 (256 bits → 43-char base64 string).
	TokenByteLength int

	// MinPasswordLength applied to the new-password field on ResetPassword.
	// Defaults to 8.
	MinPasswordLength int
}

// PasswordResetService implements ports.PasswordResetter.
type PasswordResetService struct {
	users  domain.UserRepository
	tokens domain.PasswordResetTokenRepository
	sender domain.EmailSender
	hasher domain.PasswordHasher
	cfg    PasswordResetConfig
	now    func() time.Time
}

// NewPasswordResetService wires the password-reset flow.
func NewPasswordResetService(
	users domain.UserRepository,
	tokens domain.PasswordResetTokenRepository,
	sender domain.EmailSender,
	hasher domain.PasswordHasher,
	cfg PasswordResetConfig,
) *PasswordResetService {
	cfg = applyPasswordResetDefaults(cfg)
	return &PasswordResetService{
		users:  users,
		tokens: tokens,
		sender: sender,
		hasher: hasher,
		cfg:    cfg,
		now:    time.Now,
	}
}

// RequestReset issues a token and sends the user a reset URL.
//
// Like the verification request, the response shape never leaks information
// about whether the email is on file — every caller-visible outcome is the
// same.
func (s *PasswordResetService) RequestReset(
	ctx context.Context,
	req domain.RequestPasswordResetRequest,
) error {
	if strings.TrimSpace(req.Email) == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "email is required")
	}

	user, err := s.users.FindByEmail(ctx, req.Email)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return nil // silent success
		}
		return fmt.Errorf("looking up user: %w", err)
	}

	plaintext, hash, err := newToken(s.cfg.TokenByteLength)
	if err != nil {
		return fmt.Errorf("generating token: %w", err)
	}

	now := s.now()
	record := &domain.PasswordResetToken{
		TokenHash: hash,
		UserID:    user.ID,
		ExpiresAt: now.Add(s.cfg.TokenTTL),
		CreatedAt: now,
	}
	if err := s.tokens.Save(ctx, record); err != nil {
		return fmt.Errorf("saving reset token: %w", err)
	}

	url, err := renderResetURL(s.cfg.ResetURLTemplate, plaintext)
	if err != nil {
		return fmt.Errorf("rendering reset URL: %w", err)
	}

	if err := s.sender.SendPasswordResetEmail(ctx, domain.PasswordResetEmail{
		To:       user.Email,
		Name:     user.Name,
		ResetURL: url,
	}); err != nil {
		return fmt.Errorf("sending reset email: %w", err)
	}

	return nil
}

// ResetPassword redeems a token and updates the user's password hash. All
// "this token is no good" cases collapse to ErrCodeUnauthorized.
func (s *PasswordResetService) ResetPassword(
	ctx context.Context,
	req domain.ResetPasswordRequest,
) (*domain.ResetPasswordResponse, error) {
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "token is required")
	}
	if len(req.NewPassword) < s.cfg.MinPasswordLength {
		return nil, apperrors.New(
			apperrors.ErrCodeBadRequest,
			fmt.Sprintf("new_password must be at least %d characters", s.cfg.MinPasswordLength),
		)
	}

	hash := hashToken(token)

	record, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid or expired token")
		}
		return nil, fmt.Errorf("looking up token: %w", err)
	}

	now := s.now()
	if !record.ExpiresAt.After(now) || record.UsedAt != nil {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid or expired token")
	}

	newHash, err := s.hasher.Hash(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	user, err := s.users.FindByID(ctx, record.UserID)
	if err != nil {
		return nil, fmt.Errorf("loading user for reset: %w", err)
	}

	user.PasswordHash = newHash
	user.UpdatedAt = now
	if err := s.users.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("updating user password: %w", err)
	}

	if err := s.tokens.MarkUsed(ctx, hash, now); err != nil {
		return nil, fmt.Errorf("marking token used: %w", err)
	}

	return &domain.ResetPasswordResponse{
		UserID: user.ID,
		Email:  user.Email,
	}, nil
}

// applyPasswordResetDefaults fills in zero-value fields.
func applyPasswordResetDefaults(cfg PasswordResetConfig) PasswordResetConfig {
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = time.Hour
	}
	if cfg.TokenByteLength == 0 {
		cfg.TokenByteLength = 32
	}
	if cfg.MinPasswordLength == 0 {
		cfg.MinPasswordLength = 8
	}
	return cfg
}

// renderResetURL substitutes {{token}} in the template; empty template
// returns just the token (useful for the stdout sender / tests).
func renderResetURL(template, token string) (string, error) {
	if template == "" {
		return token, nil
	}
	if !strings.Contains(template, "{{token}}") {
		return "", fmt.Errorf("template missing {{token}} placeholder")
	}
	return strings.ReplaceAll(template, "{{token}}", token), nil
}
