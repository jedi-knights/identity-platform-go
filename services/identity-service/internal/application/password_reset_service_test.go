package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

func seedUserForReset(t *testing.T, users domain.UserRepository, address string, now time.Time) {
	t.Helper()
	if err := users.Save(context.Background(), &domain.User{
		ID:           "user-" + address,
		Email:        address,
		PasswordHash: "hashed:original",
		Name:         "Test",
		CreatedAt:    now,
		UpdatedAt:    now,
		Active:       true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func newResetSvc(t *testing.T, sender domain.EmailSender, template string) (
	*application.PasswordResetService,
	domain.UserRepository,
) {
	t.Helper()
	users := memory.NewUserRepository()
	tokens := memory.NewPasswordResetTokenRepository()
	svc := application.NewPasswordResetService(users, tokens, sender, &mockHasher{}, application.PasswordResetConfig{
		TokenTTL:          10 * time.Minute,
		ResetURLTemplate:  template,
		TokenByteLength:   16,
		MinPasswordLength: 8,
	})
	return svc, users
}

func TestRequestReset_SendsEmailAndStoresToken(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users := newResetSvc(t, sender, "https://app/reset?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForReset(t, users, "alice@example.com", now)

	if err := svc.RequestReset(context.Background(), domain.RequestPasswordResetRequest{Email: "alice@example.com"}); err != nil {
		t.Fatalf("RequestReset: %v", err)
	}

	msgs := sender.DrainPasswordResets()
	if len(msgs) != 1 {
		t.Fatalf("want 1 email, got %d", len(msgs))
	}
	if msgs[0].To != "alice@example.com" {
		t.Errorf("To = %q, want alice@example.com", msgs[0].To)
	}
	if msgs[0].ResetURL == "" {
		t.Errorf("ResetURL should be populated")
	}
}

func TestRequestReset_UnknownEmail_Silent(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _ := newResetSvc(t, sender, "https://app?token={{token}}")

	if err := svc.RequestReset(context.Background(), domain.RequestPasswordResetRequest{Email: "nobody@example.com"}); err != nil {
		t.Fatalf("expected silent success, got %v", err)
	}
	if got := sender.DrainPasswordResets(); len(got) != 0 {
		t.Fatalf("no email should be sent for unknown user; got %d", len(got))
	}
}

func TestResetPassword_HappyPath_ChangesHash(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users := newResetSvc(t, sender, "https://app?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForReset(t, users, "carol@example.com", now)

	if err := svc.RequestReset(context.Background(), domain.RequestPasswordResetRequest{Email: "carol@example.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	msgs := sender.DrainPasswordResets()
	if len(msgs) != 1 {
		t.Fatalf("want 1 email, got %d", len(msgs))
	}
	token := tokenFromURL(t, msgs[0].ResetURL)

	resp, err := svc.ResetPassword(context.Background(), domain.ResetPasswordRequest{
		Token:       token,
		NewPassword: "new-strong-password",
	})
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if resp.Email != "carol@example.com" {
		t.Errorf("Email = %q", resp.Email)
	}

	u, err := users.FindByID(context.Background(), "user-carol@example.com")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if u.PasswordHash != "hashed:new-strong-password" {
		t.Errorf("PasswordHash = %q, want hashed:new-strong-password", u.PasswordHash)
	}
}

func TestResetPassword_TooShortPassword_BadRequest(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _ := newResetSvc(t, sender, "https://app?token={{token}}")

	_, err := svc.ResetPassword(context.Background(), domain.ResetPasswordRequest{
		Token:       "anything",
		NewPassword: "short",
	})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeBadRequest {
		t.Fatalf("expected ErrCodeBadRequest for short password, got %v", err)
	}
}

func TestResetPassword_UnknownToken_Unauthorized(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _ := newResetSvc(t, sender, "https://app?token={{token}}")

	_, err := svc.ResetPassword(context.Background(), domain.ResetPasswordRequest{
		Token:       "totally-fake",
		NewPassword: "long-enough-password",
	})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeUnauthorized {
		t.Fatalf("expected ErrCodeUnauthorized, got %v", err)
	}
}

func TestResetPassword_Replay_Unauthorized(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users := newResetSvc(t, sender, "https://app?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForReset(t, users, "dave@example.com", now)

	if err := svc.RequestReset(context.Background(), domain.RequestPasswordResetRequest{Email: "dave@example.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	token := tokenFromURL(t, sender.DrainPasswordResets()[0].ResetURL)

	if _, err := svc.ResetPassword(context.Background(), domain.ResetPasswordRequest{
		Token:       token,
		NewPassword: "new-strong-password",
	}); err != nil {
		t.Fatalf("first reset: %v", err)
	}

	_, err := svc.ResetPassword(context.Background(), domain.ResetPasswordRequest{
		Token:       token,
		NewPassword: "another-password-attempt",
	})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeUnauthorized {
		t.Fatalf("replay should be Unauthorized, got %v", err)
	}
}
