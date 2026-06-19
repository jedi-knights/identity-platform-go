package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// seedUserForVerification creates a user via the repository so the tests work against the
// same Save contract as production.
func seedUserForVerification(t *testing.T, users domain.UserRepository, email string, now time.Time) *domain.User {
	t.Helper()
	u := &domain.User{
		ID:           "user-" + email,
		Email:        email,
		PasswordHash: "irrelevant",
		Name:         "Test",
		CreatedAt:    now,
		UpdatedAt:    now,
		Active:       true,
	}
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func newVerificationSvc(t *testing.T, sender domain.EmailSender, urlTemplate string) (
	*application.EmailVerificationService,
	domain.UserRepository,
	domain.VerificationTokenRepository,
) {
	t.Helper()
	users := memory.NewUserRepository()
	tokens := memory.NewVerificationTokenRepository()
	svc := application.NewEmailVerificationService(users, tokens, sender, application.EmailVerificationConfig{
		TokenTTL:                15 * time.Minute,
		VerificationURLTemplate: urlTemplate,
		TokenByteLength:         16,
	})
	return svc, users, tokens
}

func TestRequestVerification_SendsEmailAndStoresToken(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users, _ := newVerificationSvc(t, sender, "https://app/verify?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForVerification(t, users, "alice@example.com", now)

	if err := svc.RequestVerification(context.Background(), domain.RequestVerificationRequest{Email: "alice@example.com"}); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}

	msgs := sender.Drain()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 email, got %d", len(msgs))
	}
	if msgs[0].To != "alice@example.com" {
		t.Errorf("To = %q, want alice@example.com", msgs[0].To)
	}
	if !strings.HasPrefix(msgs[0].VerificationURL, "https://app/verify?token=") {
		t.Errorf("VerificationURL = %q, want template-rendered URL", msgs[0].VerificationURL)
	}
}

func TestRequestVerification_UnknownEmail_NoErrorNoEmail(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")

	err := svc.RequestVerification(context.Background(), domain.RequestVerificationRequest{Email: "nobody@example.com"})
	if err != nil {
		t.Fatalf("expected silent success for unknown email, got %v", err)
	}

	if got := sender.Drain(); len(got) != 0 {
		t.Fatalf("no email should be sent for unknown user; got %d", len(got))
	}
}

func TestRequestVerification_AlreadyVerified_NoEmail(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForVerification(t, users, "bob@example.com", now)

	// Mark verified directly.
	if err := users.MarkEmailVerified(context.Background(), "user-bob@example.com", now); err != nil {
		t.Fatalf("seed verified user: %v", err)
	}

	if err := svc.RequestVerification(context.Background(), domain.RequestVerificationRequest{Email: "bob@example.com"}); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	if got := sender.Drain(); len(got) != 0 {
		t.Fatalf("no email should be sent when already verified; got %d", len(got))
	}
}

func TestRequestVerification_EmptyEmail_BadRequest(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")

	err := svc.RequestVerification(context.Background(), domain.RequestVerificationRequest{Email: "   "})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeBadRequest {
		t.Fatalf("expected ErrCodeBadRequest, got %v", err)
	}
}

func TestVerifyEmail_HappyPath_MarksVerified(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForVerification(t, users, "carol@example.com", now)

	if err := svc.RequestVerification(context.Background(), domain.RequestVerificationRequest{Email: "carol@example.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	msgs := sender.Drain()
	if len(msgs) != 1 {
		t.Fatalf("want 1 email, got %d", len(msgs))
	}

	// Extract the token from the URL.
	token := tokenFromURL(t, msgs[0].VerificationURL)

	resp, err := svc.VerifyEmail(context.Background(), domain.VerifyEmailRequest{Token: token})
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if resp.Email != "carol@example.com" {
		t.Errorf("Email = %q, want carol@example.com", resp.Email)
	}

	// User should now be verified.
	u, err := users.FindByID(context.Background(), "user-carol@example.com")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if !u.IsEmailVerified() {
		t.Fatalf("user should be verified after redemption")
	}
}

func TestVerifyEmail_UnknownToken_Unauthorized(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")

	_, err := svc.VerifyEmail(context.Background(), domain.VerifyEmailRequest{Token: "totally-fake"})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeUnauthorized {
		t.Fatalf("expected ErrCodeUnauthorized, got %v", err)
	}
}

func TestVerifyEmail_TokenReplay_Unauthorized(t *testing.T) {
	sender := email.NewBufferSender()
	svc, users, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	seedUserForVerification(t, users, "dave@example.com", now)

	if err := svc.RequestVerification(context.Background(), domain.RequestVerificationRequest{Email: "dave@example.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	token := tokenFromURL(t, sender.Drain()[0].VerificationURL)

	if _, err := svc.VerifyEmail(context.Background(), domain.VerifyEmailRequest{Token: token}); err != nil {
		t.Fatalf("first redeem: %v", err)
	}

	// Second attempt with the same token must fail.
	_, err := svc.VerifyEmail(context.Background(), domain.VerifyEmailRequest{Token: token})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeUnauthorized {
		t.Fatalf("replay should be Unauthorized, got %v", err)
	}
}

func TestVerifyEmail_EmptyToken_BadRequest(t *testing.T) {
	sender := email.NewBufferSender()
	svc, _, _ := newVerificationSvc(t, sender, "https://app?token={{token}}")

	_, err := svc.VerifyEmail(context.Background(), domain.VerifyEmailRequest{Token: ""})
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.Code() != apperrors.ErrCodeBadRequest {
		t.Fatalf("expected ErrCodeBadRequest, got %v", err)
	}
}

func tokenFromURL(t *testing.T, url string) string {
	t.Helper()
	idx := strings.LastIndex(url, "token=")
	if idx < 0 {
		t.Fatalf("URL has no token= component: %q", url)
	}
	return url[idx+len("token="):]
}
