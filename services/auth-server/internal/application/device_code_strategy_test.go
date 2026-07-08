package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// mockDeviceAuthorizationRepo implements domain.DeviceAuthorizationRepository
// for testing. Deliberately simpler than the real adapters — one map keyed
// by DeviceCode, since these tests never need the UserCode index.
type mockDeviceAuthorizationRepo struct {
	byDeviceCode map[string]*domain.DeviceAuthorization
}

func newMockDeviceAuthorizationRepo() *mockDeviceAuthorizationRepo {
	return &mockDeviceAuthorizationRepo{byDeviceCode: make(map[string]*domain.DeviceAuthorization)}
}

func (m *mockDeviceAuthorizationRepo) Save(_ context.Context, auth *domain.DeviceAuthorization) error {
	m.byDeviceCode[auth.DeviceCode] = auth
	return nil
}

func (m *mockDeviceAuthorizationRepo) FindByDeviceCode(_ context.Context, deviceCode string) (*domain.DeviceAuthorization, error) {
	auth, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	return auth, nil
}

func (m *mockDeviceAuthorizationRepo) FindByUserCode(_ context.Context, userCode string) (*domain.DeviceAuthorization, error) {
	for _, auth := range m.byDeviceCode {
		if auth.UserCode == userCode {
			return auth, nil
		}
	}
	return nil, domain.ErrDeviceAuthorizationNotFound
}

func (m *mockDeviceAuthorizationRepo) Approve(_ context.Context, userCode, subject string) error {
	for _, auth := range m.byDeviceCode {
		if auth.UserCode == userCode {
			auth.Status = domain.DeviceAuthorizationApproved
			auth.Subject = subject
			return nil
		}
	}
	return domain.ErrDeviceAuthorizationNotFound
}

func (m *mockDeviceAuthorizationRepo) Deny(_ context.Context, userCode string) error {
	for _, auth := range m.byDeviceCode {
		if auth.UserCode == userCode {
			auth.Status = domain.DeviceAuthorizationDenied
			return nil
		}
	}
	return domain.ErrDeviceAuthorizationNotFound
}

func (m *mockDeviceAuthorizationRepo) Consume(_ context.Context, deviceCode string) (*domain.DeviceAuthorization, error) {
	auth, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	delete(m.byDeviceCode, deviceCode)
	return auth, nil
}

func newTestDeviceAuthorization(deviceCode, userCode, clientID string, status domain.DeviceAuthorizationStatus) *domain.DeviceAuthorization {
	return &domain.DeviceAuthorization{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      "read",
		Status:     status,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Minute),
	}
}

func newDeviceCodeTestClient(id string) *domain.Client {
	return newTestClient(id, "", []string{"read"}, []domain.GrantType{domain.GrantTypeDeviceCode})
}

func TestDeviceCodeStrategy_Supports(t *testing.T) {
	strategy := application.NewDeviceCodeStrategy(nil, nil, nil, nil, nil, nil, time.Hour, 7*24*time.Hour)

	if !strategy.Supports(domain.GrantTypeDeviceCode) {
		t.Error("expected Supports(GrantTypeDeviceCode) = true")
	}
	if strategy.Supports(domain.GrantTypeClientCredentials) {
		t.Error("expected Supports(GrantTypeClientCredentials) = false")
	}
}

func TestDeviceCodeStrategy_Handle_ApprovedIssuesTokens(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	deviceAuthRepo := newMockDeviceAuthorizationRepo()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["cli-client"] = newDeviceCodeTestClient("cli-client")
	approved := newTestDeviceAuthorization("device-1", "USER-1", "cli-client", domain.DeviceAuthorizationApproved)
	approved.Subject = "user-42"
	if err := deviceAuthRepo.Save(context.Background(), approved); err != nil {
		t.Fatalf("Save: %v", err)
	}

	strategy := application.NewDeviceCodeStrategy(auth, deviceAuthRepo, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)

	// Act
	resp, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "cli-client",
		DeviceCode: "device-1",
	})

	// Assert
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	assertApprovedGrantResponse(t, resp)
}

// assertApprovedGrantResponse checks the fields a successful device_code
// issuance must populate. Extracted so the calling test's cyclomatic
// complexity stays within the project's cap of 7.
func assertApprovedGrantResponse(t *testing.T, resp *domain.GrantResponse) {
	t.Helper()
	want := map[string]bool{
		"AccessToken":  resp.AccessToken == "mock-token-123",
		"RefreshToken": resp.RefreshToken != "",
		"Scope":        resp.Scope == "read",
		"ActorType":    resp.ActorType == domain.ActorTypeUser,
		"Subject":      resp.Subject == "user-42",
	}
	for field, ok := range want {
		if !ok {
			t.Errorf("unexpected %s in response: %+v", field, resp)
		}
	}
}

func TestDeviceCodeStrategy_Handle_ApprovedConsumesRecord(t *testing.T) {
	// Arrange — a second poll after a successful issuance must observe
	// expired_token, proving Consume actually ran (single-use).
	auth := newMockClientAuthenticator()
	deviceAuthRepo := newMockDeviceAuthorizationRepo()
	tokenRepo := newMockTokenRepo()
	refreshTokenRepo := newMockRefreshTokenRepo()
	tokenGen := &mockTokenGen{}

	auth.clients["cli-client"] = newDeviceCodeTestClient("cli-client")
	approved := newTestDeviceAuthorization("device-2", "USER-2", "cli-client", domain.DeviceAuthorizationApproved)
	if err := deviceAuthRepo.Save(context.Background(), approved); err != nil {
		t.Fatalf("Save: %v", err)
	}

	strategy := application.NewDeviceCodeStrategy(auth, deviceAuthRepo, tokenRepo, refreshTokenRepo, tokenGen, nil, time.Hour, 7*24*time.Hour)
	req := domain.GrantRequest{GrantType: domain.GrantTypeDeviceCode, ClientID: "cli-client", DeviceCode: "device-2"}
	if _, err := strategy.Handle(context.Background(), req); err != nil {
		t.Fatalf("first Handle: %v", err)
	}

	// Act
	_, err := strategy.Handle(context.Background(), req)

	// Assert
	var pollErr *application.DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("second Handle err = %v, want *DevicePollError", err)
	}
	if pollErr.Code != "expired_token" {
		t.Errorf("second Handle poll code = %q, want expired_token", pollErr.Code)
	}
}

func TestDeviceCodeStrategy_Handle_Pending(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	deviceAuthRepo := newMockDeviceAuthorizationRepo()
	auth.clients["cli-client"] = newDeviceCodeTestClient("cli-client")
	pending := newTestDeviceAuthorization("device-3", "USER-3", "cli-client", domain.DeviceAuthorizationPending)
	if err := deviceAuthRepo.Save(context.Background(), pending); err != nil {
		t.Fatalf("Save: %v", err)
	}
	strategy := application.NewDeviceCodeStrategy(auth, deviceAuthRepo, newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "cli-client",
		DeviceCode: "device-3",
	})

	// Assert
	var pollErr *application.DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("err = %v, want *DevicePollError", err)
	}
	if pollErr.Code != "authorization_pending" {
		t.Errorf("Code = %q, want authorization_pending", pollErr.Code)
	}
	if !errors.Is(err, application.ErrInvalidGrant) {
		t.Error("expected DevicePollError to unwrap to ErrInvalidGrant")
	}
}

func TestDeviceCodeStrategy_Handle_Denied(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	deviceAuthRepo := newMockDeviceAuthorizationRepo()
	auth.clients["cli-client"] = newDeviceCodeTestClient("cli-client")
	denied := newTestDeviceAuthorization("device-4", "USER-4", "cli-client", domain.DeviceAuthorizationDenied)
	if err := deviceAuthRepo.Save(context.Background(), denied); err != nil {
		t.Fatalf("Save: %v", err)
	}
	strategy := application.NewDeviceCodeStrategy(auth, deviceAuthRepo, newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "cli-client",
		DeviceCode: "device-4",
	})

	// Assert
	var pollErr *application.DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("err = %v, want *DevicePollError", err)
	}
	if pollErr.Code != "access_denied" {
		t.Errorf("Code = %q, want access_denied", pollErr.Code)
	}
}

func TestDeviceCodeStrategy_Handle_UnknownDeviceCode(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	auth.clients["cli-client"] = newDeviceCodeTestClient("cli-client")
	strategy := application.NewDeviceCodeStrategy(auth, newMockDeviceAuthorizationRepo(), newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "cli-client",
		DeviceCode: "never-issued",
	})

	// Assert
	var pollErr *application.DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("err = %v, want *DevicePollError", err)
	}
	if pollErr.Code != "expired_token" {
		t.Errorf("Code = %q, want expired_token", pollErr.Code)
	}
}

func TestDeviceCodeStrategy_Handle_DeviceCodeBelongsToDifferentClient(t *testing.T) {
	// Arrange — device_code issued to "cli-client-a" polled by
	// "cli-client-b" must not leak approval state; treat as expired_token.
	auth := newMockClientAuthenticator()
	deviceAuthRepo := newMockDeviceAuthorizationRepo()
	auth.clients["cli-client-a"] = newDeviceCodeTestClient("cli-client-a")
	auth.clients["cli-client-b"] = newDeviceCodeTestClient("cli-client-b")
	approved := newTestDeviceAuthorization("device-5", "USER-5", "cli-client-a", domain.DeviceAuthorizationApproved)
	if err := deviceAuthRepo.Save(context.Background(), approved); err != nil {
		t.Fatalf("Save: %v", err)
	}
	strategy := application.NewDeviceCodeStrategy(auth, deviceAuthRepo, newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "cli-client-b",
		DeviceCode: "device-5",
	})

	// Assert
	var pollErr *application.DevicePollError
	if !errors.As(err, &pollErr) {
		t.Fatalf("err = %v, want *DevicePollError", err)
	}
	if pollErr.Code != "expired_token" {
		t.Errorf("Code = %q, want expired_token", pollErr.Code)
	}
}

func TestDeviceCodeStrategy_Handle_MissingDeviceCode(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	auth.clients["cli-client"] = newDeviceCodeTestClient("cli-client")
	strategy := application.NewDeviceCodeStrategy(auth, newMockDeviceAuthorizationRepo(), newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType: domain.GrantTypeDeviceCode,
		ClientID:  "cli-client",
	})

	// Assert
	if !errors.Is(err, application.ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestDeviceCodeStrategy_Handle_GrantTypeNotAllowedForClient(t *testing.T) {
	// Arrange — client registered without device_code in its grant types.
	auth := newMockClientAuthenticator()
	deviceAuthRepo := newMockDeviceAuthorizationRepo()
	auth.clients["cli-client"] = newTestClient("cli-client", "", []string{"read"}, []domain.GrantType{domain.GrantTypeClientCredentials})
	approved := newTestDeviceAuthorization("device-6", "USER-6", "cli-client", domain.DeviceAuthorizationApproved)
	if err := deviceAuthRepo.Save(context.Background(), approved); err != nil {
		t.Fatalf("Save: %v", err)
	}
	strategy := application.NewDeviceCodeStrategy(auth, deviceAuthRepo, newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "cli-client",
		DeviceCode: "device-6",
	})

	// Assert
	if err == nil {
		t.Fatal("expected error for grant type not allowed")
	}
}

func TestDeviceCodeStrategy_Handle_UnknownClient(t *testing.T) {
	// Arrange
	auth := newMockClientAuthenticator()
	strategy := application.NewDeviceCodeStrategy(auth, newMockDeviceAuthorizationRepo(), newMockTokenRepo(), newMockRefreshTokenRepo(), &mockTokenGen{}, nil, time.Hour, 7*24*time.Hour)

	// Act
	_, err := strategy.Handle(context.Background(), domain.GrantRequest{
		GrantType:  domain.GrantTypeDeviceCode,
		ClientID:   "never-registered",
		DeviceCode: "device-7",
	})

	// Assert
	if err == nil {
		t.Fatal("expected error for unknown client")
	}
}
