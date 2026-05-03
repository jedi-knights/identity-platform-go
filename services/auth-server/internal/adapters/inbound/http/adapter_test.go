//go:build unit

package http

import (
	"context"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// fakeIntrospectorSvc implements introspectorSvc for adapter delegation tests.
type fakeIntrospectorSvc struct {
	resp *domain.IntrospectResponse
	err  error
}

func (f *fakeIntrospectorSvc) Introspect(_ context.Context, _ string) (*domain.IntrospectResponse, error) {
	return f.resp, f.err
}

// fakeRevokerSvc implements revokerSvc for adapter delegation tests.
type fakeRevokerSvc struct {
	err error
}

func (f *fakeRevokerSvc) Revoke(_ context.Context, _ string) error {
	return f.err
}

func TestTokenIntrospectorAdapter_DelegatesIntrospect(t *testing.T) {
	tests := []struct {
		name    string
		svc     *fakeIntrospectorSvc
		wantErr bool
	}{
		{
			name: "delegates success response",
			svc:  &fakeIntrospectorSvc{resp: &domain.IntrospectResponse{Active: true, Subject: "user-1"}},
		},
		{
			name:    "delegates error",
			svc:     &fakeIntrospectorSvc{err: errors.New("store unavailable")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			adapter := NewTokenIntrospectorAdapter(tt.svc)

			// Act
			resp, err := adapter.Introspect(context.Background(), "tok")

			// Assert
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp != tt.svc.resp {
				t.Errorf("resp = %v, want %v", resp, tt.svc.resp)
			}
		})
	}
}

func TestTokenRevokerAdapter_DelegatesRevoke(t *testing.T) {
	tests := []struct {
		name    string
		svc     *fakeRevokerSvc
		wantErr bool
	}{
		{
			name: "delegates success",
			svc:  &fakeRevokerSvc{},
		},
		{
			name:    "delegates error",
			svc:     &fakeRevokerSvc{err: errors.New("store unavailable")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			adapter := NewTokenRevokerAdapter(tt.svc)

			// Act
			err := adapter.Revoke(context.Background(), "tok")

			// Assert
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
