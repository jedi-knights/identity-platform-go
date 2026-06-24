//go:build unit

package domain_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestScopeConstants(t *testing.T) {
	// Arrange / Act / Assert — the wire values are stable per OIDC Core §3.1.2.1
	// and §5.4. Pinning them in a test stops a copy-paste rename from breaking
	// interop with every OIDC client library in the world.
	if domain.ScopeOpenID != "openid" {
		t.Errorf("ScopeOpenID = %q, want %q", domain.ScopeOpenID, "openid")
	}
	if domain.ScopeProfile != "profile" {
		t.Errorf("ScopeProfile = %q, want %q", domain.ScopeProfile, "profile")
	}
	if domain.ScopeEmail != "email" {
		t.Errorf("ScopeEmail = %q, want %q", domain.ScopeEmail, "email")
	}
}

func TestHasScope_Present(t *testing.T) {
	// Arrange
	scopes := []string{"openid", "email", "read"}

	// Act / Assert
	if !domain.HasScope(scopes, domain.ScopeOpenID) {
		t.Error("HasScope(openid) = false, want true")
	}
	if !domain.HasScope(scopes, domain.ScopeEmail) {
		t.Error("HasScope(email) = false, want true")
	}
}

func TestHasScope_Absent(t *testing.T) {
	// Arrange
	scopes := []string{"read", "write"}

	// Act / Assert
	if domain.HasScope(scopes, domain.ScopeOpenID) {
		t.Error("HasScope(openid) = true, want false")
	}
}

func TestHasScope_EmptyTarget(t *testing.T) {
	// Arrange — defensive: empty target must not match any non-empty entry.
	if domain.HasScope([]string{"openid"}, "") {
		t.Error("HasScope with empty target = true, want false")
	}
}

func TestHasScope_NilSlice(t *testing.T) {
	// Arrange / Act / Assert — nil slice is no scopes; never matches.
	if domain.HasScope(nil, domain.ScopeOpenID) {
		t.Error("HasScope on nil slice = true, want false")
	}
}
