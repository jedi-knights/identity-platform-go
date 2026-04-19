//go:build unit

package domain_test

import (
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// --- Client ---

func TestClient_HasScope_Present(t *testing.T) {
	c := &domain.Client{Scopes: []string{"read", "write"}}
	if !c.HasScope("read") {
		t.Error("HasScope(read) = false, want true")
	}
}

func TestClient_HasScope_Absent(t *testing.T) {
	c := &domain.Client{Scopes: []string{"read"}}
	if c.HasScope("admin") {
		t.Error("HasScope(admin) = true, want false")
	}
}

func TestClient_HasScope_Empty(t *testing.T) {
	c := &domain.Client{}
	if c.HasScope("read") {
		t.Error("HasScope on empty scopes = true, want false")
	}
}

func TestClient_HasGrantType_Present(t *testing.T) {
	c := &domain.Client{GrantTypes: []domain.GrantType{domain.GrantTypeClientCredentials}}
	if !c.HasGrantType(domain.GrantTypeClientCredentials) {
		t.Error("HasGrantType(client_credentials) = false, want true")
	}
}

func TestClient_HasGrantType_Absent(t *testing.T) {
	c := &domain.Client{GrantTypes: []domain.GrantType{domain.GrantTypeClientCredentials}}
	if c.HasGrantType(domain.GrantTypeAuthorizationCode) {
		t.Error("HasGrantType(authorization_code) = true, want false")
	}
}

func TestClient_HasRedirectURI_Present(t *testing.T) {
	c := &domain.Client{RedirectURIs: []string{"https://example.com/cb"}}
	if !c.HasRedirectURI("https://example.com/cb") {
		t.Error("HasRedirectURI = false, want true")
	}
}

func TestClient_HasRedirectURI_Absent(t *testing.T) {
	c := &domain.Client{RedirectURIs: []string{"https://example.com/cb"}}
	if c.HasRedirectURI("https://attacker.com") {
		t.Error("HasRedirectURI for unknown URI = true, want false")
	}
}

// --- Token ---

func TestToken_IsExpiredAt_Expired(t *testing.T) {
	tok := &domain.Token{ExpiresAt: time.Now().Add(-time.Minute)}
	if !tok.IsExpiredAt(time.Now()) {
		t.Error("IsExpiredAt(now) for past ExpiresAt = false, want true")
	}
}

func TestToken_IsExpiredAt_NotExpired(t *testing.T) {
	tok := &domain.Token{ExpiresAt: time.Now().Add(time.Hour)}
	if tok.IsExpiredAt(time.Now()) {
		t.Error("IsExpiredAt(now) for future ExpiresAt = true, want false")
	}
}

func TestToken_IsExpiredAt_ExactlyAtBoundary(t *testing.T) {
	boundary := time.Now().Add(time.Hour)
	tok := &domain.Token{ExpiresAt: boundary}
	// IsExpiredAt uses After: now.After(expiresAt) is false when now == expiresAt.
	if tok.IsExpiredAt(boundary) {
		t.Error("IsExpiredAt at exact boundary should be false (not yet expired)")
	}
}

func TestToken_IsExpired_LiveClock(t *testing.T) {
	// IsExpired uses time.Now() — just verify it returns false for a future token.
	tok := &domain.Token{ExpiresAt: time.Now().Add(time.Hour)}
	if tok.IsExpired() {
		t.Error("IsExpired for future token = true, want false")
	}
}

func TestToken_HasScope_Present(t *testing.T) {
	tok := &domain.Token{Scopes: []string{"read", "write"}}
	if !tok.HasScope("write") {
		t.Error("HasScope(write) = false, want true")
	}
}

func TestToken_HasScope_Absent(t *testing.T) {
	tok := &domain.Token{Scopes: []string{"read"}}
	if tok.HasScope("admin") {
		t.Error("HasScope(admin) = true, want false")
	}
}

func TestToken_HasScope_Empty(t *testing.T) {
	tok := &domain.Token{}
	if tok.HasScope("read") {
		t.Error("HasScope on empty token = true, want false")
	}
}
