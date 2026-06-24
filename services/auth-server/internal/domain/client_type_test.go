//go:build unit

package domain_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestClientType_Constants(t *testing.T) {
	// Arrange / Act / Assert — the two values are the only ones the platform
	// recognises. Any third value the registry sends is treated as
	// confidential at the boundary.
	if domain.ClientTypeConfidential != "confidential" {
		t.Errorf("ClientTypeConfidential = %q, want %q", domain.ClientTypeConfidential, "confidential")
	}
	if domain.ClientTypePublic != "public" {
		t.Errorf("ClientTypePublic = %q, want %q", domain.ClientTypePublic, "public")
	}
}

func TestClient_IsPublic_PublicType(t *testing.T) {
	// Arrange
	c := &domain.Client{Type: domain.ClientTypePublic}

	// Act / Assert
	if !c.IsPublic() {
		t.Error("IsPublic() = false for ClientTypePublic")
	}
	if c.IsConfidential() {
		t.Error("IsConfidential() = true for ClientTypePublic")
	}
}

func TestClient_IsConfidential_ConfidentialType(t *testing.T) {
	// Arrange
	c := &domain.Client{Type: domain.ClientTypeConfidential}

	// Act / Assert
	if c.IsPublic() {
		t.Error("IsPublic() = true for ClientTypeConfidential")
	}
	if !c.IsConfidential() {
		t.Error("IsConfidential() = false for ClientTypeConfidential")
	}
}

func TestClient_ZeroValueTreatedAsConfidential(t *testing.T) {
	// Arrange — backwards-compat: existing clients stored before this field
	// was introduced have Type == "" and must be treated as confidential.
	c := &domain.Client{}

	// Act / Assert
	if c.IsPublic() {
		t.Error("IsPublic() = true for zero-value Type")
	}
	if !c.IsConfidential() {
		t.Error("IsConfidential() = false for zero-value Type")
	}
}

func TestClient_UnknownTypeTreatedAsConfidential(t *testing.T) {
	// Arrange — a future or misconfigured value at the data boundary must
	// fail closed: assume confidential so secret-bearing flows still require
	// the secret. The "public" path is the only one with relaxed auth.
	c := &domain.Client{Type: domain.ClientType("future-mtls")}

	// Act / Assert
	if c.IsPublic() {
		t.Error("IsPublic() = true for unrecognised type; should fail closed to confidential")
	}
	if !c.IsConfidential() {
		t.Error("IsConfidential() = false for unrecognised type; should fail closed to confidential")
	}
}
