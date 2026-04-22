//go:build unit

package observability_test

import (
	"io"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/observability"
)

func TestSetup_ReturnsLogger(t *testing.T) {
	logger, err := observability.Setup(logging.Config{
		Level:       "info",
		Format:      "json",
		ServiceName: "api-gateway",
		Environment: "test",
		Output:      io.Discard,
	})

	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if logger == nil {
		t.Fatal("Setup() returned nil logger")
	}
}

func TestSetup_DoesNotPanicWithEmptyConfig(t *testing.T) {
	logger, err := observability.Setup(logging.Config{Output: io.Discard})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}
