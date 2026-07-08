package allure

import (
	"testing"
	"time"
)

// parseTestTime parses an RFC3339 timestamp for use in test fixtures,
// failing the test immediately on a malformed literal rather than
// propagating a parse error into the assertion being tested.
func parseTestTime(t *testing.T, s string) time.Time {
	t.Helper()

	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parsing test time %q: %v", s, err)
	}
	return ts
}
