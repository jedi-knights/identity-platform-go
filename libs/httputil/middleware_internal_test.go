package httputil

import "testing"

// TestNewUUID_FixedWidth confirms that newUUID always produces a well-formed
// 36-character UUID v4 string, including cases where random bytes have leading
// zero nibbles. %x on a []byte in Go always emits exactly 2 hex chars per byte,
// so this should be stable — but the test guards against future refactors that
// switch to integer formatting.
func TestNewUUID_FixedWidth(t *testing.T) {
	const iterations = 10_000
	for range iterations {
		id := newUUID()
		if len(id) != 36 {
			t.Fatalf("newUUID() returned %q with length %d, want 36", id, len(id))
		}
		if !uuidPattern.MatchString(id) {
			t.Fatalf("newUUID() returned %q which does not match the UUID v4 pattern", id)
		}
	}
}
