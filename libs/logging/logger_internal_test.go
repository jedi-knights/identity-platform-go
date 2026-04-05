package logging

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// swapFallbackOutput atomically replaces fallbackOutput and returns the previous
// value. Use in tests only — never call from production code.
func swapFallbackOutput(w io.Writer) io.Writer {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	prev := fallbackOutput
	fallbackOutput = w
	return prev
}

// TestFromContext_FallbackMarker confirms that FromContext's fallback logger
// carries the "logger_source":"fallback" attribute. Uses a white-box swap of
// the unexported fallbackOutput variable so the actual FromContext code path
// is exercised rather than an equivalent logger constructed in the test.
//
// This test mutates package-level state and must not be made parallel.
func TestFromContext_FallbackMarker(t *testing.T) {
	var buf bytes.Buffer
	orig := swapFallbackOutput(&buf)
	t.Cleanup(func() { swapFallbackOutput(orig) })

	l := FromContext(context.Background())
	l.Info("probe")

	// FromContext uses text format; slog text handler renders key=value pairs.
	if !strings.Contains(buf.String(), "logger_source=fallback") {
		t.Errorf("fallback marker missing from FromContext output: %s", buf.String())
	}
}
