//go:build unit

package http

// White-box tests for gzipResponseWriter that require internal access.
// Black-box tests are in middleware_test.go.

import (
	"compress/gzip"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
)

func newDiscardLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger(logging.Config{Output: io.Discard})
}

// TestGzipResponseWriter_FinishIsIdempotent verifies that calling finish() twice
// on the same gzipResponseWriter does not panic. The gz=nil guard after Close()
// prevents the second call from writing a corrupt duplicate gzip footer.
func TestGzipResponseWriter_FinishIsIdempotent(t *testing.T) {
	// Arrange
	rr := httptest.NewRecorder()
	// minSizeBytes=1 ensures gzip is armed on the first write, exercising the compressed path.
	grw := newGzipResponseWriter(rr, gzip.DefaultCompression, 1, newDiscardLogger(t))
	grw.Header().Set("Content-Type", "application/json")
	body := strings.Repeat(`{"k":"v"}`, 10)
	if _, err := grw.Write([]byte(body)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Act — first finish flushes and closes the gzip writer, setting gz=nil
	grw.finish()

	// Assert — gz is nil after first finish (this is the guard the test exercises)
	if grw.gz != nil {
		t.Error("gz must be nil after finish() to prevent double-close")
	}

	// Assert — output is a well-formed gzip stream with intact content
	r, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatalf("output is not a valid gzip stream: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("gzip stream corrupt: %v", err)
	}
	if closeErr := r.Close(); closeErr != nil {
		t.Fatalf("gzip reader checksum error: %v", closeErr)
	}
	if string(got) != body {
		t.Errorf("decompressed body = %q, want %q", got, body)
	}

	// Assert — second finish must not panic (double-close guard: gz=nil after first close)
	grw.finish()
}

// TestGzipResponseWriter_FinishOnUnarmedWriter verifies that finish() does not panic
// when the writer has never been written to. When the buffer is empty, flushBuffered
// takes the plain path (no gzip arming) and gz is never set; the second call hits the
// headersDone=true, gz=nil guard and returns immediately.
func TestGzipResponseWriter_FinishOnUnarmedWriter(t *testing.T) {
	// Arrange
	rr := httptest.NewRecorder()
	// Large minSizeBytes ensures gzip is never armed regardless of body size.
	grw := newGzipResponseWriter(rr, gzip.DefaultCompression, 1024, newDiscardLogger(t))

	// Act
	grw.finish()
	grw.finish()

	// Assert — headersDone and gz=nil confirm the correct code path was taken
	if !grw.headersDone {
		t.Error("headersDone should be true after finish()")
	}
	if grw.gz != nil {
		t.Error("gz should be nil after finish() on unarmed writer")
	}
	if got := rr.Body.String(); got != "" {
		t.Errorf("body = %q, want empty for unarmed writer", got)
	}
}

// TestGzipResponseWriter_FinishOnNonCompressibleContent verifies that finish() does not
// panic when the Content-Type is not compressible. Even with a body large enough to
// cross the minSizeBytes threshold, isCompressible returns false so gz is never armed.
func TestGzipResponseWriter_FinishOnNonCompressibleContent(t *testing.T) {
	// Arrange
	rr := httptest.NewRecorder()
	// minSizeBytes=1 so the size threshold is crossed; compression is blocked by content-type only.
	grw := newGzipResponseWriter(rr, gzip.DefaultCompression, 1, newDiscardLogger(t))
	grw.Header().Set("Content-Type", "image/png")
	const imgBody = "binary image data"
	if _, err := grw.Write([]byte(imgBody)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Act
	grw.finish()
	grw.finish()

	// Assert — gz is nil (non-compressible types never arm the writer); body passes through unchanged
	if grw.gz != nil {
		t.Error("gz should be nil for non-compressible content type")
	}
	if got := rr.Body.String(); got != imgBody {
		t.Errorf("body = %q, want %q", got, imgBody)
	}
}
