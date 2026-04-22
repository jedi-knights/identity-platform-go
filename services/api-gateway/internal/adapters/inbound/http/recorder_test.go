//go:build unit

package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

func TestStatusRecorder_WriteHeader_CapturesStatus(t *testing.T) {
	rr := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "body")
	})
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusAccepted {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusAccepted)
	}
}

func TestStatusRecorder_Write_AfterExplicitWriteHeader_SkipsImplicit(t *testing.T) {
	// Write called after an explicit WriteHeader must not trigger a second header commit.
	rr := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	})
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))

	if rr.Code != http.StatusCreated {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusCreated)
	}
}

func TestStatusRecorder_Status_DefaultsTo200WhenNothingWritten(t *testing.T) {
	// When the transport writes nothing (no WriteHeader, no Write), rw.Status()
	// should return 200 so the metrics call uses a sensible default.
	route := &domain.Route{Name: "svc"}
	transport := &fakeTransport{} // no statusCode, no body, no error
	metrics := &fakeMetrics{}

	h := newHandler(t, &fakeRouter{route: route}, transport, metrics)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	h.Proxy(rr, req)

	if len(metrics.calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(metrics.calls))
	}
	if metrics.calls[0].statusCode != http.StatusOK {
		t.Errorf("metrics statusCode = %d, want %d (implicit 200 default)", metrics.calls[0].statusCode, http.StatusOK)
	}
}

func TestStatusRecorder_Write_ImplicitStatusOK(t *testing.T) {
	// Transport calls Write without WriteHeader — the recorder must commit an
	// implicit 200 before proxying the write to the underlying ResponseWriter.
	route := &domain.Route{Name: "svc"}
	// fakeTransport writes body without an explicit WriteHeader call.
	transport := &fakeTransport{body: "hello"}
	metrics := &fakeMetrics{}

	h := newHandler(t, &fakeRouter{route: route}, transport, metrics)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	h.Proxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
	if len(metrics.calls) != 1 || metrics.calls[0].statusCode != http.StatusOK {
		t.Errorf("metrics should record implicit 200, got: %v", metrics.calls)
	}
}
