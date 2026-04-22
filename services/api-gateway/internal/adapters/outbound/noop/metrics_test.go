//go:build unit

package noop_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/noop"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func TestMetricsRecorder_RecordRequest_DoesNotPanic(t *testing.T) {
	r := noop.NewMetricsRecorder()

	// Any combination of arguments must be handled silently.
	r.RecordRequest("route-name", 200, 42)
	r.RecordRequest("", 0, 0)
	r.RecordRequest("route", 500, 9999)
}

func TestMetricsRecorder_ImplementsMetricsRecorder(t *testing.T) {
	var _ ports.MetricsRecorder = noop.NewMetricsRecorder()
}
