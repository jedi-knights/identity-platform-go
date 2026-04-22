package ports

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// UpstreamTransport is the outbound port for forwarding requests to upstream services.
// Implementations must write the complete response (status code, headers, body) to w.
//
// Forward returns an error if the upstream is unreachable or the transport encounters
// a failure. Callers must check whether headers have already been written to w before
// attempting to write their own error response — use a statusRecorder wrapper to
// track this.
type UpstreamTransport interface {
	Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error
}
