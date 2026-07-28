// Package observability holds entitlements-service's shared
// observability wiring: structured logger construction and the audit
// emitter. Tracing lives in cmd/main.go's setupTracing helper.
package observability

import "github.com/jedi-knights/go-logging/pkg/logging"

// Setup initializes the service logger. Tracing and metrics are
// bootstrapped separately at composition-root startup.
func Setup(cfg logging.Config) (logging.Logger, error) {
	return logging.New(cfg), nil
}
