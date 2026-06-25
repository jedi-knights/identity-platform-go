// Package observability owns the service's logger / tracer / meter wiring.
// Today it is just the logger; tracing and metrics land here when needed.
package observability

import "github.com/jedi-knights/go-logging/pkg/logging"

// Setup constructs the structured logger from the given config. Returns the
// logger and a nil error today; future tracer/meter setup may report errors.
func Setup(cfg logging.Config) (logging.Logger, error) {
	return logging.New(cfg), nil
}
