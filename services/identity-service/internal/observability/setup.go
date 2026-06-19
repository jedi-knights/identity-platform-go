package observability

import (
	"github.com/jedi-knights/go-logging/pkg/logging"
)

// Setup initializes the logger for the service.
// Tracing and metrics are not yet implemented; add them here when needed.
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.New(cfg)
	return logger, nil
}
