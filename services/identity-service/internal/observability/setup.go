package observability

import (
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// Setup initializes the logger for the service.
// Tracing and metrics are not yet implemented; add them here when needed.
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.NewLogger(cfg)
	return logger, nil
}
