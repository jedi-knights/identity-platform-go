package observability

import (
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// Setup initializes observability (logging, tracing, metrics).
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.NewLogger(cfg)
	return logger, nil
}
