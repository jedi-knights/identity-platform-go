package observability

import "github.com/ocrosby/identity-platform-go/libs/logging"

// Setup initializes observability for the api-gateway (logging, and in future,
// distributed tracing and metrics exporters).
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.NewLogger(cfg)
	return logger, nil
}
