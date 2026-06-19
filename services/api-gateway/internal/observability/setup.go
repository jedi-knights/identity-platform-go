package observability

import "github.com/jedi-knights/go-logging/pkg/logging"

// Setup initializes observability for the api-gateway (logging, and in future,
// distributed tracing and metrics exporters).
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.New(cfg)
	return logger, nil
}
