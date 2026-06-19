package observability

import (
	"github.com/jedi-knights/go-logging/pkg/logging"
)

// Setup initializes observability (logging, tracing, metrics).
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.New(cfg)
	return logger, nil
}
