package observability

import (
	"github.com/jedi-knights/go-logging/pkg/logging"
)

// Setup initialises the service logger from the given logging config.
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.New(cfg)
	return logger, nil
}
