package observability

import (
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// Setup initialises the service logger from the given logging config.
func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.NewLogger(cfg)
	return logger, nil
}
