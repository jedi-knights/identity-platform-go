package observability

import (
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.NewLogger(cfg)
	return logger, nil
}
