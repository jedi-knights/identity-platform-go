package observability

import (
	"github.com/jedi-knights/go-logging/pkg/logging"
)

func Setup(cfg logging.Config) (logging.Logger, error) {
	logger := logging.New(cfg)
	return logger, nil
}
