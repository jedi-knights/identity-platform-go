package observability

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/audit"
	"github.com/jedi-knights/go-platform/audit/durable"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/config"
)

// AuditWiring is the result of [NewAuditEmitter]. Hold the wiring at the
// composition root so the Close hook can be registered alongside other
// shutdown handlers.
type AuditWiring struct {
	Emitter audit.Emitter
	Pool    *pgxpool.Pool
}

// NewAuditEmitter constructs the audit emitter for login-ui per
// identity-platform-go ADR-0019.
func NewAuditEmitter(ctx context.Context, cfg *config.Config, log logging.Logger) (*AuditWiring, error) {
	if cfg == nil {
		return nil, fmt.Errorf("audit: config is required")
	}
	if log == nil {
		return nil, fmt.Errorf("audit: logger is required")
	}

	stderrSink := audit.NewStderrJSONSink()
	asyncStderr := audit.NewAsyncSink(stderrSink, defaultAsyncBuffer)

	if cfg.Audit.DurableDSN == "" {
		log.Info("audit emitter configured with stderr sink only (LOGIN_UI_AUDIT_DURABLE_DSN not set)")
		return &AuditWiring{Emitter: audit.New(asyncStderr)}, nil
	}

	pool, err := pgxpool.New(ctx, cfg.Audit.DurableDSN)
	if err != nil {
		return nil, fmt.Errorf("audit: connecting to durable DSN: %w", err)
	}
	durableSink := durable.New(pool)

	if !cfg.Audit.SkipMigration {
		if err := durableSink.Migrate(ctx); err != nil {
			pool.Close()
			return nil, fmt.Errorf("audit: migrating durable schema: %w", err)
		}
		log.Info("audit durable schema migrated")
	}

	log.Info("audit emitter configured with stderr + Postgres durable sinks")
	return &AuditWiring{
		Emitter: audit.New(audit.NewMultiSink(asyncStderr, durableSink)),
		Pool:    pool,
	}, nil
}

const defaultAsyncBuffer = 1024
