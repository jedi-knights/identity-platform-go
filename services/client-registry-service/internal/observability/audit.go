package observability

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/audit"
	"github.com/jedi-knights/go-platform/audit/durable"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
)

// AuditWiring is the result of [NewAuditEmitter]. Hold the wiring at the
// composition root so the Close hook can be registered alongside other
// shutdown handlers.
type AuditWiring struct {
	// Emitter is the audit.Emitter the application layer depends on.
	// Always non-nil; falls back to a stderr-only emitter when no durable
	// sink is configured.
	Emitter audit.Emitter

	// Pool is the pgx pool backing the durable sink. Nil when no durable
	// sink is configured. The caller is responsible for calling Close
	// during graceful shutdown.
	Pool *pgxpool.Pool
}

// NewAuditEmitter constructs the audit emitter for client-registry-service
// per identity-platform-go ADR-0019.
//
//   - When cfg.Audit.DurableDSN is empty: a single best-effort sink
//     (stderr JSON, wrapped in AsyncSink for non-blocking emission).
//   - When cfg.Audit.DurableDSN is set: a multi-sink composing the
//     best-effort stderr path with a synchronous Postgres durable sink.
//     The durable sink runs its CREATE TABLE migration unless
//     cfg.Audit.SkipMigration is true.
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
		log.Info("audit emitter configured with stderr sink only (CLIENT_AUDIT_DURABLE_DSN not set)")
		return &AuditWiring{
			Emitter: audit.New(asyncStderr),
		}, nil
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

// defaultAsyncBuffer is the channel capacity for the stderr async sink.
const defaultAsyncBuffer = 1024
