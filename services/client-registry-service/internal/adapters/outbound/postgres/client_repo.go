// Package postgres provides a PostgreSQL-backed implementation of domain.ClientRepository.
// It uses pgx/v5 for the connection pool and golang-migrate for schema migrations.
// Migrations are embedded at compile time so no external migration files are required
// at runtime — the binary is self-contained.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // postgres driver for migrate
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// Compile-time interface check — fails to build if ClientRepository drifts from domain.ClientRepository.
var _ domain.ClientRepository = (*ClientRepository)(nil)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ClientRepository is a PostgreSQL-backed implementation of domain.ClientRepository.
// It is safe for concurrent use; the underlying pgxpool manages connection lifecycle.
type ClientRepository struct {
	pool *pgxpool.Pool
}

// Connect opens a pgxpool connection to the given databaseURL and returns a ClientRepository.
// The caller is responsible for calling Close when the repository is no longer needed.
func Connect(ctx context.Context, databaseURL string) (*ClientRepository, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening postgres pool: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return &ClientRepository{pool: pool}, nil
}

// Close releases the underlying connection pool. It must be called once the
// repository is no longer needed to prevent connection leaks.
func (r *ClientRepository) Close() {
	r.pool.Close()
}

// RunMigrations applies all pending up-migrations to the database identified by
// databaseURL. It is idempotent — already-applied migrations are skipped.
// Returns nil when the schema is already up to date.
func RunMigrations(databaseURL string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("loading embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return fmt.Errorf("creating migrate instance: %w", err)
	}

	return runMigrate(m)
}

// runMigrate executes the up migration and closes the migrate instance,
// propagating close errors only when no migration error occurred.
func runMigrate(m *migrate.Migrate) (retErr error) {
	defer func() {
		srcErr, dbErr := m.Close()
		if retErr == nil {
			if srcErr != nil {
				retErr = fmt.Errorf("closing migrate source: %w", srcErr)
			} else if dbErr != nil {
				retErr = fmt.Errorf("closing migrate database connection: %w", dbErr)
			}
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// queryStringSlice executes query with a single $1 argument and collects every
// scanned string into a slice. Always returns a non-nil slice. Extracted from
// loadRelated to eliminate three identical query-scan-iterate blocks.
func (r *ClientRepository) queryStringSlice(ctx context.Context, query, arg string) ([]string, error) {
	rows, err := r.pool.Query(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []string{}
	for rows.Next() {
		var s string
		if err = rows.Scan(&s); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// loadRelated fetches the scopes, grant types, and redirect URIs for the given client ID
// using three targeted queries against the join tables. Empty slices (not nil) are
// returned when no rows exist for a given relation.
func (r *ClientRepository) loadRelated(ctx context.Context, id string) (scopes, grantTypes, redirectURIs []string, err error) {
	scopes, err = r.queryStringSlice(ctx, `SELECT scope FROM client_scopes WHERE client_id = $1`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading scopes for client %q: %w", id, err)
	}
	grantTypes, err = r.queryStringSlice(ctx, `SELECT grant_type FROM client_grant_types WHERE client_id = $1`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading grant types for client %q: %w", id, err)
	}
	redirectURIs, err = r.queryStringSlice(ctx, `SELECT redirect_uri FROM client_redirect_uris WHERE client_id = $1`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading redirect URIs for client %q: %w", id, err)
	}
	return scopes, grantTypes, redirectURIs, nil
}

// FindByID returns the OAuthClient with the given id, or an ErrCodeNotFound AppError
// when no client with that id exists.
func (r *ClientRepository) FindByID(ctx context.Context, id string) (*domain.OAuthClient, error) {
	const q = `
		SELECT id, secret, name, active, created_at, updated_at
		FROM oauth_clients
		WHERE id = $1`

	var c domain.OAuthClient
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&c.ID, &c.Secret, &c.Name,
		&c.Active, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("querying client %q: %w", id, err)
	}

	c.Scopes, c.GrantTypes, c.RedirectURIs, err = r.loadRelated(ctx, id)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// insertRelated inserts the scopes, grant types, and redirect URIs for clientID
// within the provided transaction. Extracted from Save and Update to keep their
// cyclomatic complexity within bounds.
func insertRelated(ctx context.Context, tx pgx.Tx, clientID string, client *domain.OAuthClient) error {
	for _, scope := range client.Scopes {
		if _, err := tx.Exec(ctx, `INSERT INTO client_scopes (client_id, scope) VALUES ($1, $2)`, clientID, scope); err != nil {
			return fmt.Errorf("inserting scope %q for client %q: %w", scope, clientID, err)
		}
	}
	for _, gt := range client.GrantTypes {
		if _, err := tx.Exec(ctx, `INSERT INTO client_grant_types (client_id, grant_type) VALUES ($1, $2)`, clientID, gt); err != nil {
			return fmt.Errorf("inserting grant type %q for client %q: %w", gt, clientID, err)
		}
	}
	for _, uri := range client.RedirectURIs {
		if _, err := tx.Exec(ctx, `INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`, clientID, uri); err != nil {
			return fmt.Errorf("inserting redirect URI %q for client %q: %w", uri, clientID, err)
		}
	}
	return nil
}

// deleteRelated removes all scopes, grant types, and redirect URIs for clientID
// within the provided transaction. Used by Update before re-inserting the new set.
// Extracted from Update to keep its cyclomatic complexity within bounds.
func deleteRelated(ctx context.Context, tx pgx.Tx, clientID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM client_scopes WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("deleting scopes for client %q: %w", clientID, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM client_grant_types WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("deleting grant types for client %q: %w", clientID, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM client_redirect_uris WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("deleting redirect URIs for client %q: %w", clientID, err)
	}
	return nil
}

// Save persists a new OAuthClient. It returns an ErrCodeConflict AppError when a
// client with the same id already exists.
func (r *ClientRepository) Save(ctx context.Context, client *domain.OAuthClient) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction for Save: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const insertClient = `
		INSERT INTO oauth_clients (id, secret, name, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = tx.Exec(ctx, insertClient,
		client.ID, client.Secret, client.Name,
		client.Active, client.CreatedAt, client.UpdatedAt,
	)
	if isUniqueViolation(err) {
		return apperrors.New(apperrors.ErrCodeConflict, "client already exists")
	}
	if err != nil {
		return fmt.Errorf("inserting client: %w", err)
	}

	if err = insertRelated(ctx, tx, client.ID, client); err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing Save transaction: %w", err)
	}
	return nil
}

// Update replaces all mutable fields of an existing OAuthClient. It returns an
// ErrCodeNotFound AppError when no client with client.ID exists.
func (r *ClientRepository) Update(ctx context.Context, client *domain.OAuthClient) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction for Update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const updateClient = `
		UPDATE oauth_clients
		SET name = $2, active = $3, updated_at = $4
		WHERE id = $1`

	tag, err := tx.Exec(ctx, updateClient,
		client.ID, client.Name, client.Active, client.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("updating client %q: %w", client.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}

	// Delete and re-insert related rows — simpler and safer than diffing.
	if err = deleteRelated(ctx, tx, client.ID); err != nil {
		return err
	}
	if err = insertRelated(ctx, tx, client.ID, client); err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing Update transaction: %w", err)
	}
	return nil
}

// Delete removes the OAuthClient with the given id. It returns an ErrCodeNotFound
// AppError when no client with that id exists.
// The join tables (client_scopes, client_grant_types, client_redirect_uris) are
// cleaned up automatically via ON DELETE CASCADE.
func (r *ClientRepository) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM oauth_clients WHERE id = $1`

	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("deleting client %q: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	return nil
}

// List returns all registered OAuthClients ordered by creation time.
// It returns an empty slice when none exist. A single aggregation query
// with LEFT JOINs is used to avoid N+1 queries.
func (r *ClientRepository) List(ctx context.Context) ([]*domain.OAuthClient, error) {
	const q = `
		SELECT
			c.id, c.secret, c.name, c.active, c.created_at, c.updated_at,
			COALESCE(array_agg(DISTINCT cs.scope)        FILTER (WHERE cs.scope IS NOT NULL),        '{}') AS scopes,
			COALESCE(array_agg(DISTINCT cg.grant_type)   FILTER (WHERE cg.grant_type IS NOT NULL),   '{}') AS grant_types,
			COALESCE(array_agg(DISTINCT cr.redirect_uri) FILTER (WHERE cr.redirect_uri IS NOT NULL), '{}') AS redirect_uris
		FROM oauth_clients c
		LEFT JOIN client_scopes cs        ON cs.client_id = c.id
		LEFT JOIN client_grant_types cg   ON cg.client_id = c.id
		LEFT JOIN client_redirect_uris cr ON cr.client_id = c.id
		GROUP BY c.id, c.secret, c.name, c.active, c.created_at, c.updated_at
		ORDER BY c.created_at`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	defer rows.Close()

	var result []*domain.OAuthClient
	for rows.Next() {
		var c domain.OAuthClient
		if err = rows.Scan(
			&c.ID, &c.Secret, &c.Name, &c.Active, &c.CreatedAt, &c.UpdatedAt,
			&c.Scopes, &c.GrantTypes, &c.RedirectURIs,
		); err != nil {
			return nil, fmt.Errorf("scanning client row: %w", err)
		}
		result = append(result, &c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating client rows: %w", err)
	}
	return result, nil
}
