// Package sqlite provides a SQLite-backed implementation of
// domain.ClientRepository. It exists as the local/acceptance-test-time
// swap-in for the postgres adapter — same domain contract, no server
// process required. Migrations are embedded at compile time and are
// SQLite-dialect equivalents of the postgres migrations, not shared SQL
// text (see migrations/000001_create_oauth_clients.up.sql for the
// dialect-translation notes).
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// Compile-time interface check — fails to build if ClientRepository drifts from domain.ClientRepository.
var _ domain.ClientRepository = (*ClientRepository)(nil)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ClientRepository is a SQLite-backed implementation of domain.ClientRepository.
// Safe for concurrent use; *sql.DB manages its own connection pool.
type ClientRepository struct {
	db *sql.DB
}

// Connect opens a SQLite database at the given DSN and returns a
// ClientRepository. The DSN is augmented with foreign_keys and
// busy_timeout pragmas so ON DELETE CASCADE and light concurrent access
// behave correctly regardless of what the caller passed in. The caller
// must call Close when the repository is no longer needed.
func Connect(ctx context.Context, dsn string) (*ClientRepository, error) {
	db, err := sql.Open("sqlite", withPragmas(dsn))
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite database: %w", err)
	}
	return &ClientRepository{db: db}, nil
}

// withPragmas appends foreign_keys(1) and busy_timeout(5000) to dsn via
// modernc.org/sqlite's _pragma query-parameter form, unless the caller
// already specified pragmas explicitly.
func withPragmas(dsn string) string {
	if strings.Contains(dsn, "_pragma=") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// Close releases the underlying connection pool.
func (r *ClientRepository) Close() error {
	return r.db.Close()
}

// RunMigrations applies every embedded *.up.sql file, in filename order,
// that has not already been recorded in schema_migrations. It is
// idempotent — already-applied migrations are skipped.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)`); err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}
	names := upMigrationNames(entries)
	sort.Strings(names)

	for _, name := range names {
		applied, err := isApplied(ctx, db, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := applyMigration(ctx, db, name); err != nil {
			return fmt.Errorf("applying migration %q: %w", name, err)
		}
	}
	return nil
}

// upMigrationNames returns the *.up.sql filenames from entries, ignoring
// *.down.sql and any non-SQL files.
func upMigrationNames(entries []fs.DirEntry) []string {
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	return names
}

func isApplied(ctx context.Context, db *sql.DB, version string) (bool, error) {
	var exists int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE version = ?`, version).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking migration status for %q: %w", version, err)
	}
	return true, nil
}

// applyMigration runs every statement in the named migration file inside a
// single transaction, then records it in schema_migrations. Statements are
// split on ";" line boundaries rather than relying on driver-level
// multi-statement Exec support, which is not guaranteed across sqlite
// drivers.
func applyMigration(ctx context.Context, db *sql.DB, name string) error {
	content, err := migrationsFS.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("reading migration file: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range splitStatements(string(content)) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("executing statement %q: %w", stmt, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, name); err != nil {
		return fmt.Errorf("recording migration: %w", err)
	}
	return tx.Commit()
}

// splitStatements strips "--" comment lines from the whole script first —
// a comment may itself contain a semicolon (as in this package's own
// migration file), so comments must be removed before splitting on the
// statement-terminating ";" — then splits what remains on ";". Adequate
// for the plain DDL these migrations contain; it is not a general SQL parser.
func splitStatements(script string) []string {
	var codeLines []string
	for line := range strings.SplitSeq(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		codeLines = append(codeLines, line)
	}

	var stmts []string
	for raw := range strings.SplitSeq(strings.Join(codeLines, "\n"), ";") {
		if stmt := strings.TrimSpace(raw); stmt != "" {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

// isUniqueViolation reports whether err is a SQLite unique-constraint
// violation. modernc.org/sqlite does not expose a typed error with a
// stable SQLite error code the way pgx does for postgres, so this matches
// on the driver's error message text — the only stable signal available.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// sqliteTimeLayout is a fixed-width variant of RFC3339Nano: always exactly
// 9 fractional-second digits and a literal "Z" (guaranteed by always
// formatting in UTC). time.RFC3339Nano itself trims trailing zeros from
// the fractional part, which makes two timestamps' string forms compare
// incorrectly under plain "<" / ORDER BY (e.g. "...:00.09Z" sorts after
// "...:00.1Z" as strings, despite being chronologically earlier). A fixed
// width keeps lexicographic and chronological ordering identical — this
// adapter's List orders by created_at, so the distinction is load-bearing.
const sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z"

// timeToText formats t in UTC using sqliteTimeLayout for storage in a TEXT
// column that must remain correctly sortable via plain string comparison.
func timeToText(t time.Time) string {
	return t.UTC().Format(sqliteTimeLayout)
}

// textToTime parses a TEXT column written by timeToText.
func textToTime(s string) (time.Time, error) {
	return time.Parse(sqliteTimeLayout, s)
}

// queryStringSlice executes query with a single argument and collects every
// scanned string into a slice. Always returns a non-nil slice.
func (r *ClientRepository) queryStringSlice(ctx context.Context, query, arg string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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

// loadRelated fetches the scopes, grant types, and redirect URIs for the given client ID.
func (r *ClientRepository) loadRelated(ctx context.Context, id string) (scopes, grantTypes, redirectURIs []string, err error) {
	scopes, err = r.queryStringSlice(ctx, `SELECT scope FROM client_scopes WHERE client_id = ?`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading scopes for client %q: %w", id, err)
	}
	grantTypes, err = r.queryStringSlice(ctx, `SELECT grant_type FROM client_grant_types WHERE client_id = ?`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading grant types for client %q: %w", id, err)
	}
	redirectURIs, err = r.queryStringSlice(ctx, `SELECT redirect_uri FROM client_redirect_uris WHERE client_id = ?`, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading redirect URIs for client %q: %w", id, err)
	}
	return scopes, grantTypes, redirectURIs, nil
}

// FindByID returns the OAuthClient with the given id, or an ErrCodeNotFound AppError
// when no client with that id exists.
func (r *ClientRepository) FindByID(ctx context.Context, id string) (*domain.OAuthClient, error) {
	const q = `
		SELECT id, secret, name, client_type, actor_type,
		       token_endpoint_auth_method, registration_access_token_hash,
		       active, created_at, updated_at, jwks_uri
		FROM oauth_clients
		WHERE id = ?`

	var c domain.OAuthClient
	var clientType, actorType, createdAt, updatedAt string
	err := r.db.QueryRowContext(ctx, q, id).Scan(
		&c.ID, &c.Secret, &c.Name, &clientType, &actorType,
		&c.TokenEndpointAuthMethod, &c.RegistrationAccessTokenHash,
		&c.Active, &createdAt, &updatedAt, &c.JWKSURI,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("querying client %q: %w", id, err)
	}
	c.Type = domain.ClientType(clientType)
	c.ActorType = domain.ActorType(actorType)
	if c.CreatedAt, err = textToTime(createdAt); err != nil {
		return nil, fmt.Errorf("parsing created_at for client %q: %w", id, err)
	}
	if c.UpdatedAt, err = textToTime(updatedAt); err != nil {
		return nil, fmt.Errorf("parsing updated_at for client %q: %w", id, err)
	}

	c.Scopes, c.GrantTypes, c.RedirectURIs, err = r.loadRelated(ctx, id)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// insertRelated inserts the scopes, grant types, and redirect URIs for clientID
// within the provided transaction.
func insertRelated(ctx context.Context, tx *sql.Tx, clientID string, client *domain.OAuthClient) error {
	for _, scope := range client.Scopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_scopes (client_id, scope) VALUES (?, ?)`, clientID, scope); err != nil {
			return fmt.Errorf("inserting scope %q for client %q: %w", scope, clientID, err)
		}
	}
	for _, gt := range client.GrantTypes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_grant_types (client_id, grant_type) VALUES (?, ?)`, clientID, gt); err != nil {
			return fmt.Errorf("inserting grant type %q for client %q: %w", gt, clientID, err)
		}
	}
	for _, uri := range client.RedirectURIs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES (?, ?)`, clientID, uri); err != nil {
			return fmt.Errorf("inserting redirect URI %q for client %q: %w", uri, clientID, err)
		}
	}
	return nil
}

// deleteRelated removes all scopes, grant types, and redirect URIs for clientID
// within the provided transaction. Used by Update before re-inserting the new set.
func deleteRelated(ctx context.Context, tx *sql.Tx, clientID string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_scopes WHERE client_id = ?`, clientID); err != nil {
		return fmt.Errorf("deleting scopes for client %q: %w", clientID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_grant_types WHERE client_id = ?`, clientID); err != nil {
		return fmt.Errorf("deleting grant types for client %q: %w", clientID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_redirect_uris WHERE client_id = ?`, clientID); err != nil {
		return fmt.Errorf("deleting redirect URIs for client %q: %w", clientID, err)
	}
	return nil
}

// Save persists a new OAuthClient. It returns an ErrCodeConflict AppError when a
// client with the same id already exists.
func (r *ClientRepository) Save(ctx context.Context, client *domain.OAuthClient) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction for Save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const insertClient = `
		INSERT INTO oauth_clients (
			id, secret, name, client_type, actor_type,
			token_endpoint_auth_method, registration_access_token_hash,
			active, created_at, updated_at, jwks_uri
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, insertClient,
		client.ID, client.Secret, client.Name, string(client.Type), string(client.ActorType),
		client.TokenEndpointAuthMethod, client.RegistrationAccessTokenHash,
		client.Active, timeToText(client.CreatedAt), timeToText(client.UpdatedAt), client.JWKSURI,
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

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing Save transaction: %w", err)
	}
	return nil
}

// Update replaces all mutable fields of an existing OAuthClient. It returns an
// ErrCodeNotFound AppError when no client with client.ID exists.
func (r *ClientRepository) Update(ctx context.Context, client *domain.OAuthClient) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction for Update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err = updateClientRow(ctx, tx, client); err != nil {
		return err
	}

	// Delete and re-insert related rows — simpler and safer than diffing.
	if err = deleteRelated(ctx, tx, client.ID); err != nil {
		return err
	}
	if err = insertRelated(ctx, tx, client.ID, client); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing Update transaction: %w", err)
	}
	return nil
}

// updateClientRow runs the UPDATE against oauth_clients and translates a
// zero-rows-affected result into ErrCodeNotFound. Extracted from Update to
// keep its cyclomatic complexity within bounds.
func updateClientRow(ctx context.Context, tx *sql.Tx, client *domain.OAuthClient) error {
	const updateClient = `
		UPDATE oauth_clients
		SET name = ?, active = ?, updated_at = ?
		WHERE id = ?`

	tag, err := tx.ExecContext(ctx, updateClient, client.Name, client.Active, timeToText(client.UpdatedAt), client.ID)
	if err != nil {
		return fmt.Errorf("updating client %q: %w", client.ID, err)
	}
	rows, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected for client %q: %w", client.ID, err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	return nil
}

// Delete removes the OAuthClient with the given id. It returns an ErrCodeNotFound
// AppError when no client with that id exists.
// The join tables (client_scopes, client_grant_types, client_redirect_uris) are
// cleaned up automatically via ON DELETE CASCADE (foreign_keys pragma enabled by Connect).
func (r *ClientRepository) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM oauth_clients WHERE id = ?`

	tag, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("deleting client %q: %w", id, err)
	}
	rows, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("reading rows affected for client %q: %w", id, err)
	}
	if rows == 0 {
		return apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	return nil
}

// List returns all registered OAuthClients ordered by creation time.
// It returns an empty slice when none exist. Related rows are loaded with
// one query per client (N+1) rather than postgres's single array_agg
// query — SQLite has no array aggregate type, and client counts in this
// reference implementation are small enough that this is not a
// meaningful cost; a future optimization could batch these with a single
// "WHERE client_id IN (...)" query if List is ever called on a hot path.
func (r *ClientRepository) List(ctx context.Context) ([]*domain.OAuthClient, error) {
	const q = `
		SELECT id, secret, name, client_type, actor_type,
		       token_endpoint_auth_method, registration_access_token_hash,
		       active, created_at, updated_at, jwks_uri
		FROM oauth_clients
		ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []*domain.OAuthClient
	for rows.Next() {
		c, err := scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating client rows: %w", err)
	}

	for _, c := range result {
		if c.Scopes, c.GrantTypes, c.RedirectURIs, err = r.loadRelated(ctx, c.ID); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// scanClientRow scans one oauth_clients row (as selected by List's query)
// into a domain.OAuthClient. Extracted from List to keep its cyclomatic
// complexity within bounds.
func scanClientRow(rows *sql.Rows) (*domain.OAuthClient, error) {
	var c domain.OAuthClient
	var clientType, actorType, createdAt, updatedAt string
	if err := rows.Scan(
		&c.ID, &c.Secret, &c.Name, &clientType, &actorType,
		&c.TokenEndpointAuthMethod, &c.RegistrationAccessTokenHash,
		&c.Active, &createdAt, &updatedAt, &c.JWKSURI,
	); err != nil {
		return nil, fmt.Errorf("scanning client row: %w", err)
	}
	c.Type = domain.ClientType(clientType)
	c.ActorType = domain.ActorType(actorType)

	var err error
	if c.CreatedAt, err = textToTime(createdAt); err != nil {
		return nil, fmt.Errorf("parsing created_at for client %q: %w", c.ID, err)
	}
	if c.UpdatedAt, err = textToTime(updatedAt); err != nil {
		return nil, fmt.Errorf("parsing updated_at for client %q: %w", c.ID, err)
	}
	return &c, nil
}
