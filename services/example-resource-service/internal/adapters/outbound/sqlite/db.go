// Package sqlite provides a SQLite-backed implementation of
// domain.ResourceRepository. It exists as the local/acceptance-test-time
// swap-in for the postgres adapter — same domain contract, no server
// process required. Migrations are embedded at compile time and are
// SQLite-dialect equivalents of the postgres migrations, not shared SQL
// text (see migrations/000001_create_resources.up.sql for the
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
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Connect opens a SQLite database at the given DSN. The DSN is augmented
// with foreign_keys and busy_timeout pragmas so light concurrent access
// behaves correctly regardless of what the caller passed in. The caller is
// responsible for closing the returned *sql.DB.
func Connect(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", withPragmas(dsn))
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite database: %w", err)
	}
	return db, nil
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
// a comment may itself contain a semicolon — then splits what remains on
// ";". Adequate for the plain DDL these migrations contain; it is not a
// general SQL parser.
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

// sqliteTimeLayout is a fixed-width variant of RFC3339Nano: always exactly
// 9 fractional-second digits and a literal "Z" (guaranteed by always
// formatting in UTC). time.RFC3339Nano itself trims trailing zeros from
// the fractional part, which makes two timestamps' string forms compare
// incorrectly under plain "<" / ORDER BY (e.g. "...:00.09Z" sorts after
// "...:00.1Z" as strings, despite being chronologically earlier). A fixed
// width keeps lexicographic and chronological ordering identical — this
// adapter's FindAll orders by created_at, so the distinction is load-bearing.
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
