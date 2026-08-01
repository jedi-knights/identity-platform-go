//go:build unit

package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/sqlite"
)

// setupPrefsRepo boots a fresh SQLite instance and returns the prefs
// repo plus the shared *sql.DB so tests can seed the users FK directly.
func setupPrefsRepo(t *testing.T) (*sqlite.UserPreferencesRepository, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "prefs.db")

	migrationDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening migration connection: %v", err)
	}
	if err := sqlite.RunMigrations(ctx, migrationDB); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatalf("closing migration connection: %v", err)
	}

	db, err := sqlite.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.NewUserPreferencesRepository(db), db
}

func seedPrefsUserSQLite(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	// SQLite's users table has no DEFAULT for created_at/updated_at (see
	// migrations/000001) — supply them explicitly in the format the
	// production repo uses.
	nowText := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name, password_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, id+"@example.com", id, "hash", nowText, nowText,
	)
	if err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

func TestSQLiteUserPreferences_GetMissingReturnsNilNil(t *testing.T) {
	repo, _ := setupPrefsRepo(t)

	got, err := repo.Get(context.Background(), "u-missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil, got %+v", got)
	}
}

func TestSQLiteUserPreferences_SetAndGet(t *testing.T) {
	repo, db := setupPrefsRepo(t)
	seedPrefsUserSQLite(t, db, "u-1")
	now := time.Now().UTC().Truncate(time.Nanosecond)

	if err := repo.SetActiveAccount(context.Background(), "u-1", "acc-1", now); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := repo.Get(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("want row, got nil")
	}
	if got.UserID != "u-1" || got.ActiveAccountID != "acc-1" {
		t.Errorf("unexpected row: %+v", got)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
}

func TestSQLiteUserPreferences_Upserts(t *testing.T) {
	repo, db := setupPrefsRepo(t)
	seedPrefsUserSQLite(t, db, "u-2")
	ctx := context.Background()
	t0 := time.Now().UTC()
	t1 := t0.Add(time.Hour)

	_ = repo.SetActiveAccount(ctx, "u-2", "acc-1", t0)
	_ = repo.SetActiveAccount(ctx, "u-2", "acc-2", t1)

	got, _ := repo.Get(ctx, "u-2")
	if got.ActiveAccountID != "acc-2" {
		t.Errorf("upsert: got %s, want acc-2", got.ActiveAccountID)
	}
}

func TestSQLiteUserPreferences_CascadesOnUserDelete(t *testing.T) {
	repo, db := setupPrefsRepo(t)
	ctx := context.Background()
	seedPrefsUserSQLite(t, db, "u-cascade")

	if err := repo.SetActiveAccount(ctx, "u-cascade", "acc-c", time.Now().UTC()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, "u-cascade"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	got, err := repo.Get(ctx, "u-cascade")
	if err != nil {
		t.Fatalf("Get after cascade: %v", err)
	}
	if got != nil {
		t.Errorf("cascade failed: preferences row survived user deletion")
	}
}
