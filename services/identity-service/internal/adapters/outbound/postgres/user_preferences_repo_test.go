//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/postgres"
)

// seedPrefsUser inserts a real user row so the user_preferences FK is
// satisfiable. Reuses the same shape as user_repo_test's newTestUser but
// keeps the fixture local so this file remains self-contained.
func seedPrefsUser(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, email, name, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, id+"@example.com", id+"-name", "hash",
	)
	if err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
}

func setupPrefsRepo(t *testing.T) (*postgres.UserPreferencesRepository, *pgxpool.Pool) {
	t.Helper()
	dbURL := testDatabaseURL(t)
	if err := postgres.RunMigrations(dbURL); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	pool, err := postgres.Connect(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return postgres.NewUserPreferencesRepository(pool), pool
}

func TestPostgresUserPreferences_GetMissingReturnsNilNil(t *testing.T) {
	repo, _ := setupPrefsRepo(t)

	got, err := repo.Get(context.Background(), "u-does-not-exist")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil, got %+v", got)
	}
}

func TestPostgresUserPreferences_SetAndGet(t *testing.T) {
	repo, pool := setupPrefsRepo(t)
	seedPrefsUser(t, pool, "u-prefs-1")
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := repo.SetActiveAccount(context.Background(), "u-prefs-1", "acc-1", now); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := repo.Get(context.Background(), "u-prefs-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("want row, got nil")
	}
	if got.UserID != "u-prefs-1" || got.ActiveAccountID != "acc-1" {
		t.Errorf("unexpected row: %+v", got)
	}
	// pg stores microsecond precision; compare in the same resolution.
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
}

func TestPostgresUserPreferences_UpsertsOnSecondSet(t *testing.T) {
	repo, pool := setupPrefsRepo(t)
	seedPrefsUser(t, pool, "u-prefs-2")
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	t1 := t0.Add(time.Hour)

	if err := repo.SetActiveAccount(ctx, "u-prefs-2", "acc-1", t0); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetActiveAccount(ctx, "u-prefs-2", "acc-2", t1); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.Get(ctx, "u-prefs-2")
	if got.ActiveAccountID != "acc-2" || !got.UpdatedAt.Equal(t1) {
		t.Errorf("upsert: got %+v, want acc-2 @ %v", got, t1)
	}
}

func TestPostgresUserPreferences_CascadesOnUserDelete(t *testing.T) {
	repo, pool := setupPrefsRepo(t)
	ctx := context.Background()
	// Seed a user, set a preference, delete the user, then confirm the
	// preferences row is gone via CASCADE.
	_, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, name, password_hash)
		 VALUES ('u-cascade', 'cascade@example.com', 'cascade', 'hash')`,
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := repo.SetActiveAccount(ctx, "u-cascade", "acc-cascade", time.Now().UTC()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = 'u-cascade'`); err != nil {
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
