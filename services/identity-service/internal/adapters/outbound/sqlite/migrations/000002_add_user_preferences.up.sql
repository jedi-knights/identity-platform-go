-- user_preferences: SQLite equivalent of the postgres migration
-- 000003_add_user_preferences. Numbering diverges from postgres because
-- sqlite migration 000001 already bundled users + verification_tokens
-- (see 000001_create_users.up.sql), so the sqlite adapter jumps straight
-- from 1 to 2 while postgres uses 1 -> 2 -> 3.
--
-- SQLite quirks:
--   * TIMESTAMPTZ does not exist — TEXT + application-side sqliteTimeLayout
--     (see db.go) preserves lexicographic == chronological ordering.
--   * DEFAULT now() does not exist — application code sets updated_at,
--     which is fine here because SetActiveAccount always supplies now.
--   * ON DELETE CASCADE requires foreign_keys=1 (set by db.go pragma).

CREATE TABLE IF NOT EXISTS user_preferences (
    user_id           TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    active_account_id TEXT,
    updated_at        TEXT NOT NULL
);
