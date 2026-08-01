-- user_preferences: per-user mutable preferences identity-service owns.
--
-- Today the only column beyond the FK is active_account_id — the
-- entitlements-service account the user has currently selected as their
-- working context (Epic 7 multi-seat, E7-S3a). The column is nullable
-- because a fresh user with no seats (or a user who has not yet chosen)
-- has no valid active account.
--
-- identity-service does NOT enforce that active_account_id references a
-- real account or that the user has a seat on it — that authority lives
-- in entitlements-service (account_seats). The check runs on the JWT
-- issuance path in E7-S3c; storing the raw string here keeps this
-- service off the outbound entitlements dependency on preference reads.

CREATE TABLE IF NOT EXISTS user_preferences (
    user_id           TEXT        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    active_account_id TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
