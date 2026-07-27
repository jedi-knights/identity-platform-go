-- Initial entitlements schema (E3-S2 / #155).
-- Derived from ADR-0028:
--   Decision 1 (multi-seat accounts)              -> accounts, account_seats
--   Decision 3 (named bundles)                    -> resources, bundles, bundle_resources
--   Decision 4 (catalog in entitlements-service)  -> all of the above + plans, plan_bundles
--   Multi-seat + Lago plan mirror                 -> account_plans

-- Postgres 13+ ships gen_random_uuid() in pgcrypto; enable if not already.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- Catalog: resources, bundles, plans (mostly static; edited by ops/admins)
-- =============================================================================

CREATE TABLE IF NOT EXISTS resources (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    code          TEXT         NOT NULL UNIQUE,
    display_name  TEXT         NOT NULL,
    category      TEXT         NOT NULL,
    description   TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bundles (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    code          TEXT         NOT NULL UNIQUE,
    display_name  TEXT         NOT NULL,
    description   TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- bundle_resources: which resources a bundle grants. constraints holds
-- per-membership metadata (e.g. quotas, feature flags scoped to this bundle).
CREATE TABLE IF NOT EXISTS bundle_resources (
    bundle_id     UUID         NOT NULL REFERENCES bundles(id)   ON DELETE CASCADE,
    resource_id   UUID         NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
    constraints   JSONB        NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (bundle_id, resource_id)
);
CREATE INDEX IF NOT EXISTS bundle_resources_resource_id_idx
    ON bundle_resources (resource_id);

CREATE TABLE IF NOT EXISTS plans (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    -- code matches Lago plan.code (touchline-free, touchline-coach, touchline-club)
    code            TEXT         NOT NULL UNIQUE,
    display_name    TEXT         NOT NULL,
    tier            TEXT         NOT NULL CHECK (tier IN ('free', 'coach', 'club')),
    seat_allowance  INTEGER      NOT NULL CHECK (seat_allowance > 0),
    -- NULL match_quota = unlimited
    match_quota     INTEGER      CHECK (match_quota IS NULL OR match_quota >= 0),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plan_bundles (
    plan_id       UUID         NOT NULL REFERENCES plans(id)   ON DELETE CASCADE,
    bundle_id     UUID         NOT NULL REFERENCES bundles(id) ON DELETE RESTRICT,
    PRIMARY KEY (plan_id, bundle_id)
);

-- =============================================================================
-- Tenant state: accounts, seats, subscriptions
-- =============================================================================

CREATE TABLE IF NOT EXISTS accounts (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name      TEXT         NOT NULL,
    -- Nullable until wired to Lago; unique when set so we cannot double-attach.
    lago_customer_id  TEXT         UNIQUE,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- account_seats: members of an account. user_id is an opaque reference to
-- identity-service; entitlements-service does not own the user record.
CREATE TABLE IF NOT EXISTS account_seats (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id    UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id       TEXT         NOT NULL,
    role          TEXT         NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (account_id, user_id)
);
CREATE INDEX IF NOT EXISTS account_seats_user_id_idx
    ON account_seats (user_id);

-- account_plans: which plan an account is on, with validity window.
-- valid_until IS NULL = currently active. Historical rows retained for
-- audit/reporting.
CREATE TABLE IF NOT EXISTS account_plans (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id            UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    plan_id               UUID         NOT NULL REFERENCES plans(id)    ON DELETE RESTRICT,
    valid_from            TIMESTAMPTZ  NOT NULL,
    valid_until           TIMESTAMPTZ,
    lago_subscription_id  TEXT,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- One plan-start per account can only exist once (idempotent Lago webhook replays).
    UNIQUE (account_id, plan_id, valid_from),
    CONSTRAINT account_plans_valid_range CHECK (
        valid_until IS NULL OR valid_until > valid_from
    )
);
CREATE INDEX IF NOT EXISTS account_plans_account_valid_until_idx
    ON account_plans (account_id, valid_until);

-- Fast lookup for "give me the currently-active plan for this account".
CREATE INDEX IF NOT EXISTS account_plans_active_idx
    ON account_plans (account_id)
    WHERE valid_until IS NULL;
