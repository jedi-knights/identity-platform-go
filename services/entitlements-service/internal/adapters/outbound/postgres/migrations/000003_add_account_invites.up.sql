-- Add account_invites table (E7-S2 / #170).
--
-- Sending flow (this migration): an owner-seat calls
-- POST /accounts/{id}/invites; entitlements-service inserts a row here,
-- emails the invited address a signup link containing the raw token,
-- and stores only the bcrypt hash so a DB dump does not leak invite
-- links.
--
-- Accepting flow (follow-up story): a receiver POSTs the token to
-- an accept endpoint that hashes-and-matches against token_hash, marks
-- accepted_at, and creates the account_seats row.
--
-- Lifecycle states:
--   pending  : accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
--   accepted : accepted_at IS NOT NULL
--   revoked  : revoked_at IS NOT NULL
--   expired  : expires_at <= now() AND accepted_at IS NULL AND revoked_at IS NULL

CREATE TABLE IF NOT EXISTS account_invites (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id         UUID         NOT NULL REFERENCES accounts(id)      ON DELETE CASCADE,
    invited_by_seat_id UUID         NOT NULL REFERENCES account_seats(id) ON DELETE CASCADE,
    invited_email      TEXT         NOT NULL,
    -- token_hash is bcrypt(rawToken). The raw token appears only in the
    -- emailed link; a DB read cannot recover it.
    token_hash         TEXT         NOT NULL UNIQUE,
    expires_at         TIMESTAMPTZ  NOT NULL,
    accepted_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Cannot both be set — an accepted invite cannot then be revoked
    -- and vice-versa. Enforced at the schema level so business logic
    -- bugs cannot silently violate the state machine.
    CONSTRAINT account_invites_terminal_state CHECK (
        accepted_at IS NULL OR revoked_at IS NULL
    )
);

-- Same invited email cannot have two open (not-yet-accepted-or-revoked)
-- invites on the same account. Partial index rather than an EXCLUDE
-- constraint so the predicate is IMMUTABLE — expiry checks live in
-- application logic (expired invites are revoked before a new one is
-- issued).
CREATE UNIQUE INDEX IF NOT EXISTS account_invites_no_dup_open_idx
    ON account_invites (account_id, invited_email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- List-pending-invites-for-account: partial index scoped to pending rows
-- so the account-detail page's "who's invited?" query stays fast even
-- as the accepted/revoked history grows.
CREATE INDEX IF NOT EXISTS account_invites_pending_by_account_idx
    ON account_invites (account_id)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- Token-lookup on accept: pending-only, so once an invite is used it
-- drops out of the index and cannot be replayed even if the token were
-- somehow guessed.
CREATE INDEX IF NOT EXISTS account_invites_pending_by_token_idx
    ON account_invites (token_hash)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
