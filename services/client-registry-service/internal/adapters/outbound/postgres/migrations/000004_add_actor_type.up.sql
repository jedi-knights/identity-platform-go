-- ADR-0015: ActorType (user / service / agent) classifies the principal
-- kind a registered OAuth client represents. Orthogonal to client_type
-- (public/confidential) — a confidential client may be either a service
-- or an agent; a public client may be a user-driven SPA or an agent.
--
-- Backwards compatibility: existing rows default to 'service'. The
-- application layer treats any value other than 'user' or 'agent' as
-- service (fail closed), so the column carries no CHECK constraint
-- and the only role of the default is to populate pre-ADR-0015 rows
-- during the migration window.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT 'service';
