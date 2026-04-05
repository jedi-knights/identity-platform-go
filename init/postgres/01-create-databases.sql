-- Create per-service databases. Each service owns its own database;
-- no cross-service foreign keys, no shared tables.
-- auth-server uses Redis for token storage, not PostgreSQL.
SELECT 'CREATE DATABASE identity_service'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'identity_service')\gexec

SELECT 'CREATE DATABASE client_registry'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'client_registry')\gexec

SELECT 'CREATE DATABASE authorization_policy'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'authorization_policy')\gexec

SELECT 'CREATE DATABASE example_resource'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'example_resource')\gexec
