# Example Resource Service

A protected API that validates JWT tokens and enforces scopes.

## Port: 8085

## Endpoints
- `GET /resources` - List all resources (requires "read" scope)
- `GET /resources/{id}` - Get a resource by ID (requires "read" scope)
- `POST /resources` - Create a resource (requires "write" scope)
- `GET /health` - Health check (no auth)

## Configuration (ENV prefix: RESOURCE)
- `RESOURCE_JWT_SIGNING_KEY` - JWT HMAC signing key
- `RESOURCE_SERVER_PORT` - Port (default: 8085)
