# Token Introspection Service

Validates JWT tokens and returns metadata per RFC 7662.

## Port: 8083

## Endpoints
- `POST /introspect` - Introspect a token (form-encoded `token` param)
- `GET /health` - Health check

## Configuration (ENV prefix: INTROSPECT)
- `INTROSPECT_JWT_SIGNING_KEY` - JWT HMAC signing key
- `INTROSPECT_SERVER_PORT` - Port (default: 8083)
