# Authorization Policy Service

Fine-grained authorization using Strategy/Specification patterns.

## Port: 8084

## Endpoints
- `POST /evaluate` - Evaluate authorization policy (JSON body)
- `GET /health` - Health check

## Configuration (ENV prefix: POLICY)
- `POLICY_SERVER_PORT` - Port (default: 8084)
