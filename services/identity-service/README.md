# identity-service

User Authentication and Identity Management microservice.

## Overview

This service handles user registration and authentication using bcrypt password hashing and an in-memory user repository.

## Endpoints

| Method | Path              | Description              |
|--------|-------------------|--------------------------|
| POST   | /auth/register    | Register a new user      |
| POST   | /auth/login       | Authenticate a user      |
| GET    | /health           | Health check             |

## Configuration

Environment variables (prefix: `IDENTITY`):

| Variable                    | Default       | Description        |
|-----------------------------|---------------|--------------------|
| `IDENTITY_SERVER_HOST`      | `0.0.0.0`     | Server bind host   |
| `IDENTITY_SERVER_PORT`      | `8081`        | Server port        |
| `IDENTITY_LOG_LEVEL`        | `info`        | Log level          |
| `IDENTITY_LOG_FORMAT`       | `json`        | Log format         |
| `IDENTITY_LOG_ENVIRONMENT`  | `development` | Environment name   |

## Running

```bash
go run ./cmd/main.go
```
