# client-registry-service

OAuth2 Client Registry microservice for managing registered OAuth clients.

## Overview

This service provides CRUD operations for OAuth2 client registrations, including client credential validation.

## Endpoints

| Method | Path                   | Description                      |
|--------|------------------------|----------------------------------|
| POST   | /clients               | Register a new OAuth client      |
| GET    | /clients               | List all registered clients      |
| GET    | /clients/{id}          | Get a specific client            |
| DELETE | /clients/{id}          | Delete a client                  |
| POST   | /clients/validate      | Validate client credentials      |
| GET    | /health                | Health check                     |

## Configuration

Environment variables (prefix: `CLIENT`):

| Variable                   | Default       | Description        |
|----------------------------|---------------|--------------------|
| `CLIENT_SERVER_HOST`       | `0.0.0.0`     | Server bind host   |
| `CLIENT_SERVER_PORT`       | `8082`        | Server port        |
| `CLIENT_LOG_LEVEL`         | `info`        | Log level          |
| `CLIENT_LOG_FORMAT`        | `json`        | Log format         |
| `CLIENT_LOG_ENVIRONMENT`   | `development` | Environment name   |

## Running

```bash
go run ./cmd/main.go
```
