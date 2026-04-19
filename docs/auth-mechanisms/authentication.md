# Authentication

Authentication is the process of verifying that a user or system is who they claim to be. It answers the question **"Who are you?"** before any authorization decision ("What are you allowed to do?") can take place.

---

## How Authentication Works

The following diagram illustrates the end-to-end authentication flow, from the initial login request through identity validation and into the protected service layers.

```
                            ┌──────────────────────────────────────────────────────────────────┐
                            │                     CLIENT / USER AGENT                          │
                            │  (Browser, Mobile App, CLI, Service)                             │
                            └──────────────────┬───────────────────────────────────────────────┘
                                               │
                                               │  1. Login Request
                                               │     ┌─────────────────────────────────┐
                                               │     │ POST /login                     │
                                               │     │ Body: { username, password }     │
                                               │     │ — or —                           │
                                               │     │ Header: Authorization: Basic ... │
                                               │     │ — or —                           │
                                               │     │ Header: X-API-Key: ...           │
                                               │     └─────────────────────────────────┘
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                        API GATEWAY                                               │
│                                                                                                  │
│  The single entry point for all external traffic. Responsibilities:                              │
│                                                                                                  │
│  • TLS termination — decrypts HTTPS so internal traffic can be plain HTTP                        │
│  • Rate limiting — prevents brute-force and denial-of-service attacks                            │
│  • Request routing — forwards to the correct downstream service based on path/host               │
│  • Pre-authentication — may reject obviously malformed or unsigned requests early                 │
│  • Logging & tracing — assigns a trace ID carried through all downstream calls                   │
│                                                                                                  │
└──────────────────────────────────┬───────────────────────────────────────────────────────────────┘
                                   │
                                   │  2. Forward credentials
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                         API LAYER                                                │
│                                                                                                  │
│  The HTTP boundary of the application. Handles protocol-level concerns but contains no           │
│  business logic. In this project, these are the inbound HTTP adapters.                           │
│                                                                                                  │
│  • Request parsing — deserializes JSON bodies, extracts headers and query parameters             │
│  • Input validation — rejects structurally invalid requests (missing fields, bad formats)        │
│  • Content negotiation — ensures Accept/Content-Type headers are compatible                      │
│  • Error formatting — translates domain errors into RFC-compliant HTTP responses                 │
│  • Middleware pipeline — executes cross-cutting concerns (CORS, request ID, logging)             │
│                                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                          IDENTITY VALIDATION                                              │  │
│  │                                                                                           │  │
│  │  The API layer delegates credential verification to the service layer and acts on the      │  │
│  │  result. The two outcomes:                                                                │  │
│  │                                                                                           │  │
│  │  ┌─────────────────────────────────┐     ┌──────────────────────────────────────────────┐ │  │
│  │  │        ✗ INVALID                │     │        ✓ VALID                               │ │  │
│  │  │                                 │     │                                              │ │  │
│  │  │  Credentials do not match any   │     │  Credentials match a known identity.         │ │  │
│  │  │  known identity, or the account │     │                                              │ │  │
│  │  │  is locked/disabled.            │     │  The server:                                 │ │  │
│  │  │                                 │     │  • Issues a token (JWT, session ID,          │ │  │
│  │  │  The server:                    │     │    or opaque access token)                   │ │  │
│  │  │  • Returns 401 Unauthorized     │     │  • Sets token metadata (expiry,              │ │  │
│  │  │  • Includes WWW-Authenticate    │     │    scopes, subject)                          │ │  │
│  │  │    header indicating the        │     │  • Returns 200 OK with the token             │ │  │
│  │  │    expected auth scheme         │     │    in the response body or a                 │ │  │
│  │  │  • Logs the failed attempt      │     │    Set-Cookie header                         │ │  │
│  │  │    (without credentials)        │     │  • Logs the successful authentication        │ │  │
│  │  │  • May increment a lockout      │     │                                              │ │  │
│  │  │    counter                      │     │  Subsequent requests include the token       │ │  │
│  │  │                                 │     │  so the user is not re-prompted.             │ │  │
│  │  └──────────────┬──────────────────┘     └───────────────────────┬──────────────────────┘ │  │
│  │                 │                                                │                        │  │
│  │                 ▼                                                ▼                        │  │
│  │        ┌────────────────┐                          ┌─────────────────────────┐           │  │
│  │        │  401 Response   │                          │  200 + Token / Session  │           │  │
│  │        │  ← back to      │                          │  → proceed to services  │           │  │
│  │        │    client       │                          │                         │           │  │
│  │        └────────────────┘                          └────────────┬────────────┘           │  │
│  │                                                                 │                        │  │
│  └─────────────────────────────────────────────────────────────────┼────────────────────────┘  │
│                                                                    │                           │
└────────────────────────────────────────────────────────────────────┼───────────────────────────┘
                                                                     │
                                                                     │  3. Authenticated request
                                                                     │     (token attached)
                                                                     ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      SERVICE LAYER                                               │
│                                                                                                  │
│  Contains the core business logic of the application. Services are framework-agnostic — they     │
│  have no knowledge of HTTP, headers, or status codes. In hexagonal architecture, this is the     │
│  application and domain layer.                                                                   │
│                                                                                                  │
│  • Identity Service — verifies username/password against stored credentials                      │
│  • Auth Server — issues, validates, and revokes tokens                                           │
│  • Client Registry — manages OAuth2 client registrations                                         │
│  • Token Introspection — inspects token validity and metadata                                    │
│  • Authorization Policy — evaluates RBAC rules after authentication succeeds                     │
│                                                                                                  │
│  Services communicate through domain interfaces (ports). They never import HTTP adapters         │
│  or infrastructure code directly.                                                                │
│                                                                                                  │
└──────────────────────────────────────┬───────────────────────────────────────────────────────────┘
                                       │
                                       │  4. Read/write identity data
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    DATA SOURCE LAYER                                             │
│                                                                                                  │
│  The persistence boundary. Implements the repository interfaces defined in the domain layer.     │
│  The service layer depends on abstractions, not on the data source directly — so the storage     │
│  technology can be swapped without changing business logic.                                       │
│                                                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │  User Store       │  │  Token Store      │  │  Client Store    │  │  Policy Store            │ │
│  │                   │  │                   │  │                  │  │                          │ │
│  │  Stores user      │  │  Stores issued    │  │  Stores OAuth2   │  │  Stores roles,           │ │
│  │  credentials,     │  │  access tokens,   │  │  client IDs,     │  │  permissions, and        │ │
│  │  profiles, and    │  │  refresh tokens,  │  │  secrets, and    │  │  resource-action          │ │
│  │  account state    │  │  and revocation   │  │  allowed scopes  │  │  mappings                │ │
│  │  (active/locked)  │  │  status           │  │                  │  │                          │ │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  └──────────────────────────┘ │
│                                                                                                  │
│  Current implementation: in-memory adapters (see ADR-0004)                                       │
│  Production path: PostgreSQL for relational data (ADR-0007), Redis for tokens (ADR-0006)         │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer Responsibilities Summary

| Layer | Responsibility | Knows About |
|-------|---------------|-------------|
| **Client** | Collects credentials, sends login request, stores returned token | Nothing internal — treats the system as a black box |
| **API Gateway** | TLS termination, rate limiting, routing, tracing | Downstream service addresses and routing rules |
| **API Layer** | Request parsing, input validation, error formatting, middleware | Port interfaces into the service layer |
| **Service Layer** | Credential verification, token issuance, business rules | Domain models and repository interfaces (ports) |
| **Data Source Layer** | Persistence of users, tokens, clients, policies | Storage technology (database driver, cache client) |

---

## Authentication vs Authorization

These two concepts are often confused but serve distinct purposes:

| | Authentication | Authorization |
|---|---------------|---------------|
| **Question** | "Who are you?" | "What are you allowed to do?" |
| **When** | Before any access decision | After identity is established |
| **Input** | Credentials (password, token, certificate) | Authenticated identity + requested action |
| **Output** | Identity confirmation or rejection | Permit or deny |
| **Failure response** | `401 Unauthorized` | `403 Forbidden` |

Authentication is a prerequisite to authorization — you cannot decide what someone is allowed to do until you know who they are.

---

## Common Authentication Factors

Authentication mechanisms are built on one or more of these factors:

| Factor | Category | Examples |
|--------|----------|----------|
| Something you **know** | Knowledge | Password, PIN, security question |
| Something you **have** | Possession | Phone (TOTP/SMS), hardware key (YubiKey), smart card |
| Something you **are** | Inherence | Fingerprint, face recognition, retina scan |

**Multi-factor authentication (MFA)** combines two or more of these categories. Using a password (knowledge) plus a TOTP code from a phone app (possession) is MFA. Using a password plus a security question is not — both are knowledge factors.

---

## Where This Project Fits

In this identity platform, authentication flows through the following services:

1. **Client** sends credentials to the **auth-server** (`POST /token`)
2. **auth-server** delegates to **identity-service** for user credential verification (password grant) or to **client-registry-service** for client credential verification (client credentials grant)
3. On success, **auth-server** issues a signed JWT access token
4. Subsequent requests to **example-resource-service** carry the JWT in the `Authorization: Bearer` header
5. **example-resource-service** validates the token via **token-introspection-service** and checks permissions via **authorization-policy-service**

This maps directly onto the layered diagram above — the auth-server and identity-service form the service layer for authentication, while token validation on protected endpoints is a separate authentication check on every subsequent request.
