# Authentication & Authorization Mechanisms

This directory contains reference documentation for common authentication and authorization mechanisms. Each document explains the mechanism's design, how it works, its security properties, and where it fits in a modern identity platform.

## Documents

| Document | Mechanism | Summary |
|----------|-----------|---------|
| [basic-auth.md](basic-auth.md) | HTTP Basic Authentication | Username/password sent with every request via the `Authorization` header |
| [digest-auth.md](digest-auth.md) | HTTP Digest Authentication | Challenge-response scheme that avoids sending passwords in cleartext |
| [api-keys.md](api-keys.md) | API Keys | Static credentials for identifying and rate-limiting API consumers |
| [session-auth.md](session-auth.md) | Session-Based Authentication | Server-side session state tied to a browser cookie |
| [bearer-jwt-tokens.md](bearer-jwt-tokens.md) | Bearer Tokens & JWT | Stateless tokens carried in the `Authorization` header |
| [access-refresh-tokens.md](access-refresh-tokens.md) | Access & Refresh Tokens | Short-lived access tokens paired with long-lived refresh tokens |
| [oauth2.md](oauth2.md) | OAuth 2.0 | Delegated authorization framework for third-party access |
| [openid-connect.md](openid-connect.md) | OpenID Connect (OIDC) | Identity layer on top of OAuth 2.0 for authentication |
| [sso.md](sso.md) | Single Sign-On (SAML & OIDC) | Federated authentication across multiple applications |

## How These Relate

These mechanisms form a progression from simple to sophisticated:

```
Credential-per-request          Stateful sessions          Token-based          Delegated/Federated
─────────────────────          ─────────────────          ───────────          ────────────────────
Basic Auth                     Session + Cookie           Bearer/JWT           OAuth 2.0
Digest Auth                                               Access/Refresh       OpenID Connect
API Keys                                                                       SSO (SAML, OIDC)
```

Simple mechanisms (Basic, API Keys) work well for internal or machine-to-machine communication. Token-based mechanisms (JWT, OAuth2) suit distributed systems. Federated mechanisms (OIDC, SAML) enable enterprise SSO across organizational boundaries.
