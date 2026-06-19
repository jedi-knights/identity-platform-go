# Rate limiting — moved

This document described the rate-limiting strategies implemented by `services/api-gateway` while the gateway lived inside this repository.

The gateway has since been extracted to its own repository:

- **[github.com/jedi-knights/api-gateway](https://github.com/jedi-knights/api-gateway)**

The rate-limiting design doc lives there now: [`docs/rate-limiting.md`](https://github.com/jedi-knights/api-gateway/blob/main/docs/rate-limiting.md). All the strategies (token bucket, fixed window, sliding window log, sliding window counter, leaky bucket, concurrency limiter) ship with the gateway and are wired by configuration; no rate-limiting code lives in `identity-platform-go` anymore.
