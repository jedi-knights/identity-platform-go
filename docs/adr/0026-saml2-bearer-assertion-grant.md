# ADR-0026: SAML 2.0 Bearer Assertion Grant (RFC 7522)

**Status**: Accepted
**Date**: 2026-07-08

## Context

RFC 7522 lets a client exchange a SAML 2.0 assertion for an OAuth access token — a federation bridge for organizations whose identity provider speaks SAML rather than OIDC. This ADR implements RFC 7522 §2.1/§3 only: **the SAML assertion as an authorization grant** (`grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer`), where the assertion's `Subject` identifies the resource owner a token is being minted for. RFC 7522 §2.2 (using a SAML assertion for *client authentication*, as an alternative to `client_secret`) is explicitly **out of scope** — this repo already has the JWT-based analogue of that (RFC 7521/7523, client assertion authentication), and duplicating the same mechanism in a second assertion format is not worth the combinatorial surface increase.

### Two decisions made before writing any code

**1. Trusted-issuer certificate registration.** RFC 7521 §5.1 explicitly leaves "how the client and authorization server establish which assertion issuers are trusted" to the deployment. This platform extends `client-registry-service`'s `OAuthClient` record with an optional `TrustedIssuerCert` field (PEM-encoded X.509) — the registered OAuth client (not the SAML IdP) is the trust anchor: a client that wants to use `saml2-bearer` registers the certificate of the SAML IdP whose assertions it will present. This mirrors RFC 7521/7523's `jwks_uri` field precedent exactly (same record, same "optional capability the client opts into" shape) rather than a separate trusted-issuers store, which would be more surface for a reference implementation with no second consumer of that data.

**2. `github.com/crewjam/saml` doesn't do what the phase-planning research assumed.** Its only exported entrypoints (`ParseResponse`, `ParseXMLResponse`, `ParseXMLArtifactResponse`) are irreducibly shaped around a full browser SSO `<samlp:Response>` envelope — `Destination`, `InResponseTo` tracked against `possibleRequestIDs`, `sp.AcsURL`, `sp.IDPMetadata.EntityID` comparisons are baked into unexported functions (`parseResponse`, `validateAssertion`, `validateSignature`). **There is no supported entrypoint for validating a bare RFC 7522 `<Assertion>` with no envelope, no ACS, no redirect.** The library was never going to remove the "hand-rolled crypto" risk the original plan hoped it would; the actual per-assertion signature verification and condition checks are all unexported.

  The workable path, and what this ADR implements: reuse `crewjam/saml`'s exported `schema.go` types (`saml.Assertion`, `saml.Conditions`, `saml.Subject`, `saml.SubjectConfirmation`, `saml.SubjectConfirmationData`, `saml.AudienceRestriction`, `saml.Issuer`) purely as `encoding/xml` unmarshal targets — their struct tags carry no SP-context — and call `github.com/russellhaering/goxmldsig` **directly** for signature verification, mirroring (not depending on) the private logic `crewjam/saml` itself uses: strip `Signature/KeyInfo` when it has no `X509Certificate` child (forces verification against the *registered* trusted cert, never an attacker-supplied one embedded in the assertion), set `IdAttribute = "ID"`, and validate the **exact element the claims were read from** — never re-look-up "the assertion" by any other means after the fact. This last point is the single most important invariant in SAML validation: signature-wrapping attacks work by getting the validator to check one XML element's signature while the application reads claims from a different, unsigned (or differently-signed) sibling element.

  **Required dependency override, non-negotiable**: `crewjam/saml@v0.5.1`'s `go.mod` requires `russellhaering/goxmldsig@v1.4.0`, which has an **open, unpatched, upstream-unfixed** vulnerability — **CVE-2026-33487** ("`validateSignature` Loop Variable Capture Signature Bypass"), a real signature-wrapping-class bug: `goxmldsig@v1.4.0`'s reference-matching loop takes the address of a shared loop variable instead of the slice element, so a `SignedInfo` with multiple `Reference`s can make the "matched" reference end up pointing at attacker-chosen content while the digest check runs against different data. The fix (per-reference addressing) exists in `goxmldsig@v1.6.0`, whose exported API (`NewDefaultValidationContext`, `ValidationContext{CertificateStore, IdAttribute, Clock}`, `MemoryX509CertificateStore{Roots}`, `Validate(el) (*etree.Element, error)`) is unchanged from v1.4.0. This repo's `go.mod` explicitly requires `russellhaering/goxmldsig v1.6.0` — Go's Minimal Version Selection honors the higher explicit requirement over `crewjam/saml`'s declared `v1.4.0`, so the build uses the patched version without forking or patching `crewjam/saml` itself. **Drop this override once `crewjam/saml` ships a release requiring `goxmldsig >= 1.6.0`** (as of this ADR, two unmerged upstream PRs — #662, #664 — exist for exactly this bump).

## Decision

### Validation pipeline (`application.SAMLBearerValidator`, mirrors `application.DPoPValidator`'s placement — domain has no external imports per this repo's architecture rule, so the crypto lives in application, not domain)

Given raw assertion XML (base64url-decoded from the `assertion` form parameter by the HTTP layer) and the authenticated client's `TrustedIssuerCert`:

1. Parse the client's `TrustedIssuerCert` PEM into an `*x509.Certificate`.
2. Unmarshal the raw XML into `saml.Assertion` via `encoding/xml`, and separately parse it into a `*etree.Element` (needed for signature verification — `goxmldsig` operates on `etree`, not `encoding/xml` structs).
3. Verify the signature: strip `Signature/KeyInfo` unless it has no `X509Certificate` child (same as `crewjam/saml`'s own defense — never trust an assertion's self-declared key), build a `dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{trustedCert}}`, call `dsig.NewDefaultValidationContext(&store).Validate(assertionElement)`. Reject on any error. **Read all subsequent claims from the `saml.Assertion` unmarshaled from this same validated XML — never re-fetch or re-parse.**
4. `Conditions.NotBefore`/`NotOnOrAfter` (both plain `time.Time`, not pointers — `IsZero()` distinguishes "absent" from "present" since the RFC 7522 wire format may omit either) must bracket now.
5. `Conditions.AudienceRestrictions` must contain an `Audience` equal to this auth-server's token endpoint URL (RFC 7522 §3's audience-restriction requirement) — reconstructed from the live request via the same `requestURL(r)` helper ADR-0025 already introduced for DPoP's `htu`, not a configured "public base URL."
6. `Subject.SubjectConfirmations` must contain one with `Method == "urn:oasis:names:tc:SAML:2.0:cm:bearer"` whose `SubjectConfirmationData.Recipient` equals the token endpoint URL and whose `NotOnOrAfter` has not passed.
7. Return `Subject.NameID.Value` (the resource owner identity the issued token represents) and `Issuer.Value` (recorded for audit, not otherwise used — trust was already established via the client's registered certificate, not the issuer string).

### Grant strategy (`application.SAMLBearerStrategy`, registered via the existing Strategy/Registry extension point)

`domain.GrantTypeSAML2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"`. `Handle`:
1. Reject if `req.SAMLAssertion == ""` (`invalid_request`).
2. `s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)` — the OAuth client authenticates itself exactly as it does for every other grant; the SAML assertion is a *separate* artifact identifying the resource owner, not a client-authentication mechanism (that's RFC 7522 §2.2, out of scope).
3. Reject if the client lacks `saml2-bearer` in its registered grant types (`unauthorized_client`).
4. Reject if `client.TrustedIssuerCert == ""` (`invalid_grant` — no trust established for this client, so the assertion cannot be verified regardless of its own validity).
5. Run the validation pipeline above.
6. Issue an access token: `Subject` = the assertion's `NameID`, `ActorType = domain.ActorTypeUser` (mirrors `AuthorizationCodeStrategy`'s ADR-0015 reasoning — a SAML-asserted token represents a human resource owner, not the client itself, regardless of the client's own `ActorType`), `Scopes` = requested scopes intersected with the client's registered scopes (mirrors `ClientCredentialsStrategy.resolveScopes`).

**No refresh token is issued for this grant.** Unlike `client_credentials` (which this reference implementation issues refresh tokens for, against RFC 6749 §4.4.3's SHOULD NOT, specifically to make the full lifecycle testable), an assertion grant's natural re-authorization mechanism is presenting a fresh assertion — the IdP mints a new one, short-lived by design (`NotOnOrAfter`). Issuing a long-lived refresh token here would extend access far past what any individual assertion ever authorized, undermining the whole point of a short-lived bearer assertion.

## Consequences

### Positive

- Fully real, end-to-end tested: a real self-signed X.509 certificate and a real signed SAML assertion (generated in-process by the acceptance suite, mirroring how PKCE scenarios generate their own `code_verifier` rather than depending on a fixture — no external IdP dependency).
- The signature-wrapping mitigation (validate the exact parsed element, KeyInfo-stripping, patched `goxmldsig`) is the load-bearing security property and is explicit, tested, and documented — not an incidental side effect of calling a library function.
- No new persistent trust-anchor infrastructure — reuses the existing client record and its existing memory/clientregistry-HTTP dual-adapter pattern.

### Negative

- **Hand-rolled validation, not library-provided**, despite using `crewjam/saml` — stated explicitly rather than implied. A future upstream release with a standalone-assertion entrypoint could replace this ADR's `application.SAMLBearerValidator` with a thinner wrapper; until then, this repo owns the correctness of steps 3-6 above.
- **Explicit dependency override** (`goxmldsig >= 1.6.0`) that must be watched for staleness — if `crewjam/saml` ships a release with an even newer `goxmldsig` requirement, or if a *different* CVE surfaces in `goxmldsig` before `crewjam/saml` catches up, this repo's override needs to move independently.
- RFC 7522 §2.2 (SAML client authentication) is not implemented — a deployment wanting that would need a second grant/auth-method addition later.
- No refresh token — a client must re-obtain a fresh assertion from its IdP for every token, by design (see above), but this means the grant is unsuitable for long-running background access without repeated IdP round trips. Acceptable for a reference implementation demonstrating the federation bridge, not for a production long-lived-access use case.

## Alternatives Considered

- **Wrap the raw assertion in a synthetic `<samlp:Response>` envelope just to use `crewjam/saml`'s `ParseXMLResponse`.** Rejected — fragile, and semantically wrong: RFC 7522 assertions are never wrapped in a Response, and doing so would mean fighting `Destination`/`InResponseTo`/`sp.AcsURL` checks that have no RFC 7522 meaning, for no real benefit over calling `goxmldsig` directly.
- **A separate trusted-issuers store, decoupled from OAuth client records.** Rejected — more new surface (a new repository, a new admin API) for a reference implementation with exactly one consumer of the data (this grant), when the client record already has a precedent field (`jwks_uri`) for exactly this "client opts into an extra capability" shape.
- **Wait for `crewjam/saml` to ship a `goxmldsig >= 1.6.0` release rather than overriding.** Rejected — the CVE is a live signature-integrity bypass in the exact code path this feature depends on; shipping this feature on a known-vulnerable transitive dependency when a same-API-surface fix is one `go.mod` line away is not defensible, reference implementation or not.
- **Issue a refresh token, matching `client_credentials`'s existing precedent.** Rejected — see Consequences above; a long-lived refresh token would outlive the trust boundary an individual short-lived assertion establishes.

## References

- [RFC 7522 — SAML 2.0 Bearer Assertion Profile for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc7522)
- [RFC 7521 — Assertion Framework for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc7521)
- [GHSA-479m-364c-43vc / CVE-2026-33487](https://github.com/russellhaering/goxmldsig/security/advisories/GHSA-479m-364c-43vc) — `goxmldsig` signature bypass via loop-variable capture
- [GHSA-j2jp-wvqg-wc2g / CVE-2022-41912](https://github.com/crewjam/saml/security/advisories/GHSA-j2jp-wvqg-wc2g) — `crewjam/saml` signature bypass via multiple `Assertion` elements (historical precedent for the signature-wrapping attack class this ADR's validation order defends against)
- [ADR-0005 — Adapter Scalability Contract](0005-adapter-scalability-contract.md)
- [ADR-0015 — Agent Principal Type](0015-agent-principal-type.md)
- [ADR-0025 — DPoP: Demonstrating Proof of Possession (RFC 9449)](0025-dpop-proof-of-possession.md) — precedent for `application`-layer crypto validators and the `requestURL(r)` live-request-reconstruction pattern
