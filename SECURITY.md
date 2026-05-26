# Authentication Service — Security Posture

This service follows the [Neosofia Service Security Baseline](https://github.com/Neosofia/templates/blob/main/SECURITY.md), which defines the controls required of every platform service. This document covers only what is specific to the Authentication Service.

Because every other service trusts JWTs minted here, the threat model for this service is one of the strictest in the codebase.

To report any security-related issue please email security@neosofia.tech — do not create a public issue.

---

## Service-Specific Standards

| Domain | Standard / Framework |
|---|---|
| **OAuth 2.0 / OIDC** | [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749), [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) (Threat Model), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) (PKCE), [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) (Native Apps BCP) |
| **JSON Web Tokens** | [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) (JWK), [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) (JWA), [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) (JWT), [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) (JWK Thumbprint) |
| **Identity Guidelines** | [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| **Internal Governance** | [ADR-0007](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md) (never roll your own authentication), Constitution §VII (scalability by design) |

---

## Architecture at a Glance

```
┌─────────────┐    OAuth 2.0 + PKCE     ┌──────────────┐
│   Browser   │───────────────────────▶│  WorkOS      │
└──────┬──────┘                         │  AuthKit     │
       │                                └──────┬───────┘
       │ sealed session cookie                 │
       ▼                                       ▼
┌──────────────────────────────────────────────────────┐
│  Authentication Service (Flask)                      │
│  ├─ /login, /callback        OAuth + state + PKCE    │
│  ├─ /api/token (session)     Human JWT (15 min)      │
│  ├─ /api/token (client_cred) Service JWT (5 min)     │
│  ├─ /api/token-inspect       RS256 validation        │
│  └─ /.well-known/jwks.json   Public key publication  │
└──────┬──────────────┬────────────────────────────────┘
       │              │
       ▼              ▼
  PostgreSQL     Other services
  (machine       (validate JWTs offline
   credentials)   via cached JWKS)
```

Key architectural decisions:
- **Stateless validation** — downstream services validate JWTs locally via cached JWKS; no per-request callback to this service or WorkOS.
- **Delegated identity** — WorkOS owns passwords, MFA, federation, and user lifecycle.
- **Short-lived tokens** — human JWTs expire in 15 minutes; Service JWTs in 5. No refresh tokens issued by this service.

---

## Service-Specific Security Controls

### Identity & Authentication

- **Delegated identity provider (WorkOS AuthKit)** — passwords, MFA, federation, account lockout, and user lifecycle are owned by a HIPAA-eligible identity platform. We are a relying party, not a credential store. ([ADR-0007](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md))
- **OAuth 2.0 `state` parameter** — a 32-byte cryptographic random value is generated at `/login`, stored in Flask's signed session (along with the PKCE `code_verifier`), and verified at `/callback`. Mismatch aborts the flow, defeating OAuth CSRF and session-fixation attacks ([CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-384](https://cwe.mitre.org/data/definitions/384.html)).
- **PKCE** ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) — a 128-character code verifier with SHA-256 challenge (`S256`) protects against authorization-code interception.
- **Role allow-list** — `VALID_ROLES` (required env var) defines accepted WorkOS org membership roles. Unknown roles are rejected fail-closed ([CWE-863](https://cwe.mitre.org/data/definitions/863.html)). The service refuses to start if `VALID_ROLES` is unset or empty.

### Token Issuance & Validation

- **Asymmetric signing (RS256)** — all platform JWTs are signed with a 2048-bit RSA private key that lives only in env vars. The public key is published at `/.well-known/jwks.json` ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) for offline validation. No HS256 / shared-secret tokens exist.
- **Audience (`aud`) claim required** — every token carries an `aud` claim. Downstream services validate this claim locally; `/api/token-inspect` is a debug convenience that returns decoded JWT claims if the token is structurally valid.
- **No `iss` claim — by design** — the `iss` (issuer) claim is intentionally omitted. In this closed, single-issuer deployment model each environment has a unique RSA key pair. A token that passes JWKS signature verification *already proves* it came from this auth service — no other service can produce a validly-signed token. The `iss` string check would add no independent security: it is only meaningful in multi-issuer or federated scenarios that do not apply here. RFC 7519 §4.1.1 marks `iss` as OPTIONAL with "application specific" processing. Removing it eliminates an operational risk (stale issuer URLs after domain changes) with no security trade-off. If the deployment model ever changes to multi-issuer or federated identity, re-evaluate.
- **RFC 7638 JWK Thumbprint as `kid`** — stable across deploys; does not leak modulus bits.
- **Dual-key JWKS during rotation** — `JWT_PREVIOUS_PUBLIC_KEY_PEM` can be set alongside `JWT_PUBLIC_KEY_PEM`. When set, both keys appear in `/.well-known/jwks.json` so downstream caches can verify tokens signed by either key during the rotation overlap window. See **OPERATIONS.md Appendix B** for the step-by-step runbook.

### Session Management

- **Sealed session cookie (WorkOS SDK)** — AES-256-GCM + HMAC with a 32-character platform-supplied cookie password. Tampering is detected at decryption.
- **Cookie hardening** — the sealed `wos_session` cookie is set (and cleared on logout) with `HttpOnly`, `Secure`, `SameSite=None`, and `path="/"`. `SameSite=None` is required because the CDP UI and this service run on different origins and the browser sends the cookie on credentialed `POST /api/token` requests via CORS. Set and delete must use identical attributes or browsers retain the cookie. OAuth `state` and PKCE verifier are not separate browser cookies; they live in Flask's signed session.
- **Stateless architecture** — no server-side session store; aligns with Constitution §VII.
- **`CSRF_SECRET_KEY` signs the Flask session cookie** — the OAuth `state` parameter and PKCE `code_verifier` are stored in Flask's signed session (not a separate browser cookie). Compromising this key defeats OAuth state binding. **Rotate `CSRF_SECRET_KEY` and `WORKOS_COOKIE_PASSWORD` together** on the same cadence (generate independently with `openssl rand -hex 32` / `openssl rand -base64 32`). A rotation requires a brief service restart; all in-flight OAuth flows are invalidated at that point.

### service-to-service Credentials

- **bcrypt-hashed secrets** — stored at cost factor 12; never reversible. Compromised credentials are revoked by **rotating** the service secret via `POST /api/services/{slug}/rotate` (replaces the bcrypt hash in place; audit history preserved).
- **Constant-time verification** — a dummy hash is pre-computed at import; unknown `client_id` submissions still run `bcrypt.checkpw` to prevent enumeration via timing side-channel ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)).

### Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /login` | 60 / minute |
| `GET /callback` | 60 / minute |
| `POST /api/token` | 20 / minute |
| `GET /api/token-inspect` | 10 / minute (development only) |
| `GET /api/profile` | 60 / minute |
| `GET/POST /api/services/*` | 60 / minute |
| `GET/POST /logout` | 60 / minute |

### UI Token Handling

The CDP UI is a public SPA client and is **not** registered as a platform service.

- **JWT stored in React state (in-memory)** — The platform JWT returned by `POST /api/token` is held in JS memory, not `localStorage` or a cookie. This is the OWASP-preferred storage for SPA access tokens: in-memory state is not persisted to disk, not accessible by other origins, and is destroyed on tab close. ([OWASP Cheat Sheet: Storing tokens](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html))
- **Short TTL bounds exposure** — Human JWTs expire in 15 minutes. An XSS that exfiltrates the token has a maximum 15-minute replay window; the sealed `wos_session` credential remains in an `HttpOnly`/`Secure`/`SameSite=None` cookie and is not accessible to JS.
- **Real credential stays HttpOnly** — The upstream credential (`wos_session`) is sealed with AES-256-GCM and served as `HttpOnly`/`Secure`/`SameSite=None`. Even a successful XSS cannot exfiltrate it.
- **CSP `script-src 'self'`** — Talisman enforces this in production, substantially narrowing the XSS surface.
- **Rec §3.4 evaluated and accepted as-is** — Issuing the JWT into an `HttpOnly` cookie (the "Token Handler" / BFF pattern) was considered. The tradeoffs outweigh the marginal gain given the 15-minute TTL and the HttpOnly sealed session already protecting the real credential. The UI and this service are already cross-origin (`FRONTEND_URL`); credentialed CORS to `/api/token` depends on `SameSite=None` on `wos_session`. Re-evaluate the BFF pattern if the JWT TTL is extended beyond 15 minutes.

### Web-Layer Defenses

- **Bearer JWT for privileged API routes** — `/api/profile` and `/api/services/*` require `Authorization: Bearer`. Cross-origin sites cannot inject the in-memory platform JWT, so classic CSRF does not apply to those mutations.
- **`POST /api/token`** — bound by HTTP Basic auth (`client_credentials`) or the sealed `wos_session` cookie; attackers cannot read token responses cross-origin.
- **Request body size cap** — `MAX_CONTENT_LENGTH = 16 KiB` rejects body-flood DoS before the body parser runs.
- **Debug mode off** — gated on `ENV=development`; eliminates the Werkzeug debugger RCE surface in production ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)).


## Threat Model Summary

### What This Service Defends Against

| Threat | Control |
|---|---|
| Credential theft of signing key | Private key only in env vars; unprivileged container user |
| JWT forgery | RS256 + JWKS signature + `aud` + `exp` validation (no `iss` claim — see Token Issuance) |
| Session hijacking | `HttpOnly`, `Secure`, `SameSite=None`; AES-256-GCM sealed cookie |
| Session fixation / OAuth CSRF | `state` + PKCE |
| Auth code interception | PKCE (RFC 7636) |
| Cross-service token replay | Per-service `aud` claim |
| Credential stuffing / brute force | Rate limiting + constant-time bcrypt |
| Service credential enumeration | Constant-time dummy hash |
| Clickjacking | `frame-ancestors 'none'` |
| Protocol downgrade | HSTS (1 year) |
| PHI exposure in logs | No email / names / DOB in any log event |

### What This Service Explicitly Delegates

| Concern | Owner |
|---|---|
| Password strength, rotation, storage | WorkOS |
| Multi-factor authentication | WorkOS |
| Account lockout | WorkOS |
| Identity federation (SAML, OIDC, Google, etc.) | WorkOS |
| TLS termination and certificate management | Ingress controller / load balancer |
| DDoS absorption (volumetric) | Firewall / CDN layer |
| Authorization decisions | Authorization Service (spec 016) |
| Audit trail aggregation & retention | Audit Infrastructure Service (spec 017) |

---

## Known Limitations

| Item | Status | Notes |
|---|---|---|
| Rate limit storage is per-node (in-memory) | Accepted | Upgrade to Redis via `RATELIMIT_STORAGE_URI` when shared Redis is available |
| `/api/token-inspect` decode-only semantics | Accepted | The endpoint does not verify signature, expiry, issuer, or audience — it only rejects structurally invalid JWTs. A caller already in possession of a JWT can read the unencrypted claims directly (they are base64-encoded, not encrypted). No confidentiality is lost, but the endpoint is gated to `ENV=development`/`test` (returns 404 in production) and rate-limited to 10 / minute to limit its use as a recon aid. |
| WorkOS session refresh logic opaque to this service | Accepted | WorkOS SDK handles refresh internally |

---

## References

- [ADR-0007: Never roll your own authentication](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md)
- [ADR-0009: Structured JSON logging with schema validation](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0009-structured-json-logging-with-schema-validation.md)
- [Constitution](https://github.com/Neosofia/cdp/blob/main/architecture/constitution.md)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

