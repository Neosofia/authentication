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
| **Internal Governance** | [ADR-0007](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md) (never roll your own authentication), Constitution §VII (stateless), §VIII (defense in depth) |

---

## Architecture at a Glance

```
┌─────────────┐    OAuth 2.0 + PKCE     ┌──────────────┐
│   Browser   │────────────────────────▶│  WorkOS      │
└──────┬──────┘                         │  AuthKit     │
       │                                └──────┬───────┘
       │ sealed session cookie                 │
       ▼                                       ▼
┌──────────────────────────────────────────────────────┐
│  Authentication Service (Flask)                      │
│  ├─ /login, /callback        OAuth + state + PKCE    │
│  ├─ /api/token (session)     Human JWT (15 min)      │
│  ├─ /api/token (client_cred) Service JWT (5 min)     │
│  ├─ /api/token-inspect        RS256 validation        │
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
- **OAuth 2.0 `state` parameter** — a 32-byte cryptographic random value is bound to a `HttpOnly`/`Secure`/`SameSite=Lax` cookie with a 5-minute TTL and verified at `/callback`. Mismatch aborts the flow, defeating OAuth CSRF and session-fixation attacks ([CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-384](https://cwe.mitre.org/data/definitions/384.html)).
- **PKCE** ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) — a 128-character code verifier with SHA-256 challenge (`S256`) protects against authorization-code interception.
- **Role allow-list** — `VALID_ROLES` (required env var) defines accepted WorkOS org membership roles. Unknown roles are rejected fail-closed ([CWE-863](https://cwe.mitre.org/data/definitions/863.html)). The service refuses to start if `VALID_ROLES` is unset or empty.

### Token Issuance & Validation

- **Asymmetric signing (RS256)** — all platform JWTs are signed with a 2048-bit RSA private key that lives only in env vars. The public key is published at `/.well-known/jwks.json` ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) for offline validation. No HS256 / shared-secret tokens exist.
- **Issuer + audience claims** — every token contains `iss` and `aud`. `/api/token-inspect` enforces `["exp", "iat", "iss", "sub", "aud"]` via `pyjwt`, preventing cross-service token replay ([CWE-347](https://cwe.mitre.org/data/definitions/347.html)).
- **RFC 7638 JWK Thumbprint as `kid`** — stable across deploys; does not leak modulus bits.

### Session Management

- **Sealed session cookie (WorkOS SDK)** — AES-256-GCM + HMAC with a 32-character platform-supplied cookie password. Tampering is detected at decryption.
- **Cookie hardening** — all cookies set with `HttpOnly`, `Secure` (production), `SameSite=Lax`, `path="/"`.
- **Stateless architecture** — no server-side session store; satisfies Constitution §VII.

### service-to-service Credentials

- **bcrypt-hashed secrets** — stored at cost factor 12; never reversible. `ServiceCredential.active` flag enables immediate revocation.
- **Constant-time verification** — a dummy hash is pre-computed at import; unknown `client_id` submissions still run `bcrypt.checkpw` to prevent enumeration via timing side-channel ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)).

### Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /login` | 60 / minute |
| `GET /callback` | 60 / minute |
| `POST /api/token` | 20 / minute |

### Web-Layer Defenses

- **CSRF protection (Flask-WTF)** — all state-changing routes protected by default. `/api/token` exempted because it is bound by Basic auth or the sealed session cookie.
- **Request body size cap** — `MAX_CONTENT_LENGTH = 16 KiB` rejects body-flood DoS before the body parser runs.
- **Debug mode off** — gated on `ENV=development`; eliminates the Werkzeug debugger RCE surface in production ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)).

---

## Threat Model Summary

### What This Service Defends Against

| Threat | Control |
|---|---|
| Credential theft of signing key | Private key only in env vars; unprivileged container user |
| JWT forgery | RS256 + iss + aud + exp validation |
| Session hijacking | `HttpOnly`, `Secure`, `SameSite=Lax`; AES-256-GCM sealed cookie |
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
| `/api/token-inspect` is not rate-limited | Accepted | Downstream services validate JWTs locally; this endpoint is a dev/debug convenience |
| WorkOS session refresh logic opaque to this service | Accepted | WorkOS SDK handles refresh internally |

---

## References

- [ADR-0007: Never roll your own authentication](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md)
- [ADR-0009: Structured JSON logging with schema validation](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0009-structured-json-logging-with-schema-validation.md)
- [Constitution](https://github.com/Neosofia/cdp/blob/main/architecture/constitution.md)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

