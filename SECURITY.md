# Authentication Service — Security Posture

This document describes the security posture of the PDC Authentication Service — the system of record for human and machine identity, token issuance, and session lifecycle for the entire PDC platform. Because every other service trusts JWTs minted here, the threat model for this service is one of the strictest in the codebase.

To report any security related issue please email security@neosofia.tech -- do not create an issue.

## 1. Standards & Frameworks

The service is designed and audited against the following bodies of work:

| Domain | Standard / Framework |
|---|---|
| **OAuth 2.0 / OIDC** | [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) (OAuth 2.0), [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) (Threat Model), [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) (PKCE), [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) (Native Apps BCP) |
| **JSON Web Tokens** | [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) (JWK), [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) (JWA), [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) (JWT), [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) (JWK Thumbprint), [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) (Token Introspection) |
| **Web Application Security** | [OWASP Top 10 (2021)](https://owasp.org/Top10/), [OWASP ASVS Level 2](https://owasp.org/www-project-application-security-verification-standard/), [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) |
| **Cryptographic Weakness** | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) (Timing), [CWE-287](https://cwe.mitre.org/data/definitions/287.html) (Improper Auth), [CWE-347](https://cwe.mitre.org/data/definitions/347.html) (Improper Signature Verification), [CWE-352](https://cwe.mitre.org/data/definitions/352.html) (CSRF), [CWE-384](https://cwe.mitre.org/data/definitions/384.html) (Session Fixation), [CWE-522](https://cwe.mitre.org/data/definitions/522.html) (Insufficiently Protected Credentials) |
| **Healthcare Compliance** | [HIPAA Security Rule §164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) (audit, integrity, transmission security); no PHI in logs per internal Constitution §I |
| **Transport Security** | [TLS 1.2+](https://datatracker.ietf.org/doc/html/rfc5246) (enforced at ingress); [HSTS](https://datatracker.ietf.org/doc/html/rfc6797) (1 year, includeSubDomains) |
| **Identity Guidelines** | [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) (Digital Identity — Authentication & Lifecycle) |
| **Internal Governance** | [Constitution §I](https://github.com/Neosofia/cdp/blob/main/.specify/memory/constitution.md) (no PHI/PII in logs), §VII (stateless), §VIII (defense in depth); [ADR-0007](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md) (never roll your own authentication) |

We delegate identity verification to **WorkOS AuthKit** (a HIPAA-eligible identity platform) rather than implementing credential storage, MFA, or password policies ourselves.

---

## 2. Architecture at a Glance

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
│  ├─ /api/token (client_cred) Machine JWT (5 min)     │
│  ├─ /api/me                  RS256 validation        │
│  └─ /.well-known/jwks.json   Public key publication  │
└──────┬──────────────┬────────────────────────────────┘
       │              │
       ▼              ▼
  PostgreSQL     Other PDC services
  (machine       (validate JWTs offline
   credentials)   via cached JWKS)
```

Key architectural decisions:
- **Stateless validation:** Downstream services validate JWTs locally via cached JWKS — no per-request callback to this service or WorkOS.
- **Delegated identity:** WorkOS owns passwords, MFA, federation, and user lifecycle.
- **Short-lived tokens:** Human JWTs expire in 15 minutes; machine JWTs in 5. No refresh tokens issued by this service (refresh is via the sealed WorkOS session cookie).

---

## 3. Security Controls

Controls are grouped by the risk domain they address. Every control listed below is active in the current code, verified by the test suite, and exercised end-to-end via the `/login` → `/callback` → `/api/token` → `/api/me` → `/logout` flow.

### 3.1 Identity & Authentication

- **Delegated identity provider (WorkOS AuthKit)** — passwords, MFA, federation, account lockout, and user lifecycle are owned by a HIPAA-eligible identity platform. We are a relying party, not a credential store. ([ADR-0007](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md))
- **OAuth 2.0 `state` parameter** ([RFC 6819 §4.4.1.8](https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.8)) — a 32-byte cryptographic random value is generated at `/login`, bound to a `HttpOnly`/`Secure`/`SameSite=Lax` cookie with a 5-minute TTL, and verified at `/callback`. Mismatch logs `oauth_state_mismatch` and aborts the flow, defeating OAuth CSRF and session-fixation attacks ([CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-384](https://cwe.mitre.org/data/definitions/384.html)).
- **PKCE** ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) — a 128-character code verifier is generated alongside `state`; its SHA-256 challenge is sent to WorkOS with `code_challenge_method=S256`, and the verifier is cookie-stored for the callback. Protects against authorization-code interception even if TLS is compromised.
- **User-type allow-list** — `VALID_USER_TYPES = frozenset({"clinician", "patient"})` with a strict `WORKOS_ROLE_TO_PDC_TYPE` mapping. Unknown roles or user types are rejected fail-closed, preventing privilege escalation via provider-side role injection.

### 3.2 Token Issuance & Validation

- **Asymmetric signing (RS256)** — all platform JWTs are signed with a 2048-bit RSA private key. The private key lives only in env vars; the public key is published at `/.well-known/jwks.json` ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) for offline validation by other services. No HS256 / shared-secret tokens exist anywhere in the platform.
- **Issuer + audience claims** — every token contains `iss = "https://auth.pdc.local"` and `aud = "pdc-auth-svc"`. `/api/me` requires `["exp", "iat", "iss", "sub", "aud"]` via `pyjwt.decode(..., options={"require": [...]})`, preventing cross-service token replay ([CWE-347](https://cwe.mitre.org/data/definitions/347.html)).
- **Short-lived tokens** — human JWTs expire in 15 minutes, machine JWTs in 5. No refresh tokens issued by this service; re-issuance requires a valid sealed WorkOS session cookie.
- **RFC 7638 JWK Thumbprint as `kid`** — the `kid` in the published JWKS is the base64url-encoded SHA-256 hash of the canonical JSON representation of the key, per [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638). Stable across deploys and doesn't leak modulus bits.

### 3.3 Session Management

- **Sealed session cookie (WorkOS SDK)** — the `wos_session` cookie holds the session in encrypted, authenticated form (AES-256-GCM + HMAC) with a 32-character platform-supplied cookie password. Tampering is detected at decryption.
- **Cookie hardening** — every cookie (`wos_session`, `oauth_state`, `code_verifier`) is set with `HttpOnly`, `Secure` (in production), `SameSite=Lax`, and explicit `path="/"`.
- **Stateless architecture** — no server-side session store. All request context flows in the sealed cookie or Bearer JWT, satisfying Constitution §VII and permitting horizontal scaling without sticky sessions.

### 3.4 Machine-to-Machine Credentials

- **bcrypt-hashed secrets** — `client_id` + `client_secret` pairs are stored with bcrypt cost factor 12. Secrets are hashed at issuance and never reversible. The `MachineCredential.active` flag enables immediate revocation.
- **Constant-time verification** — a module-level `_DUMMY_HASH` is pre-computed at import. When an unknown `client_id` is submitted, we still perform `bcrypt.checkpw(_DUMMY_SECRET, _DUMMY_HASH)`, matching the timing of the happy path and preventing enumeration via side-channel ([CWE-208](https://cwe.mitre.org/data/definitions/208.html)).

### 3.5 Network Isolation & Transport Security

**TLS termination at the edge**

In all deployment environments, TLS is terminated at the ingress layer — Traefik (dev/staging) or CloudFront + API Gateway (prod). Traffic from the ingress to the service container travels over plain HTTP within an isolated network segment:

- **Dev:** Docker bridge network (`authentication_default`) inside a single LXC container. Traffic never leaves the container.
- **Prod:** AWS VPC private subnet. The ECS Fargate task is unreachable from the internet; only the API Gateway (also inside the VPC) can route to it.

This is the standard TLS-termination-at-edge pattern and is compliant with HIPAA §164.312(e)(1) (transmission security) and GDPR Article 32, which require encryption over *untrusted/public* networks — not within an isolated private segment. More stringent frameworks (PCI-DSS v4 Requirement 4.2.1; FedRAMP High / DoD IL4+ via NIST SP 800-53 SC-8) mandate encryption for *all* in-transit data including internal hops — at that point, mutual TLS between containers (e.g. via a service mesh) would be required.

### 3.6 Web-Layer Defenses

- **CSRF protection (Flask-WTF)** — all state-changing routes are CSRF-protected by default. `/api/token` is exempted because its binding mechanism is Basic auth or the sealed session cookie itself (`SameSite=Lax` + cryptographic sealing).
- **Security headers (Flask-Talisman, production)** — HSTS (`max-age=31536000; includeSubDomains`), strict Content Security Policy (`default-src 'self'; script-src 'self'; frame-ancestors 'none'`; no inline JS), `Referrer-Policy: strict-origin-when-cross-origin`, forced HTTPS. No inline `<script>` tags — client JS is loaded from `static/app.js`.
- **Request body size cap** — `MAX_CONTENT_LENGTH = 16 KiB` (configurable via env var) rejects body-flood DoS attempts. Flask returns `413 Request Entity Too Large` before the body parser runs. JWTs ride in the `Authorization` header, so they're unaffected.
- **Debug mode off by default** — `debug=` is gated on `ENV=development`, eliminating the Werkzeug debugger RCE surface ([CWE-489](https://cwe.mitre.org/data/definitions/489.html)) in production.
- **CORS** — browser clients reach this service through the Traefik reverse proxy (`auth.localhost` in dev; the platform ingress in production). No cross-origin browser requests to this service are expected; CORS response headers are therefore not configured here. When the platform API gateway is adopted (TBD), all services will share a single domain, eliminating cross-origin concerns entirely. Until then, if a cross-origin client is added, configure `CORS_ALLOWED_ORIGINS` per-service at that time.

### 3.7 Rate Limiting

Per-node rate limiting via [Flask-Limiter](https://flask-limiter.readthedocs.io/), using in-memory storage. Upgrade path to shared Redis limits via `RATELIMIT_STORAGE_URI=redis://...` — no code changes required.

| Endpoint | Limit | Scope |
|---|---|---|
| `POST /login` | 60 / minute | per client IP |
| `GET /callback` | 60 / minute | per client IP |
| `POST /api/token` | 20 / minute | per client IP |

**Sizing rationale:** 60/min tolerates a large hospital network behind a single NAT during shift changes (effectively 120/min across two nodes via round-robin). 20/min on token issuance accommodates normal 15-minute refresh cycles plus burst tolerance. DDoS absorption is delegated to the firewall / CDN layer; these in-process limits are for per-node abuse protection and credential brute-force resistance ([CWE-307](https://cwe.mitre.org/data/definitions/307.html)).

### 3.8 Observability & Audit

- **Structured JSON logs ([ADR-0009](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0009-structured-json-logging-with-schema-validation.md))** — every security-relevant event (`login_initiated`, `authentication_success`, `oauth_state_mismatch`, `machine_auth_failure`, `session_revoked`, …) emits JSON validated against [schemas/log.json](https://github.com/Neosofia/cdp/blob/main/schemas/log.json) at CI time.
- **No PHI / PII in logs (Constitution §I)** — only opaque WorkOS user IDs (e.g. `user_01KPMY3Q...`). No emails, names, DOBs, or phone numbers appear in any log event.
- **Error class preserved on callback failures** — `/callback` exceptions log `error_class` (the exception class name) and a truncated message, distinguishing WorkOS failures from unexpected application errors without leaking stack traces to clients.
- **SIEM integration (TBD)** — the structured JSON log format is designed for ingestion by a SIEM (e.g. Splunk, Elastic SIEM, AWS Security Lake). Schema-validated events with consistent `event_type` fields enable correlation rules for brute-force detection, anomalous login patterns, and token misuse across services.

### 3.9 Platform & Supply Chain

- **Typed configuration, fail-closed** — all secrets (`JWT_PRIVATE_KEY_PEM`, `WORKOS_API_KEY`, `WORKOS_COOKIE_PASSWORD`, `CSRF_SECRET_KEY`, …) come exclusively from environment variables via `pydantic-settings`. Missing required values cause startup failure.
- **Dependency pinning (`uv` + lockfile)** — `uv.lock` records cryptographic hashes for every dependency. `uv sync --frozen` is enforced in CI, blocking uncontrolled upgrades ([CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)).
- **Vulnerability scanning (trivy)** — `trivy fs` (lockfile) and `trivy image` (built image) run in `.github/workflows/authentication-trivy.yml`, failing the build on any CRITICAL or HIGH finding.
- **Schema-versioned migrations (Alembic)** — no ad-hoc `ALTER TABLE` in application code. Schema changes are reviewed and reversible.
- **Least-privilege container** — the production image runs as an unprivileged user on a minimal Alpine base with no shell tools.

---

## 4. Threat Model Summary

### 4.1 What This Service Defends Against

| Threat | Control |
|---|---|
| Credential theft of signing key | Private key only in env vars; container runs as unprivileged user |
| JWT forgery | RS256 signing; all services validate signature + iss + aud + exp |
| Session hijacking via cookie theft | `HttpOnly`, `Secure`, `SameSite=Lax`; sealed with AES-256-GCM |
| Session fixation / OAuth CSRF | `state` parameter + PKCE |
| Auth code interception | PKCE (RFC 7636) |
| Cross-service token replay | Per-service `aud` claim + validation |
| Credential stuffing / brute force on `/api/token` | Rate limiting + constant-time bcrypt |
| Machine credential enumeration | Constant-time verification via dummy hash |
| Clickjacking | `frame-ancestors 'none'` via Talisman |
| Protocol downgrade | HSTS (1 year) |
| Supply-chain tampering | `uv.lock` with hashes |
| PHI exposure in logs | No email / names / DOB in any log event |

### 4.2 What This Service Explicitly Delegates

| Concern | Owner |
|---|---|
| Password strength, rotation, storage | WorkOS |
| Multi-factor authentication | WorkOS |
| Account lockout after failed logins | WorkOS |
| User identity federation (SAML, OIDC, Google, etc.) | WorkOS |
| TLS termination and certificate management | Ingress controller / load balancer |
| DDoS absorption (volumetric) | Firewall / CDN layer |
| Coarse-grained authorization decisions | Authorization Service (spec 016, Cedar/AWS Verified Permissions) |
| Audit trail aggregation & retention | Audit Infrastructure Service (spec 017) |

### 4.3 Known Limitations & Future Work

| Item | Status | Recommendation |
|---|---|---|
| Rate limit storage is per-node (in-memory) | Accepted | Upgrade to Redis via `RATELIMIT_STORAGE_URI` when shared Redis is available |
| `/api/me` is not rate-limited | Accepted | Primarily a dev/debug endpoint; downstream services validate JWTs locally via cached JWKS rather than calling this. Validation is pure local CPU with no side effects. |
| WorkOS session refresh logic opaque to this service | Accepted | WorkOS SDK internally refreshes; 15-minute inactivity timeout enforced by WorkOS config |

## 7. References

- [ADR-0007: Never roll your own authentication](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md)
- [ADR-0009: Structured JSON logging with schema validation](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0009-structured-json-logging-with-schema-validation.md)
- [Spec 014: Authentication Service](https://github.com/Neosofia/cdp/blob/main/specs/014-authentication-service/spec.md)
- [Constitution](https://github.com/Neosofia/cdp/blob/main/.specify/memory/constitution.md)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
