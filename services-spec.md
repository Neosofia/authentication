# Feature Specification: Service Credential Lifecycle

**Status**: Draft
**Motivation**: Security audit §8 — lack of a documented rotation/revocation API increases
the chance operators fall back to ad-hoc DB writes, which bypass audit logging.

---

## Current State

- `POST /api/services` registers a service, generates a secret, and returns it once (bcrypt
  cost 12 in DB). ✓
- `ServiceCredential` has no `active` flag. The `issue_service_token` path queries
  `scalar_one_or_none()` — it assumes exactly one credential per service and has no way to
  invalidate a credential without a direct DB write.
- No rotate or revoke endpoints exist.

---

## Data Model Changes

### Add `active` and `rotated_at` to `ServiceCredential`

```python
active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
```

- `active = False` means the credential is revoked/rotated and will be rejected at token
  issuance time.
- `rotated_at` is set to `now()` on the *old* credential when it is superseded by a rotate
  operation. Null means the credential has never been rotated away from.

An Alembic migration is required. Both columns are additive and non-breaking.

### Fix `issue_service_token` query

The existing query does not filter on `active`. After migration it must:

```python
select(ServiceCredential)
    .join(Service, ...)
    .where(Service.slug == service_name, ServiceCredential.active == True)
    .order_by(ServiceCredential.changed_at.desc())
    .limit(1)
```

Using `.limit(1)` instead of `scalar_one_or_none()` future-proofs against the brief moment
during a rotation where two active rows could theoretically exist if a transaction is
not tight. In practice, rotate is a single atomic transaction, but the defensive query
costs nothing.

---

## New Endpoints

Both endpoints are admin-only (reuse the existing `require_admin` decorator).

### `POST /api/services/{slug}/rotate`

Generate a new secret, return it once, and deactivate all previous credentials atomically.

**Request**: no body required.

**Response `200`**:
```json
{
  "slug": "capabilities",
  "client_secret": "<new-secret>"   // returned EXACTLY ONCE
}
```

**Response `404`**: service slug not found.

**Behaviour**:
1. Look up `Service` by `slug`; 404 if not found.
2. Inside a single DB transaction:
   a. Set `active = False`, `rotated_at = now()` on all existing credentials for the service.
   b. Generate `secrets.token_urlsafe(32)`, bcrypt hash it, insert new `ServiceCredential`
      with `active = True`.
3. Emit `service_credential_rotated` audit event (slug, admin uuid).
4. Return the plaintext secret — this is the only time it is visible.

**Note**: the previous secret is invalidated *immediately*. Services must update their
`AUTH_CLIENT_SECRET` env var and restart before calling `rotate`. Coordinate with operators.

---

### `POST /api/services/{slug}/revoke`

Deactivate all credentials for a service, preventing any further token issuance.

**Request**: no body required.

**Response `200`**:
```json
{ "slug": "capabilities", "revoked": true }
```

**Response `404`**: service slug not found.
**Response `409`**: service already fully revoked (no active credentials).

**Behaviour**:
1. Look up `Service` by `slug`; 404 if not found.
2. Count currently active credentials; 409 if already zero.
3. Set `active = False` on all credentials for the service.
4. Emit `service_credential_revoked` audit event (slug, admin uuid).

**Note**: revoke does not delete the service record or its credential history. To restore
a revoked service, use `POST /api/services/{slug}/rotate` (which issues a fresh active
credential).

---

## Tests

### Unit tests (add to `tests/unit/routes/test_services.py`)

| Test | Expected |
|---|---|
| `POST /rotate` — happy path | 200, returns `client_secret`, old credential `active=False` |
| `POST /rotate` — unknown slug | 404 |
| `POST /rotate` — non-admin JWT | 403 |
| `POST /revoke` — happy path | 200, all credentials `active=False` |
| `POST /revoke` — unknown slug | 404 |
| `POST /revoke` — already revoked | 409 |
| `POST /revoke` — non-admin JWT | 403 |

### Integration test (add to `tests/integration/routes/test_services.py`)

1. Create a service, capture `client_secret`.
2. Issue a service token with the original secret → `200`.
3. Rotate the service; capture new `client_secret`.
4. Issue a service token with the **original** secret → `401` (credential deactivated).
5. Issue a service token with the **new** secret → `200`.
6. Revoke the service.
7. Issue a service token with the new secret → `401` (revoked).

---

## Implementation Order

1. Alembic migration: add `active` (non-null, default `true`) and `rotated_at` (nullable) to
   `service_credentials`.
2. Update `issue_service_token` query to filter `active = True`.
3. Add `POST /api/services/{slug}/rotate` route.
4. Add `POST /api/services/{slug}/revoke` route.
5. Register both routes in `openapi.json`.
6. Write unit + integration tests.
7. Update `SECURITY.md` §3.4 (service-to-service credentials) to note rotate/revoke endpoints.
