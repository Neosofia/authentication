# Product Installation Plan

Per-version instructions for system administrators: prerequisites, deploy and configuration steps, post-deploy verification, and evidence to capture. For what changed in each release, see [CHANGELOG.md](CHANGELOG.md) when present, or the GitHub release for that tag.

## [Unreleased] — `VALID_ACTORS` rename and `study` actor

**Build identifiers:** Authentication image after `VALID_ACTORS` / `study` rollout; SDK `authentication-in-the-middle/v0.9.5` then `v0.9.6`; redeploy all JWT consumers.

**Prerequisites:**

- Coordinate with User, Capabilities, Chat, Care Episode, and other services on **authentication-in-the-middle** wheel bumps (`uv sync`, rebuild images).
- Plan WorkOS Authorization changes before token issuance changes.

**Pre-deploy:**

- Rename env var **`VALID_ROLES`** → **`VALID_ACTORS`** everywhere (no default in application code; service refuses to start if unset or empty).

  ```text
  VALID_ACTORS=operator,study,clinician,patient
  ```

  Surfaces: Authentication, User, JWT consumers on middleware v0.9.5+; local CDP `cdp/.authentication.env`, `cdp/.user.env`, `cdp/.capabilities.env` (and `.authentication.env.sample`); cloud secret bundles (AWS Secrets Manager, Railway, PaaS).

- In WorkOS **Authorization** (environment/instance roles), add Tier-1 slug **`study`** alongside `operator`, `clinician`, `patient`. Assign `study` to users who administer CRO, sponsor, or SMO tenants.

- **v0.9.5 consumers:** each service sets Flask config **`TIER1_ACTOR_CLASSES`** at startup from Pydantic `valid_actors` / env `VALID_ACTORS` (middleware does not read env directly).

- **v0.9.6 consumers:** remove per-service **`valid_actors`** / **`VALID_ACTORS`**; keep **`JWT_JWKS_URI`** only and call **`configure_tier1_actor_classes(app)`** at startup. Tier-1 list loads from Authentication **`GET /.well-known/platform-actors.json`** (same origin as JWKS).

**Deploy:**

1. Publish/use SDK tag `authentication-in-the-middle/v0.9.5` (or `v0.9.6` when adopting well-known actors).
2. Bump wheel URLs in each service `pyproject.toml`, `uv sync`, rebuild images.
3. Redeploy Authentication, User, Capabilities, and other JWT consumers after secrets rename.

**Post-deploy verification:**

1. Authentication starts with `VALID_ACTORS=operator,study,clinician,patient`.
2. Study users re-login; JWT `neosofia:actors` includes `study` where assigned.
3. With v0.9.6: `GET /.well-known/platform-actors.json` returns the same list as `VALID_ACTORS`.
4. Service registry and downstream APIs accept tokens from updated consumers.

**Evidence:**

- Secret-manager change ticket showing `VALID_ACTORS` (not `VALID_ROLES`).
- Screenshot or CLI output of WorkOS `study` role assignments (sample admin user).
- Sample JWT decode showing `neosofia:actors` for operator and study test users.

---

## authentication v0.34.0

**Build identifiers:** Tag `authentication/v0.34.0`; image `ghcr.io/neosofia/authentication:v0.34.0`.

**Mandatory (same change window):**

- Deploy **care-episode v0.4.0** (or newer) after this release so CE can resolve Chat via `GET /api/services/chat` with a care-episode service token.

**Deploy:**

1. Tag and push `authentication/v0.34.0`; wait for CI image publish.
2. Redeploy the authentication service (policy bundle only — no migrations or env vars).

**Post-deploy verification:**

1. `GET /health` returns version `0.34.0`.
2. Operator JWT: `GET /api/services` → **200** (full catalog management unchanged).
3. Care-episode service token (`aud=authentication`): `GET /api/services/chat` → **200** with private-mesh `base_url`.
4. Same service token: `POST /api/services` → **403** (read-only peer discovery).

**Evidence:**

- Health response showing `0.34.0`.
- Registry read succeeds with care-episode client credentials; create/rotate still operator-only.

---

## authentication v0.33.0

**Build identifiers:** Tag `authentication/v0.33.0`; SDK **`authorization-in-the-middle/v0.4.23`**, **`logenvelope/v0.3.4`**.

**Prerequisites:**

- Publish/use SDK tag `authorization-in-the-middle/v0.4.23` (hyphenated catalog inference fix).

**Deploy:**

1. Tag and push `authentication/v0.33.0`; wait for CI image publish if applicable.
2. Redeploy the authentication service (no new migrations or env vars).

**Post-deploy verification:**

1. `GET /health` returns version `0.33.0`.
2. Service registry and catalog audit routes still return **200** for operator JWTs.

**Evidence:**

- Health response showing `0.33.0`.

---

## authentication v0.32.3

**Build identifiers:** Tag `authentication/v0.32.3`; SDK **`authorization-in-the-middle/v0.4.22`**, **`logenvelope/v0.3.4`**.

**Prerequisites:**

- Rebuild the authentication image so Dockerfile/`uv.lock` resolve the published SDK wheels (no local path overrides).

**Deploy:**

1. Tag and push `authentication/v0.32.3`; wait for CI image publish if applicable.
2. Redeploy the authentication service (no new migrations or env vars for this release).

**Post-deploy verification:**

1. `GET /health` returns version `0.32.3`.
2. Operator session: service registry list/create and catalog audit list succeed (Cedar `authorization.allowed` in logs).
3. Login still issues `platform_token_issued`; user registry upsert logs `user_provisioning_succeeded` with status `200` or `201`.

**Evidence:**

- Health response showing `0.32.3`.
- Sample `authorization.allowed` log for `GET /api/services` and `GET /api/services/audits`.

---

## authentication v0.31.2

**Build identifiers:** Tag `authentication/v0.31.2`; **sql-template v0.6.0**; **user v0.4.0**.

**Prerequisites:**

- Deploy with matching User service and sql-template audit v2 artifacts pinned in the consumer image.

**Pre-deploy:**

- Greenfield only (no production clones yet): plan Postgres volume reset or fresh database before migrate.
- Set `USER_SERVICE_BASE_URL` on Railway migrate job to private mesh URL (e.g. `http://user.railway.internal:8080`); default in migration `005` is `http://user:8018` for Compose.
- Ensure `AUTHENTICATION_CLIENT_SECRET` is set in Railway before migrate runs (migration `002` hashes it; plaintext is never logged).

**Deploy:**

1. Nuke auth Postgres volume if greenfield audit v2 apply is required; run `python -m alembic upgrade head` or the migrate container so migration `000` applies audit v2 SQL.
2. Deploy authentication and user images for this release line.

**Post-deploy verification:**

1. `GET /health` succeeds.
2. Application reads live rows from main tables; audit timelines available from `*_history` views.
3. User service registry `base_url` resolves (Compose or Railway internal URL).

**Evidence:**

- Migrate job log (success, no secret values).
- Health check pass record.
- Optional: query confirming `*_history` views exist.

---

## authentication v0.31.1

**Build identifiers:** Tag `authentication/v0.31.1`; **user v0.4.0**.

**Prerequisites:**

- User service v0.4.0 deployed or deploying in the same window.

**Pre-deploy:**

- None beyond standard release pins.

**Deploy:**

1. Deploy authentication v0.31.1 alongside user v0.4.0.

**Post-deploy verification:**

1. Login provisions User registry row (best-effort); first Tier-1 `operator` receives **`platform.admin`** on the user row.
2. Human tokens include `neosofia:actors`, `neosofia:tenant_type` when `tenants.type` is set, and `neosofia:roles` (short Tier-2 names) from the local `users.roles` mirror.
3. Token mint does not call the User service on the critical path.

**Evidence:**

- Sample human JWT with expected `neosofia:*` claims after login.
- User row exists for a test login (UUID matches `sub`).

---

## authentication v0.31.0

**Build identifiers:** Tag `authentication/v0.31.0`.

**Prerequisites:**

- User service registered for `audience=user` client-credentials flow.

**Pre-deploy:**

- Configure `USER_PROVISIONING_ENABLED`, `USER_PROVISIONING_HTTP_TIMEOUT_SECS`, and `AUTHENTICATION_CLIENT_SECRET` for the target environment.

**Deploy:**

1. Apply migration `004` (registers `user` in service registry).
2. Deploy authentication v0.31.0.

**Post-deploy verification:**

1. OAuth callback best-effort provisions User registry rows using registered User `base_url` and `aud=user` service token.
2. Service registry lists `user` with correct `base_url`.

**Evidence:**

- Registry API listing includes `user`.
- Provisioned test user visible in User API after login.

---

## authentication v0.30.0

**Build identifiers:** Tag `authentication/v0.30.0`; requires **user v0.2.0** and CDP UI **v0.2.0** for Admin → Users.

**Prerequisites:**

- User v0.2.0 and CDP UI v0.2.0 installation steps complete or scheduled in the same change window.

**Pre-deploy:**

- Add `user` to `JWT_WEB_AUDIENCE` (e.g. `authentication,capabilities,python-template,user`).

**Deploy:**

1. Redeploy authentication v0.30.0 after env update.

**Post-deploy verification:**

1. Log in as **`operator`**.
2. Token `aud` includes **`user`** (re-login after env change).
3. CDP **Admin → Users** is not **401**.

**Evidence:**

- JWT decode showing `aud` contains `user`.
- Screenshot or HAR of successful Admin → Users load (no 401).

---

## authentication v0.29.0 — Tier-1 `operator` actor

**Build identifiers:** Tag `authentication/v0.29.0`. Reference: [authentication#11](https://github.com/Neosofia/authentication/issues/11).

**Prerequisites:**

- CDP Capabilities Cedar policies and CDP UI gates expect JWT role **`operator`** for platform operator/debug menus (`ui:menu:operator`, `ui:menu:debug`).

**Pre-deploy:**

- WorkOS: create environment-level role slug **`operator`** (not per-org only). Add **`clinician`** and **`patient`** if missing. Assign **`operator`** to registry admins in each organization (replace `admin` when ready).
- Set `VALID_ACTORS=operator,study,clinician,patient` (legacy **`admin`** must not appear in `VALID_ACTORS`; not accepted at `/api/services/*`).
- Update local `authentication/.env`, `cdp/.authentication.env`, and cloud secret bundles.

**Deploy:**

1. Deploy authentication v0.29.0.

**Post-deploy verification:**

1. `GET /health` succeeds.
2. User with WorkOS **`operator`** logs in; `POST /api/token` → JWT `neosofia:roles` includes `operator`.
3. `GET /api/services` with that JWT → **200** (not 403).
4. Use **`X-Active-Role: operator`** when calling Capabilities or downstream services.

**Evidence:**

- WorkOS role assignment screenshot for `operator`.
- JWT and registry smoke-test results (200 on `/api/services`).
- Note dashboard updates if log queries filtered on `admin=` (now `operator=` for `service_created`, `service_updated`, `service_credential_rotated`).
