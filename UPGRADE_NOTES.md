# Upgrade notes

## authentication v0.31.2

### Manual actions

- Deploy with **sql-template v0.6.0** (audit v2: archive-on-delete, no RLS, `_history` views wired in `setup_tracking`) and **user v0.4.0**.
- Greenfield only (no production clones yet): nuke the auth Postgres volume and re-run `python -m alembic upgrade head` or the migrate container so migration `000` applies audit v2 SQL. Application code already reads live rows from main tables and audit timelines from `*_history` views.
- Migration `005` sets the User service registry `base_url` to `USER_SERVICE_BASE_URL` when set, otherwise `http://user:8018` (Docker Compose service name). On Railway, set `USER_SERVICE_BASE_URL` to the private mesh URL (for example `http://user.railway.internal:8080`) in the migrate job env.
- `AUTHENTICATION_CLIENT_SECRET` must already be set in Railway before migrate runs (migration `002` hashes it; plaintext is never logged). After a volume nuke, the same env value re-seeds credentials — no need to rotate unless you intentionally change the secret.

## authentication v0.31.1

- Login provisioning sends `tier1_roles` to the User service (best-effort, off critical path); the first Tier-1 `operator` receives **`platform.admin`**. Human tokens include **`neosofia:tenant_type`** only when **`tenants.type`** is set explicitly (no default), and **`neosofia:org_roles`** from the local `users.org_roles` mirror. **Token mint never calls the User service.** Deploy alongside **user v0.5.0**. Run Alembic through **007** (`tenants.type` nullable + `users.org_roles` cache).

## authentication v0.31.0

- Added migration `004` to register the `user` service in the service registry for `audience=user` client-credentials tokens.
- OAuth callback now best-effort provisions User registry rows after identity sync using the registered User service `base_url` and an `aud=user` Authentication service token.
- New rollout controls: `USER_PROVISIONING_ENABLED`, `USER_PROVISIONING_HTTP_TIMEOUT_SECS`, and `AUTHENTICATION_CLIENT_SECRET`.

## authentication v0.30.0

Requires **user v0.2.0** and CDP UI **v0.2.0** for Admin -> Users.

### Update

- `JWT_WEB_AUDIENCE` -- add `user` (for example `authentication,capabilities,python-template,user`).
- Redeploy authentication **v0.30.0**.

### Test

1. Log in as **`operator`**.
2. Token `aud` includes **`user`** (re-login after env change).
3. CDP **Admin -> Users** is not **401**.

### Tag

`authentication/v0.30.0`

---

## authentication v0.29.0 -- Tier-1 `operator` actor

**Issue:** [authentication#11](https://github.com/Neosofia/authentication/issues/11)

### Summary

The canonical Tier-1 IdP actor class for platform administration is **`operator`** (replaces the overloaded `admin` slug). **`clinician`** and **`patient`** are the other Tier-1 actor classes.

- **`/api/services/*`** requires JWT role **`operator`** (`requires operator role` on 403).
- **`VALID_ROLES`** must list only Tier-1 slugs you issue tokens for: `operator,clinician,patient`.
- Legacy **`admin`** is **not** accepted at the service-management gate and **must not** appear in `VALID_ROLES`. Users may still have an `admin` assignment in WorkOS for housekeeping; those users will not receive `admin` in platform JWTs and cannot manage the service registry until assigned **`operator`**.

### WorkOS setup

Create the **`operator`** role at the **environment (instance) level**, not per organization:

1. WorkOS Dashboard -> **Authorization** (environment/instance roles).
2. Add role slug **`operator`** (plus **`clinician`** and **`patient`** if not already present).
3. Under each **organization**, assign **`operator`** to users who manage the service registry (replace `admin` assignments when ready).
4. You may delete or leave unused **`admin`** org-role definitions in WorkOS; they have no effect on the platform once removed from `VALID_ROLES`.

Org-level role configuration for memberships remains under **Organizations -> [org] -> Members**.

### Environment variables

| Variable | Value |
|----------|--------|
| `VALID_ROLES` | `operator,clinician,patient` |

Update in:

- Local: `authentication/.env` and CDP stack `cdp/.authentication.env`
- Cloud: AWS Secrets Manager / Railway / PaaS secret bundle for the authentication service

No other env vars change for this release.

### Deploy and verify

1. Deploy authentication **v0.29.0**.
2. Confirm `GET /health` succeeds.
3. Log in as a user with WorkOS role **`operator`**.
4. `POST /api/token` -> JWT `neosofia:roles` includes `operator`.
5. `GET /api/services` with that JWT -> **200** (not 403).

### Public cloud checklist

1. Update secret: `VALID_ROLES=operator,clinician,patient`
2. Redeploy authentication
3. Re-assign **`operator`** in WorkOS for registry admins
4. Smoke-test service registry CRUD

### Log field rename

Service lifecycle audit events use `operator=` instead of `admin=` (`service_created`, `service_updated`, `service_credential_rotated`). Update dashboards if they filter on `admin`.

### Downstream

CDP Capabilities Cedar policies and the CDP UI dashboard gate on JWT role **`operator`** for platform operator/debug menus (`ui:menu:operator`, `ui:menu:debug`). Use **`X-Active-Role: operator`** when calling Capabilities or downstream services.
