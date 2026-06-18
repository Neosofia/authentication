# Changelog

What changed for authentication consumers. Deploy: [INSTALLATION_PLAN.md](INSTALLATION_PLAN.md).

## [0.38.2] - 2026-06-18

### Fixed

- Service errors and API failures are recorded in operational logs at default verbosity.

## [0.38.1] - 2026-06-16

### Fixed

- Trivy lockfile scan: pin **`pyjwt>=2.13.0`** and **`cryptography>=48.0.1`** (dev group and runtime `pyjwt` dependency).

## [0.38.0] - 2026-06-16

### Changed

- Human access token default lifetime increased from **15 minutes** to **30 minutes** (`ACCESS_TOKEN_TTL_SECS`, default **1800**). Staging and production should set the env var explicitly when overriding defaults.

## [0.37.0] - 2026-06-14

### Changed

- Pinned **`authorization-in-the-middle/v0.7.1`** — shared `resolve_jwt_principal`, SDK REST entity inference for service registry routes, OpenAPI write planners for Cedar merge on PATCH.
- Service registry Cedar attrs use `registry_{model}_cedar_attrs` hooks; removed duplicate principal and catalog builders.

## [0.36.0] - 2026-06-13

### Added

- **`demo`** tier-1 actor in provisioning docs and samples; operators must include it in **`VALID_ACTORS`** for demo bootstrap.
- **`tenant_types`** helper module for org-kind validation shared with JWT mint.

### Changed

- Token claims and user provisioning align with demo actor and tenant-type vocabulary.

## [0.35.0] - 2026-06-13

### Added

- **`VALID_TENANT_TYPES`** — required comma-separated org-kind allow-list for `neosofia:tenant_type` at JWT mint (interim; vocabulary will move to a dedicated service later).

### Changed

- Tenant-type validation uses `VALID_TENANT_TYPES` instead of a hard-coded allow-list.

## [0.34.0] - 2026-06-11

### Added

- Cedar policy and principal resolution for **service-token peer discovery** on the service registry (`GET /api/services`, `GET /api/services/{slug}`). Required for care-episode v0.4.0 to resolve Chat `base_url` over the private mesh.

### Changed

- Service JWTs now evaluate as `authentication::Service` principals (not `User`) so registry read policies apply correctly.

## [0.33.0] - 2026-06-10

### Changed

- Pinned **`authorization-in-the-middle/v0.4.23`** (hyphenated catalog type inference fix).
