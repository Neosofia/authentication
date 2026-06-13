# Changelog

What changed for authentication consumers. Deploy: [INSTALLATION_PLAN.md](INSTALLATION_PLAN.md).

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
