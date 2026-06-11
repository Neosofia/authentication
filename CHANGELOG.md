# Changelog

What changed for authentication consumers. Deploy: [INSTALLATION_PLAN.md](INSTALLATION_PLAN.md).

## [0.34.0] - 2026-06-11

### Added

- Cedar policy and principal resolution for **service-token peer discovery** on the service registry (`GET /api/services`, `GET /api/services/{slug}`). Required for care-episode v0.4.0 to resolve Chat `base_url` over the private mesh.

### Changed

- Service JWTs now evaluate as `authentication::Service` principals (not `User`) so registry read policies apply correctly.

## [0.33.0] - 2026-06-10

### Changed

- Pinned **`authorization-in-the-middle/v0.4.23`** (hyphenated catalog type inference fix).
