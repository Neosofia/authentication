# Authentication Service

Issues JWTs for human users via [WorkOS AuthKit](https://workos.com/docs/authkit) and for platform services via client credentials. Identity is always delegated to WorkOS — no passwords are stored or managed by this service.

## Resources

### Operations

For testers, developers, and system administrators, [OPERATIONS.md](OPERATIONS.md) is the place to start — it covers WorkOS configuration, local tooling setup, and helps you choose the right path for your environment. From there, follow [OPS-LOCAL.md](OPS-LOCAL.md) for single-box development and testing without HTTPS, or [OPS-CLOUD.md](OPS-CLOUD.md) for staging and production deployments on Proxmox with NetBird and OpenTofu.

### API Contract

For API consumers, integration testers, and frontend developers, [openapi.json](openapi.json) is the authoritative machine-readable contract for all endpoints exposed by this service. You can browse it interactively at [localhost:8091 ↗](http://localhost:8091) after running `docker compose -f docker-compose.dev.yml up -d swagger-ui`.

### Security Policy

For security reviewers, on-call engineers, and contributors, [SECURITY.md](SECURITY.md) documents the threat model, responsible disclosure process, and security controls in place for this service.

### Feature Specification

For product owners, architects, and new contributors, the [feature spec](../../specs/014-authentication-service/spec.md) describes the goals, scope, and acceptance criteria that drove the design of this service. It is the human-readable record of what was built and why.

### Governance & Architecture Decisions

For architects and senior engineers, the [project constitution](../../.specify/memory/constitution.md) captures the non-negotiable principles that apply across the whole platform. [ADR-0007](../../architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md) records the decision to delegate all authentication to WorkOS rather than implement it in-house, and [ADR-0008](../../architecture/structurizr/decisions/0008-published-json-schema-contracts-for-api-testing.md) establishes the published JSON Schema contract approach used for API testing across services.

### External References

For developers integrating with or extending WorkOS AuthKit, the [WorkOS AuthKit documentation](https://workos.com/docs/authkit/vanilla/python) covers the Python SDK and configuration options used by this service.
