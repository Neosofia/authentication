# Authentication Service

This service is the platform's single source of truth for identity. It delegates the question "is this human who they say they are?" to an external provider — currently [WorkOS AuthKit](https://workos.com/docs/authkit) — then answers the separate platform question: "given that, what identity and permissions does this principal have?" The answer is a short-lived platform JWT with normalized `neosofia:` claims (`token_type`, `token_version`, `roles`, `tenant_id`) that every downstream service validates offline. We mint our own tokens so that the platform's trust model, claim vocabulary, tenant scoping, and token lifetime are all enforced here — independently of whatever the IdP does. No downstream service ever sees the external provider's token; the provider is a hidden implementation detail that can be swapped without touching any consumer. Additional authentication providers will be added as customer demand requires — the most likely near-term candidates are Google Workspace and Microsoft Entra ID (Azure AD) via OIDC federation.

## Resources

### Operations

For testers, developers, and system administrators, [OPERATIONS.md](OPERATIONS.md) is the place to start — it covers WorkOS configuration, local tooling setup, and helps you choose the right path for your environment. From there, follow [OPS-LOCAL.md](OPS-LOCAL.md) for single-box development and testing.

### API Contract

For API consumers, integration testers, and frontend developers, [openapi.json](openapi.json) is the authoritative machine-readable contract for all endpoints exposed by this service.

### Security Policy

For security reviewers, on-call engineers, and contributors, [SECURITY.md](SECURITY.md) documents the threat model, responsible disclosure process, and security controls in place for this service.

### Feature Specification

For product owners, architects, and new contributors, the [feature spec](https://github.com/Neosofia/cdp/blob/main/specs/014-authentication-service/spec.md) describes the goals, scope, and acceptance criteria that drove the design of this service. It is the human-readable record of what was built and why.

### Governance & Architecture Decisions

For architects and senior engineers, the [project constitution](https://github.com/Neosofia/cdp/blob/main/.specify/memory/constitution.md) captures the non-negotiable principles that apply across the whole platform. [ADR-0007](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0007-never-roll-your-own-authentication.md) records the decision to delegate all authentication to WorkOS rather than implement it in-house, and [ADR-0008](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0008-published-json-schema-contracts-for-api-testing.md) establishes the published JSON Schema contract approach used for API testing across services.

### External References

For developers integrating with or extending WorkOS AuthKit, the [WorkOS AuthKit documentation](https://workos.com/docs/authkit/vanilla/python) covers the Python SDK and configuration options used by this service.
