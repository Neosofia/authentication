// Tenant read — operators any tenant; others only their session tenant.
//   tenant:read   GET /api/v1/tenants/{tenant_uuid}
permit (
    principal is authentication::User,
    action == Action::"tenant:read",
    resource is authentication::Tenant
) when {
    principal.isOperator || principal.tenantId == resource.tenantId
};

// Service registry — operators only (route map in src/authorization/entities.py).
//   service:list          GET  /api/services
//   service:create        POST /api/services
//   service:read          GET  /api/services/{slug}
//   service:update        PUT  /api/services/{slug}
//   service:rotate        POST /api/services/{slug}/rotate
//   service:audit:list    GET  /api/services/audits, GET /api/services/{slug}/audits
permit (
    principal is authentication::User,
    action in [
        Action::"service:list",
        Action::"service:create",
        Action::"service:read",
        Action::"service:update",
        Action::"service:rotate",
        Action::"service:audit:list",
    ],
    resource
) when {
    principal.isOperator && (
        resource is authentication::ServiceCatalog ||
        resource is authentication::Service
    )
};

// IdP failed sign-in observability — operators only.
//   idp:failed_auth:read   GET /api/idp/failed-authentications
permit (
    principal is authentication::User,
    action == Action::"idp:failed_auth:read",
    resource is authentication::IdpObservability
) when {
    principal.isOperator
};
