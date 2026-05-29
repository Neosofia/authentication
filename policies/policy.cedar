// Operators may read any tenant; others only their session tenant.
permit (
    principal is authentication::User,
    action == Action::"tenant:read",
    resource is authentication::Tenant
) when {
    principal.isOperator || principal.tenantId == resource.tenantId
};

// Profile is always the authenticated principal's own record.
permit (
    principal is authentication::User,
    action == Action::"profile:read",
    resource is authentication::Profile
) when {
    resource.ownerUuid == principal.uuid
};

// Service registry operations require Tier-1 operator.
permit (
    principal is authentication::User,
    action in [
        Action::"service:list",
        Action::"service:create",
        Action::"service:read",
        Action::"service:update",
        Action::"service:rotate",
        Action::"service:audit:read"
    ],
    resource
) when {
    principal.isOperator && (
        resource is authentication::ServiceCatalog ||
        resource is authentication::Service
    )
};
