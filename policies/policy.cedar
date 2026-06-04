// Operators may read any tenant; others only their session tenant.
permit (
    principal is authentication::User,
    action == Action::"tenant:read",
    resource is authentication::Tenant
) when {
    principal.isOperator || principal.tenantId == resource.tenantId
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

// Operator observability for identity-provider failed sign-in events.
permit (
    principal is authentication::User,
    action == Action::"idp:failed_auth:read",
    resource is authentication::IdpObservability
) when {
    principal.isOperator
};
