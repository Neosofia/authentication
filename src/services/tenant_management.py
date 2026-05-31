from __future__ import annotations

import uuid as _uuid

from sqlalchemy import select
from werkzeug.exceptions import NotFound

from src.models.tenant import Tenant


def get_tenant_or_404(db, tenant_id: str) -> dict:
    try:
        tenant_uuid = _uuid.UUID(str(tenant_id))
    except ValueError as exc:
        raise NotFound() from exc

    tenant = db.scalar(select(Tenant).where(Tenant.uuid == tenant_uuid))
    if tenant is None:
        raise NotFound()

    return {
        "uuid": str(tenant.uuid),
        "name": tenant.name,
        "idp_id": tenant.idp_id,
    }
