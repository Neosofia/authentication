import uuid
import threading
from typing import Optional

from sqlalchemy import select

from src.bootstrap.logging import log_event, log_exception
from src.db.engine import SessionLocal
from src.models.tenant import Tenant
from src.models.user import User
from src.services.token_claims import resolve_tenant_type

SYSTEM_ACTOR_UUID = uuid.UUID("00000000-0000-7000-8000-000000000000")
SYSTEM_ACTOR_TYPE = 2


def sync_identity_data(
    user_uuid: Optional[str],
    tenant_uuid: Optional[str],
    idp_user_id: str,
    idp_tenant_id: Optional[str],
    tenant_name: Optional[str],
    tenant_type: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """
    Best-effort sync of IdP tenant/user identifiers into local tables.

    Users rows hold only uuid, idp_id, and a T2 roles mirror; profile fields live in User service.
    """
    user_uuid_out = user_uuid
    tenant_uuid_out = tenant_uuid

    def _do_sync():
        nonlocal user_uuid_out, tenant_uuid_out
        db = None
        try:
            with SessionLocal() as db:
                if idp_tenant_id:
                    tenant = db.scalar(select(Tenant).filter_by(idp_id=idp_tenant_id))
                    if not tenant:
                        tenant = Tenant(
                            idp_id=idp_tenant_id,
                            name=tenant_name or "Unknown Tenant",
                            uuid=uuid.UUID(tenant_uuid) if tenant_uuid else None,
                            type=resolve_tenant_type(tenant_type),
                            changed_by_uuid=SYSTEM_ACTOR_UUID,
                            changed_by_type=SYSTEM_ACTOR_TYPE,
                        )
                        db.add(tenant)
                    else:
                        if tenant_name:
                            tenant.name = tenant_name
                        resolved_type = resolve_tenant_type(tenant_type)
                        if resolved_type:
                            tenant.type = resolved_type
                    db.commit()
                    tenant_uuid_out = str(tenant.uuid)

                if idp_user_id:
                    user = db.scalar(select(User).filter_by(idp_id=idp_user_id))
                    if not user:
                        user = User(
                            idp_id=idp_user_id,
                            uuid=uuid.UUID(user_uuid) if user_uuid else None,
                            changed_by_uuid=SYSTEM_ACTOR_UUID,
                            changed_by_type=SYSTEM_ACTOR_TYPE,
                        )
                        db.add(user)
                    db.commit()
                    user_uuid_out = str(user.uuid)
        except Exception as exc:
            if db is not None:
                try:
                    db.rollback()
                except Exception as rollback_exc:
                    log_exception(
                        "identity_sync_rollback_failed",
                        rollback_exc,
                        idp_user_id=idp_user_id,
                        idp_tenant_id=idp_tenant_id,
                    )
            log_exception(
                "identity_sync_error",
                exc,
                idp_user_id=idp_user_id,
                idp_tenant_id=idp_tenant_id,
            )

    thread = threading.Thread(target=_do_sync)
    thread.start()
    thread.join(timeout=2.0)

    if thread.is_alive():
        log_event(
            "identity_sync_timeout",
            idp_user_id=idp_user_id,
            idp_tenant_id=idp_tenant_id,
        )

    return user_uuid_out, tenant_uuid_out
