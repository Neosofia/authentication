import uuid
import threading
from typing import Optional
from sqlalchemy import select
from src.db.engine import SessionLocal
from src.models.user import User
from src.models.tenant import Tenant
from src.bootstrap.logging import log_event

SYSTEM_ACTOR_UUID = uuid.UUID("00000000-0000-7000-8000-000000000000")
SYSTEM_ACTOR_TYPE = 2

# Use a timeout context for the session
def sync_identity_data(
    user_uuid: Optional[str],
    tenant_uuid: Optional[str],
    idp_user_id: str,
    first_name: Optional[str],
    last_name: Optional[str],
    email: Optional[str],
    idp_tenant_id: Optional[str],
    tenant_name: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """
    Best effort sync of IdP data into the local users and tenants tables.
    Returns the internal user_uuid and tenant_uuid mapped to the given IdP identifiers.
    Enforces a 2s timeout. If timeout or DB fail, returns None, None for the missing ones, 
    but if the record existed before, ideally we'd want it, but if DB is down we return None.
    Actually, we should do the DB operations in a thread or with a strict timeout.
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
                            changed_by_uuid=SYSTEM_ACTOR_UUID,
                            changed_by_type=SYSTEM_ACTOR_TYPE,
                        )
                        db.add(tenant)
                    else:
                        if tenant_name:
                            tenant.name = tenant_name
                    db.commit()
                    tenant_uuid_out = str(tenant.uuid)

                if idp_user_id:
                    user = db.scalar(select(User).filter_by(idp_id=idp_user_id))
                    if not user:
                        user = User(
                            idp_id=idp_user_id,
                            first_name=first_name,
                            last_name=last_name,
                            email=email,
                            uuid=uuid.UUID(user_uuid) if user_uuid else None,
                            changed_by_uuid=SYSTEM_ACTOR_UUID,
                            changed_by_type=SYSTEM_ACTOR_TYPE,
                        )
                        db.add(user)
                    else:
                        if first_name: user.first_name = first_name
                        if last_name: user.last_name = last_name
                        if email: user.email = email
                    db.commit()
                    user_uuid_out = str(user.uuid)
        except Exception as exc:
            if db is not None:
                try:
                    db.rollback()
                except Exception as rollback_exc:
                    log_event(
                        "identity_sync_rollback_failed",
                        idp_user_id=idp_user_id,
                        idp_tenant_id=idp_tenant_id,
                        error_class=type(rollback_exc).__name__,
                        error=str(rollback_exc),
                    )
            log_event(
                "identity_sync_error",
                idp_user_id=idp_user_id,
                idp_tenant_id=idp_tenant_id,
                error_class=type(exc).__name__,
                error=str(exc),
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
        # We don't join blocking, thread will finish or fail in background
    return user_uuid_out, tenant_uuid_out
