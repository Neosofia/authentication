from __future__ import annotations

import threading
from typing import Any

import httpx

from src.bootstrap.logging import log_event, log_exception
from src.config import settings
from src.db.engine import SessionLocal
from src.services.idp import PlatformIdentity
from src.services.service_management import get_service
from src.services.service_tokens import issue_service_token
from src.services.token_claims import cache_roles_mirror

AUTHENTICATION_SERVICE_SLUG = "authentication"
USER_SERVICE_SLUG = "user"


def _identity_payload(identity: PlatformIdentity) -> dict[str, Any]:
    if not identity.user_uuid:
        raise ValueError("identity user_uuid is required")
    if not identity.tenant_uuid:
        raise ValueError("identity tenant_uuid is required")
    return {
        "tenant_uuid": identity.tenant_uuid,
        "idp_id": identity.idp_user_id,
        "first_name": identity.profile.get("first_name"),
        "last_name": identity.profile.get("last_name"),
        "email": identity.profile.get("email"),
    }


def provision_user_registry_sync(identity: PlatformIdentity) -> bool:
    return _provision_user_registry_sync(identity)


def _provision_user_registry_sync(identity: PlatformIdentity) -> bool:
    try:
        payload = _identity_payload(identity)
        if not settings.authentication_client_secret:
            log_event(
                "user_provisioning_misconfigured",
                reason="missing_authentication_client_secret",
                user_uuid=identity.user_uuid,
            )
            return False

        with SessionLocal() as db:
            user_service = get_service(db, USER_SERVICE_SLUG)
            service_token = issue_service_token(
                AUTHENTICATION_SERVICE_SLUG,
                settings.authentication_client_secret,
                db,
                audience=USER_SERVICE_SLUG,
            )

        url = f"{user_service['base_url'].rstrip('/')}/api/v1/users/{identity.user_uuid}"
        response = httpx.put(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {service_token}"},
            timeout=settings.user_provisioning_http_timeout_secs,
        )
        if response.status_code in (200, 201):
            log_event(
                "user_provisioning_succeeded",
                user_uuid=identity.user_uuid,
                status_code=response.status_code,
            )
            try:
                body = response.json()
                if isinstance(body, dict):
                    with SessionLocal() as db:
                        cache_roles_mirror(
                            db,
                            user_uuid=str(identity.user_uuid),
                            tenant_uuid=str(identity.tenant_uuid),
                            registry_payload=body,
                        )
            except Exception as exc:
                log_exception(
                    "user_roles_cache_error",
                    exc,
                    user_uuid=identity.user_uuid,
                )
            return True
        log_event(
            "user_provisioning_failed",
            user_uuid=identity.user_uuid,
            status_code=response.status_code,
        )
        return False
    except Exception as exc:
        log_exception(
            "user_provisioning_error",
            exc,
            user_uuid=identity.user_uuid,
        )
        return False


def provision_user_registry(identity: PlatformIdentity) -> threading.Thread | None:
    if not settings.user_provisioning_enabled:
        return None
    thread = threading.Thread(
        target=_provision_user_registry_sync,
        args=(identity,),
        daemon=True,
    )
    thread.start()
    return thread
