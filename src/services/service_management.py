import secrets
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

import bcrypt
from sqlalchemy import literal, select, func, union_all
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import IntegrityError

from src.models.service import Service, ServiceHistory
from src.models.service_credential import ServiceCredential, ServiceCredentialHistory


class NotFoundError(Exception):
    pass


class CredentialNotFoundError(NotFoundError):
    pass


class InvalidAuditSourceError(Exception):
    pass


class ConflictError(Exception):
    pass


def _days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days


def list_services(db, page: int, page_size: int, search: str) -> tuple[list[dict], int]:
    query = (
        select(Service, ServiceCredential)
        .outerjoin(
            ServiceCredential,
            ServiceCredential.service_uuid == Service.uuid,
        )
        .order_by(Service.name.asc())
    )

    if search:
        pattern = f"%{search}%"
        query = query.where(
            Service.name.ilike(pattern)
            | Service.slug.ilike(pattern)
            | Service.base_url.ilike(pattern)
        )

    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.execute(query.offset((page - 1) * page_size).limit(page_size)).all()

    items = []
    for svc, cred in rows:
        items.append({
            "uuid": str(svc.uuid),
            "name": svc.name,
            "slug": svc.slug,
            "base_url": svc.base_url,
            "credential_uuid": str(cred.uuid) if cred else None,
            "credential_changed_at": cred.changed_at.isoformat() if cred and cred.changed_at else None,
            "days_since_rotation": _days_since(cred.changed_at) if cred else None,
        })

    return items, total


def create_service(db, user_uuid: str, name: str, slug: str, base_url: str) -> dict:
    changed_by_uuid = _uuid.UUID(str(user_uuid))
    plain_secret = secrets.token_urlsafe(32)
    hashed_secret = bcrypt.hashpw(plain_secret.encode(), bcrypt.gensalt()).decode()

    new_service = Service(
        name=name,
        slug=slug,
        base_url=base_url,
        changed_by_uuid=changed_by_uuid,
        changed_by_type=1,
    )

    try:
        db.add(new_service)
        db.flush()

        new_credential = ServiceCredential(
            service_uuid=new_service.uuid,
            hashed_secret=hashed_secret,
            changed_by_uuid=changed_by_uuid,
            changed_by_type=1,
        )
        db.add(new_credential)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError("service name or slug or base_url already exists")

    return {
        "uuid": str(new_service.uuid),
        "name": new_service.name,
        "slug": new_service.slug,
        "base_url": new_service.base_url,
        "client_secret": plain_secret,
    }


def get_service(db, slug: str) -> dict:
    svc = db.scalar(select(Service).where(Service.slug == slug))
    if svc is None:
        raise NotFoundError("service not found")

    cred = db.scalar(select(ServiceCredential).where(ServiceCredential.service_uuid == svc.uuid))

    return {
        "uuid": str(svc.uuid),
        "name": svc.name,
        "slug": svc.slug,
        "base_url": svc.base_url,
        "credential_uuid": str(cred.uuid) if cred else None,
        "credential_changed_at": cred.changed_at.isoformat() if cred and cred.changed_at else None,
        "days_since_rotation": _days_since(cred.changed_at) if cred else None,
    }


def update_service(db, slug: str, user_uuid: str, updates: dict[str, str]) -> dict:
    svc = db.scalar(select(Service).where(Service.slug == slug))
    if svc is None:
        raise NotFoundError("service not found")

    svc.changed_by_uuid = _uuid.UUID(str(user_uuid))
    svc.changed_by_type = 1
    for field, value in updates.items():
        setattr(svc, field, value)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError("name, slug, or base_url already in use")

    return {
        "uuid": str(svc.uuid),
        "name": svc.name,
        "slug": svc.slug,
        "base_url": svc.base_url,
    }


def rotate_service(db, slug: str, user_uuid: str) -> dict:
    svc = db.scalar(select(Service).where(Service.slug == slug))
    if svc is None:
        raise NotFoundError("service not found")

    cred = db.scalar(select(ServiceCredential).where(ServiceCredential.service_uuid == svc.uuid))
    if cred is None:
        raise CredentialNotFoundError("service credential not found")

    cred.changed_by_uuid = _uuid.UUID(str(user_uuid))
    cred.changed_by_type = 1
    plain_secret = secrets.token_urlsafe(32)
    cred.hashed_secret = bcrypt.hashpw(plain_secret.encode(), bcrypt.gensalt()).decode()
    db.commit()

    return {
        "slug": svc.slug,
        "client_secret": plain_secret,
    }


def _map_audit_row(row: Any, *, source: str) -> dict:
    return {
        "history_uuid": str(row["history_uuid"]) if row["history_uuid"] else None,
        "source": source,
        "credential_uuid": str(row["credential_uuid"]) if source == "credential" and row.get("credential_uuid") else None,
        "name": row.get("name"),
        "slug": row.get("slug"),
        "base_url": row.get("base_url"),
        "changed_at": row["changed_at"].isoformat() if row["changed_at"] else None,
        "changed_by_uuid": str(row["changed_by_uuid"]),
        "changed_by_type": row["changed_by_type"],
        "changed_by_name": None,
        "change_type": row["change_type"],
    }


def get_service_audits(
    db,
    service_uuid: str,
    source: str | None,
    page: int,
    page_size: int,
) -> tuple[list[dict], int]:
    if source == "service":
        history_table = ServiceHistory.__table__
        where_clause = history_table.c.uuid == _uuid.UUID(service_uuid)
        ordering = history_table.c.changed_at.desc()
    elif source == "credential":
        history_table = ServiceCredentialHistory.__table__
        where_clause = history_table.c.service_uuid == _uuid.UUID(service_uuid)
        ordering = history_table.c.changed_at.desc()
    else:
        raise InvalidAuditSourceError("source must be 'service' or 'credential'")

    query = (
        select(history_table)
        .where(where_clause)
        .order_by(ordering)
    )

    total = db.scalar(select(func.count()).select_from(
        select(history_table).where(where_clause).subquery()
    ))
    rows = db.execute(query.offset((page - 1) * page_size).limit(page_size)).mappings().all()

    items = []
    for row in rows:
        mapped = dict(row)
        if source == "credential":
            mapped["credential_uuid"] = mapped.get("uuid")
            mapped["slug"] = None
        items.append(_map_audit_row(mapped, source=source))

    return items, total


def list_catalog_audits(db, limit: int) -> list[dict]:
    service_history = ServiceHistory.__table__
    credential_history = ServiceCredentialHistory.__table__
    services = Service.__table__

    service_rows = select(
        service_history.c.history_uuid,
        literal("service").label("source"),
        service_history.c.slug,
        literal(None).cast(UUID(as_uuid=True)).label("credential_uuid"),
        service_history.c.name,
        service_history.c.base_url,
        service_history.c.changed_at,
        service_history.c.changed_by_uuid,
        service_history.c.changed_by_type,
        service_history.c.change_type,
    )

    credential_rows = (
        select(
            credential_history.c.history_uuid,
            literal("credential").label("source"),
            services.c.slug,
            credential_history.c.uuid.label("credential_uuid"),
            literal(None).label("name"),
            literal(None).label("base_url"),
            credential_history.c.changed_at,
            credential_history.c.changed_by_uuid,
            credential_history.c.changed_by_type,
            credential_history.c.change_type,
        )
        .join(services, credential_history.c.service_uuid == services.c.uuid)
    )

    combined = union_all(service_rows, credential_rows).subquery()
    rows = db.execute(
        select(combined)
        .order_by(combined.c.changed_at.desc())
        .limit(limit)
    ).mappings().all()

    return [_map_audit_row(row, source=row["source"]) for row in rows]

