from __future__ import annotations

import uuid
from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.engine import Base
from src.models.audit_mixin import AuditColumnsMixin, HistoryColumnsMixin

class Tenant(Base, AuditColumnsMixin):
    __tablename__ = "tenants"

    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )
    idp_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False, comment="The unchanging provider tenant ID (e.g. WorkOS org_123)")
    name: Mapped[str] = mapped_column(Text, nullable=False)

class TenantHistory(Base, HistoryColumnsMixin):
    __tablename__ = "tenants_history"

    uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    idp_id: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
