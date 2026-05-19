from __future__ import annotations

import uuid

from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.engine import Base
from src.models.audit_mixin import AuditColumnsMixin, HistoryColumnsMixin


class Service(Base, AuditColumnsMixin):
    __tablename__ = "services"

    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
    )
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(Text, nullable=False)

    credentials: Mapped[list["ServiceCredential"]] = relationship(back_populates="service")


class ServiceHistory(Base, HistoryColumnsMixin):
    __tablename__ = "services_history"

    uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    base_url: Mapped[str] = mapped_column(Text, nullable=False)
