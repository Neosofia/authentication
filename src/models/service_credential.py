from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text, func, SmallInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.engine import Base
from src.models.audit_mixin import AuditColumnsMixin, HistoryColumnsMixin


class ServiceCredential(Base, AuditColumnsMixin):
    __tablename__ = "service_credentials"

    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
    )
    service_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("services.uuid", ondelete="CASCADE"),
        nullable=False,
    )
    hashed_secret: Mapped[str] = mapped_column(Text, nullable=False)

    service: Mapped["Service"] = relationship(back_populates="credentials")


class ServiceCredentialHistory(Base, HistoryColumnsMixin):
    __tablename__ = "service_credentials_history"

    uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    service_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    hashed_secret: Mapped[str] = mapped_column(Text, nullable=False)
