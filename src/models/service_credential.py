from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Text, func, SmallInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.engine import Base


class ServiceCredential(Base):
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

    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    changed_by_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    changed_by_type: Mapped[int] = mapped_column(SmallInteger)
    change_type: Mapped[int] = mapped_column(SmallInteger, server_default="1")
