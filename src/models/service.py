from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Text, func, SmallInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.engine import Base


class Service(Base):
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

    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    changed_by_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    changed_by_type: Mapped[int] = mapped_column(SmallInteger)
    change_type: Mapped[int] = mapped_column(SmallInteger, server_default="1")
