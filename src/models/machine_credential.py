import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Text, func, SmallInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.engine import Base


class MachineCredential(Base):
    __tablename__ = "machine_credentials"

    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
    )
    service_name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    hashed_secret: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")

    # Audit tracking fields (automatically injected and managed by Postgres triggers)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    changed_by_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    changed_by_type: Mapped[int] = mapped_column(SmallInteger)
    change_type: Mapped[int] = mapped_column(SmallInteger, server_default="1")
