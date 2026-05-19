from __future__ import annotations

import uuid
from typing import Optional
from sqlalchemy import Text, SmallInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.engine import Base
from src.models.audit_mixin import AuditColumnsMixin, HistoryColumnsMixin

class User(Base, AuditColumnsMixin):
    __tablename__ = "users"

    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )
    idp_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False, comment="The unchanging provider subject ID (e.g. WorkOS user_123)")
    first_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    email: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class UserHistory(Base, HistoryColumnsMixin):
    __tablename__ = "users_history"

    uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    idp_id: Mapped[str] = mapped_column(Text, nullable=False)
    first_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    email: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
