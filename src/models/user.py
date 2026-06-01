from __future__ import annotations

import uuid

from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.engine import Base
from src.models.audit_mixin import AuditColumnsMixin


class User(Base, AuditColumnsMixin):
    __tablename__ = "users"

    uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )
    idp_id: Mapped[str] = mapped_column(
        Text,
        unique=True,
        nullable=False,
        comment="The unchanging provider subject ID (e.g. WorkOS user_123)",
    )
    roles: Mapped[list[str]] = mapped_column(
        ARRAY(Text),
        nullable=False,
        server_default="{}",
        comment="Mirror of User registry roles (T2); JWT cache, updated on provision",
    )
