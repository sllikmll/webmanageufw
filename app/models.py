from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class Server(Base):
    __tablename__ = 'servers'
    __table_args__ = (
        Index('ix_servers_name', 'name'),
        Index('ix_servers_host', 'host'),
        Index('ix_servers_auth_type', 'auth_type'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(20), nullable=False)
    encrypted_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_private_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_sudo_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
