from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.services.database import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    media_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    original_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    original_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(nullable=True)
    acquired_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    acquired_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acquired_md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    integrity_verified: Mapped[bool | None] = mapped_column(nullable=True)
    integrity_status: Mapped[str] = mapped_column(String(30), default="PENDING")
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="uploaded")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
