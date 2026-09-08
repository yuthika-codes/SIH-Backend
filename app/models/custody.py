from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.services.database import Base


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    action: Mapped[str] = mapped_column(String(100))
    actor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
