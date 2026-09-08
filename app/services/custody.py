import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.custody import CustodyEvent


def record_custody_event(
    db: Session,
    evidence_id: str,
    action: str,
    *,
    actor: str | None = "system",
    description: str | None = None,
    sha256: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CustodyEvent:
    event = CustodyEvent(
        id=str(uuid4()),
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        description=description,
        sha256=sha256,
        metadata_json=json.dumps(metadata or {}, default=str),
    )
    db.add(event)
    return event