import json
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.custody import CustodyEvent
from app.models.evidence import Evidence
from app.services.database import get_db

router = APIRouter(prefix="/custody", tags=["chain of custody"])


class CustodyCreate(BaseModel):
    action: str
    actor: str = "system"
    description: str | None = None
    sha256: str | None = None
    metadata: dict[str, object] | None = None
    notes: str | None = None


@router.post("/{evidence_id}", response_model=None, status_code=201)
def add_event(evidence_id: str, payload: CustodyCreate, db: Session = Depends(get_db)) -> CustodyEvent:
    if db.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    data = payload.model_dump()
    metadata = data.pop("metadata")
    event = CustodyEvent(id=str(uuid4()), evidence_id=evidence_id, metadata_json=json.dumps(metadata or {}, default=str), **data)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.get("/{evidence_id}", response_model=None)
def list_events(evidence_id: str, db: Session = Depends(get_db)) -> list[CustodyEvent]:
    return list(db.scalars(select(CustodyEvent).where(CustodyEvent.evidence_id == evidence_id).order_by(CustodyEvent.created_at)))
