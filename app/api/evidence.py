from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.services.database import get_db
from app.services.storage import ROOT, ensure_storage, sha256_file

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("/upload/{case_id}", response_model=None, status_code=201)
def upload_evidence(case_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)) -> Evidence:
    if db.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    ensure_storage()
    evidence_id = str(uuid4())
    destination = ROOT / "evidence" / f"{evidence_id}_{file.filename or 'evidence.bin'}"
    destination.write_bytes(file.file.read())
    evidence = Evidence(id=evidence_id, case_id=case_id, filename=file.filename or "evidence.bin", media_type=file.content_type, storage_path=str(destination), sha256=sha256_file(destination))
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


@router.get("/{case_id}", response_model=None)
def list_evidence(case_id: str, db: Session = Depends(get_db)) -> list[Evidence]:
    return list(db.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.created_at.desc())))
