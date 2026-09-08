from datetime import datetime, timezone
from uuid import uuid4
import shutil

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.services.database import get_db
from app.services.custody import record_custody_event
from app.services.storage import ROOT, ensure_storage
from app.forensic_engine.hashing import calculate_file_hashes

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("/upload/{case_id}", response_model=None, status_code=201)
def upload_evidence(case_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)) -> Evidence:
    if db.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    ensure_storage()
    evidence_id = str(uuid4())
    destination = ROOT / "evidence" / f"{evidence_id}_{file.filename or 'evidence.bin'}"
    with destination.open("wb") as output_file:
        shutil.copyfileobj(file.file, output_file, length=1024 * 1024)
    hashes = calculate_file_hashes(destination)
    acquisition_time = datetime.now(timezone.utc).replace(tzinfo=None)
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        filename=file.filename or "evidence.bin",
        media_type=file.content_type,
        storage_path=str(destination),
        original_path=str(destination),
        sha256=str(hashes["sha256"]),
        original_sha256=str(hashes["sha256"]),
        md5=str(hashes["md5"]),
        size_bytes=int(hashes["size_bytes"]),
        created_at=acquisition_time,
        integrity_status="PENDING",
    )
    db.add(evidence)
    record_custody_event(db, evidence_id, "EVIDENCE_UPLOADED", description="Evidence uploaded and stored without modifying the source stream.", sha256=evidence.sha256, metadata={"filename": evidence.filename, "size_bytes": evidence.size_bytes})
    record_custody_event(db, evidence_id, "HASH_CALCULATED", description="Original evidence hashes calculated.", sha256=evidence.sha256, metadata={"md5": evidence.md5, "size_bytes": evidence.size_bytes})
    db.commit()
    db.refresh(evidence)
    return evidence


@router.get("/{case_id}", response_model=None)
def list_evidence(case_id: str, db: Session = Depends(get_db)) -> list[Evidence]:
    return list(db.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.created_at.desc())))
