from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.forensic_engine.hashing import calculate_sha256
from app.models.evidence import Evidence
from app.services.custody import record_custody_event
from app.services.database import get_db
router = APIRouter(prefix="/verification", tags=["verification"])


class VerificationRequest(BaseModel):
    expected_sha256: str
    actual_sha256: str


@router.post("/hash")
def verify_hash(payload: VerificationRequest) -> dict[str, bool]:
    return {"valid": payload.expected_sha256.lower() == payload.actual_sha256.lower()}


@router.get("/{evidence_id}")
def verify_evidence(evidence_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if not evidence.acquired_path or not evidence.acquired_sha256:
        raise HTTPException(status_code=409, detail="Evidence has not been acquired")
    acquired_path = Path(evidence.acquired_path)
    if not acquired_path.exists():
        raise HTTPException(status_code=404, detail="Acquired evidence file is missing")
    try:
        current_sha256 = calculate_sha256(acquired_path)
    except (OSError, PermissionError) as exc:
        raise HTTPException(status_code=500, detail=f"Unable to verify acquired evidence: {exc}") from exc
    verified = current_sha256.lower() == evidence.acquired_sha256.lower()
    evidence.integrity_verified = verified
    evidence.integrity_status = "VERIFIED" if verified else "INTEGRITY_COMPROMISED"
    if not verified:
        evidence.status = "integrity_compromised"
    record_custody_event(db, evidence_id, "INTEGRITY_VERIFIED" if verified else "INTEGRITY_COMPROMISED", description="Acquired evidence re-verification completed.", sha256=current_sha256, metadata={"stored_sha256": evidence.acquired_sha256})
    db.commit()
    return {
        "evidence_id": evidence_id,
        "stored_sha256": evidence.acquired_sha256,
        "current_sha256": current_sha256,
        "verified": verified,
        "status": "VERIFIED" if verified else "INTEGRITY_COMPROMISED",
    }
