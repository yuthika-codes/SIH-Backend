from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.forensic_engine.engine import ForensicEngine, serialize_result
from app.models.analysis import AnalysisResult
from app.models.evidence import Evidence
from app.services.custody import record_custody_event
from app.services.database import get_db

router = APIRouter(prefix="/analysis", tags=["analysis"])


class AnalysisRequest(BaseModel):
    evidence_id: str | None = None
    evidence_path: str | None = None
    analysis_type: str = "metadata"


@router.post("/run")
def run_analysis(payload: AnalysisRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    evidence_id = payload.evidence_id
    path = payload.evidence_path
    if evidence_id:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None:
            raise HTTPException(status_code=404, detail="Evidence not found")
        path = evidence.storage_path
    if not path:
        raise HTTPException(status_code=400, detail="Provide evidence_id or evidence_path")
    if evidence_id:
        record_custody_event(db, evidence_id, "ANALYSIS_STARTED", description="Forensic analysis started.", sha256=evidence.sha256 if evidence else None, metadata={"analysis_type": payload.analysis_type})
        record_custody_event(db, evidence_id, "ACQUISITION_STARTED", description="Forensic acquisition started.", sha256=evidence.sha256 if evidence else None)
        db.commit()
    result = ForensicEngine().analyze(path)
    if evidence_id:
        acquisition = result.get("acquisition", {})
        if isinstance(acquisition, dict):
            evidence.acquired_path = acquisition.get("acquired_path")
            evidence.acquired_sha256 = acquisition.get("acquired_sha256")
            evidence.acquired_md5 = acquisition.get("acquired_md5")
            evidence.integrity_verified = acquisition.get("integrity_verified")
            evidence.integrity_status = str(acquisition.get("integrity_status", "PENDING"))
            if acquisition.get("status") == "completed":
                evidence.status = "acquired"
                evidence.acquired_at = datetime.utcnow()
                record_custody_event(db, evidence_id, "ACQUISITION_COMPLETED", description="Forensic acquisition copy created.", sha256=evidence.acquired_sha256, metadata={"acquired_path": evidence.acquired_path})
                record_custody_event(db, evidence_id, "INTEGRITY_VERIFIED", description="Acquired copy SHA-256 matches the original evidence SHA-256.", sha256=evidence.acquired_sha256)
            elif acquisition.get("status") == "INTEGRITY_COMPROMISED":
                evidence.status = "integrity_compromised"
                record_custody_event(db, evidence_id, "INTEGRITY_COMPROMISED", description="Acquired copy SHA-256 differs from the original evidence SHA-256.", sha256=evidence.acquired_sha256, metadata={"original_sha256": evidence.sha256})
            elif acquisition.get("status") != "completed":
                record_custody_event(db, evidence_id, "ACQUISITION_FAILED", description="Forensic acquisition did not complete.", sha256=evidence.sha256, metadata={"error": acquisition.get("error")})
        if result.get("status") == "completed":
            record_custody_event(db, evidence_id, "ANALYSIS_COMPLETED", description="Forensic analysis completed.", sha256=evidence.acquired_sha256, metadata={"analysis_type": payload.analysis_type})
        record = AnalysisResult(id=str(uuid4()), evidence_id=evidence_id, analysis_type=payload.analysis_type, result=serialize_result(result))
        db.add(record)
        db.commit()
    return {"evidence_id": evidence_id, "analysis_type": payload.analysis_type, "result": result}
