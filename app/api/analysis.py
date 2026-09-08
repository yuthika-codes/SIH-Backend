from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.forensic_engine.engine import ForensicEngine, serialize_result
from app.models.analysis import AnalysisResult
from app.models.evidence import Evidence
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
    result = ForensicEngine().analyze(path)
    if evidence_id:
        record = AnalysisResult(id=str(uuid4()), evidence_id=evidence_id, analysis_type=payload.analysis_type, result=serialize_result(result))
        db.add(record)
        db.commit()
    return {"evidence_id": evidence_id, "analysis_type": payload.analysis_type, "result": result}
