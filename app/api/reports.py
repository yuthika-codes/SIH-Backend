import json
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.forensic_engine.hashing import calculate_sha256
from app.models.analysis import AnalysisResult
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.models.evidence import Evidence
from app.models.report import Report
from app.services.custody import record_custody_event
from app.services.database import get_db
from app.services.reporting import build_report, latest_report, render_pdf
from app.services.storage import ROOT, ensure_storage

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportRequest(BaseModel):
    evidence_id: str
    case_id: str | None = None
    format: Literal["json", "pdf"] = "json"


@router.post("/generate", response_model=None)
def generate_report(payload: ReportRequest, db: Session = Depends(get_db)) -> object:
    evidence = db.get(Evidence, payload.evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    case = db.get(Case, payload.case_id or evidence.case_id)
    if payload.case_id and case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    analysis = db.scalars(select(AnalysisResult).where(AnalysisResult.evidence_id == evidence.id).order_by(AnalysisResult.created_at.desc())).first()
    custody = list(db.scalars(select(CustodyEvent).where(CustodyEvent.evidence_id == evidence.id).order_by(CustodyEvent.created_at)))
    report_id = str(uuid4())
    report = build_report(evidence, case, analysis, custody, report_id)
    ensure_storage()
    if payload.format == "json":
        output_path = ROOT / "reports" / f"{report_id}.json"
        output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        media_type = "application/json"
    else:
        try:
            content = render_pdf(report)
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="PDF generation requires ReportLab") from exc
        output_path = ROOT / "reports" / f"{report_id}.pdf"
        output_path.write_bytes(content)
        media_type = "application/pdf"
    report_record = Report(id=report_id, evidence_id=evidence.id, case_id=case.id if case else None, report_type=payload.format, file_path=str(output_path), report_hash=calculate_sha256(output_path))
    db.add(report_record)
    record_custody_event(db, evidence.id, "REPORT_GENERATED", description=f"{payload.format.upper()} forensic report generated.", sha256=report_record.report_hash, metadata={"report_id": report_id, "path": str(output_path)})
    db.commit()
    if payload.format == "pdf":
        return FileResponse(path=output_path, media_type=media_type, filename=output_path.name, headers={"X-Report-ID": report_id, "X-Report-SHA256": report_record.report_hash})
    return report


@router.get("/{evidence_id}", response_model=None)
def get_report(evidence_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    report = latest_report(db, evidence_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    path = Path(report.file_path)
    result: dict[str, object] = {"report_id": report.id, "evidence_id": report.evidence_id, "case_id": report.case_id, "report_type": report.report_type, "generated_at": report.generated_at.isoformat(), "file_path": report.file_path, "report_hash": report.report_hash, "status": report.status}
    if report.report_type == "json" and path.exists():
        try:
            result["report"] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            result["report_error"] = "Stored JSON report could not be read"
    return result
