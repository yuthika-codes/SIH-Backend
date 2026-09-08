import json
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.analysis import AnalysisResult
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.models.evidence import Evidence
from app.models.report import Report
from app.services.storage import ROOT
from app.forensic_engine.hashing import calculate_sha256


def _available(value: object) -> object:
    return value if value not in (None, "") else "Not available"


def build_report(evidence: Evidence, case: Case | None, analysis: AnalysisResult | None, custody: list[CustodyEvent], report_id: str | None = None) -> dict[str, object]:
    analysis_result: dict[str, Any] = {}
    if analysis:
        try:
            parsed = json.loads(analysis.result)
            if isinstance(parsed, dict):
                analysis_result = parsed
        except json.JSONDecodeError:
            analysis_result = {}
    acquisition = analysis_result.get("acquisition", {}) if isinstance(analysis_result.get("acquisition"), dict) else {}
    metadata = analysis_result.get("metadata", []) if isinstance(analysis_result.get("metadata"), list) else []
    timeline = analysis_result.get("timeline", {})
    correlations = analysis_result.get("correlations", []) if isinstance(analysis_result.get("correlations"), list) else []
    recovery = analysis_result.get("recovery", {}) if isinstance(analysis_result.get("recovery"), dict) else {}
    artifacts = recovery.get("artifacts", []) if isinstance(recovery.get("artifacts"), list) else []
    ai_analysis = _normalize_ai_analysis(analysis_result.get("ai_analysis"))
    warnings: list[str] = []
    if not analysis:
        warnings.append("No stored forensic analysis result is available.")
    if not evidence.integrity_verified:
        warnings.append("Evidence integrity has not been verified.")
    for item in metadata:
        if item.get("probe_status") != "success":
            warnings.append(str(item.get("error", "Video metadata is unavailable.")))
    if recovery.get("status") == "error":
        warnings.append(str(recovery.get("error", "Recovery analysis failed.")))
    if any(item.get("timestamp", {}).get("source") == "filesystem_mtime" for item in metadata if isinstance(item, dict) and isinstance(item.get("timestamp"), dict)):
        warnings.append("A filesystem modification time was used as a low-confidence fallback, not as a CCTV recording time.")
    report = {
        "report_header": {
            "report_id": report_id or str(uuid4()),
            "case_id": evidence.case_id,
            "evidence_id": evidence.id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "application_name": "SIH Forensic Evidence API",
            "application_version": "0.1.0",
        },
        "case_information": {"case_id": case.id if case else evidence.case_id, "title": _available(case.title if case else None), "description": _available(case.description if case else None), "investigator": _available(case.created_by if case else None), "created_at": case.created_at.isoformat() if case else None},
        "evidence_information": {"evidence_id": evidence.id, "original_path": _available(evidence.original_path or evidence.storage_path), "acquired_path": _available(evidence.acquired_path), "filename": evidence.filename, "file_size_bytes": evidence.size_bytes, "media_type": _available(evidence.media_type), "acquired_at": evidence.acquired_at.isoformat() if evidence.acquired_at else None},
        "integrity_information": {"original_sha256": _available(evidence.original_sha256 or evidence.sha256), "acquired_sha256": _available(evidence.acquired_sha256), "original_md5": _available(evidence.md5), "acquired_md5": _available(evidence.acquired_md5 or acquisition.get("acquired_md5")), "verified": bool(evidence.integrity_verified), "status": evidence.integrity_status, "verification_timestamp": next((event.created_at.isoformat() for event in custody if event.action == "INTEGRITY_VERIFIED"), None)},
        "device_information": analysis_result.get("device", {}) or {"status": "Not available"},
        "filesystem_analysis": analysis_result.get("filesystem", {}) or {"status": "Not available"},
        "video_analysis": metadata,
        "timestamp_analysis": [{"timestamp": item.get("timestamp"), "camera_id": item.get("camera_id", "UNKNOWN")} for item in metadata if isinstance(item, dict)],
        "timeline": timeline,
        "multi_camera_correlation": correlations,
        "recovery_findings": artifacts,
        "ai_analysis": ai_analysis,
        "chain_of_custody": [_custody_dict(event) for event in sorted(custody, key=lambda item: item.created_at)],
        "warnings_limitations": sorted(set(warnings)),
    }
    report["executive_summary"] = _summary(report)
    return report


def _custody_dict(event: CustodyEvent) -> dict[str, object]:
    try:
        metadata = json.loads(event.metadata_json or "{}")
    except json.JSONDecodeError:
        metadata = {}
    return {"event_id": event.id, "timestamp": event.created_at.isoformat(), "action": event.action, "actor": _available(event.actor), "description": _available(event.description), "sha256": _available(event.sha256), "notes": _available(event.notes), "metadata": metadata}


def _summary(report: dict[str, object]) -> dict[str, object]:
    evidence = report["evidence_information"]
    integrity = report["integrity_information"]
    metadata = report["video_analysis"]
    artifacts = report["recovery_findings"]
    correlations = report["multi_camera_correlation"]
    ai = report["ai_analysis"]
    return {"evidence": evidence["filename"], "integrity_status": integrity["status"], "integrity_verified": integrity["verified"], "device_status": report["device_information"].get("vendor", "Not available"), "video_file_count": len(metadata), "event_count": len(report["timeline"].get("events", [])) if isinstance(report["timeline"], dict) else 0, "recovered_artifact_count": len(artifacts), "corrupted_or_unknown_artifact_count": sum(1 for item in artifacts if item.get("classification") in {"CORRUPTED", "UNKNOWN"}), "correlated_event_count": len(correlations), "ai_analysis_status": ai["status"], "ai_event_count": ai["summary"]["total_events"], "persons_detected": ai["summary"]["person_detections"], "objects_detected": ai["summary"]["object_detections"], "limitations": report["warnings_limitations"]}


def _normalize_ai_analysis(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        return {"status": "not_run", "model": "Unknown", "events": [], "summary": _ai_summary([])}
    events = raw.get("events") if isinstance(raw.get("events"), list) else []
    videos = raw.get("videos") if isinstance(raw.get("videos"), list) else []
    model = raw.get("model") if raw.get("model") else "Unknown"
    if model == "Unknown":
        for video in videos:
            components = video.get("components") if isinstance(video, dict) else None
            if isinstance(components, dict) and components.get("yolo") == "available":
                model = "YOLO"
                break
    return {"status": raw.get("status") or "not_run", "model": model, "events": events, "summary": _ai_summary(events)}


def _ai_summary(events: list[object]) -> dict[str, object]:
    person = face = motion = objects = 0
    labels: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = event.get("event_type")
        label = event.get("label")
        if event_type == "person":
            person += 1
        elif event_type == "face":
            face += 1
        elif event_type == "motion":
            motion += 1
        elif event_type == "object":
            objects += 1
            if isinstance(label, str) and label:
                labels.add(label)
    return {"total_events": len(events), "person_detections": person, "object_detections": objects, "face_detections": face, "motion_events": motion, "unique_object_labels": sorted(labels)}


def render_pdf(report: dict[str, object]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    stream = BytesIO()
    document = SimpleDocTemplate(stream, pagesize=letter, rightMargin=0.5 * inch, leftMargin=0.5 * inch, topMargin=0.5 * inch, bottomMargin=0.5 * inch, pageCompression=0)
    styles = getSampleStyleSheet()
    story = [Paragraph("SIH Forensic Evidence Report", styles["Title"]), Paragraph(f"Report ID: {report['report_header']['report_id']}", styles["Normal"]), Spacer(1, 12)]
    ai_section = {"status": report["ai_analysis"]["status"], "model": report["ai_analysis"]["model"], **report["ai_analysis"]["summary"], "events": report["ai_analysis"]["events"][:100], "event_list_note": "Only the first 100 events are displayed; the full AI results remain in the JSON report." if len(report["ai_analysis"]["events"]) > 100 else ""}
    for title, section in (("Executive Summary", report["executive_summary"]), ("Case Information", report["case_information"]), ("Evidence Information", report["evidence_information"]), ("Integrity Information", report["integrity_information"]), ("Device Information", report["device_information"]), ("Filesystem Analysis", report["filesystem_analysis"]), ("Video Analysis", {"streams": report["video_analysis"]}), ("AI Analysis", ai_section), ("Timeline", report["timeline"]), ("Correlations", {"correlations": report["multi_camera_correlation"]}), ("Recovery Findings", {"artifacts": report["recovery_findings"]}), ("Chain of Custody", {"events": report["chain_of_custody"]}), ("Warnings / Limitations", {"warnings": report["warnings_limitations"]})):
        story.append(Paragraph(title, styles["Heading2"]))
        rows = [[str(key), json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value)] for key, value in section.items()]
        table = Table(rows, colWidths=[1.8 * inch, 5.2 * inch])
        table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.extend([table, Spacer(1, 10)])
    document.build(story, onFirstPage=_page_number, onLaterPages=_page_number)
    return stream.getvalue()


def _page_number(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.drawString(0.5 * 72, 0.35 * 72, f"Page {document.page}")
    canvas.restoreState()


def latest_report(db: Session, evidence_id: str) -> Report | None:
    return db.query(Report).filter(Report.evidence_id == evidence_id).order_by(Report.generated_at.desc()).first()