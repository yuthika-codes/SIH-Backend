import json
import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def _uploaded_evidence(client: TestClient) -> tuple[str, bytes]:
    case = client.post("/cases", json={"title": "Reporting case", "description": "Report test"}).json()
    original = b"report evidence bytes"
    evidence = client.post(
        f"/evidence/upload/{case['id']}",
        files={"file": ("CAM01_20260908_101532.bin", original, "application/octet-stream")},
    ).json()
    client.post("/analysis/run", json={"evidence_id": evidence["id"]})
    return evidence["id"], original


def test_json_report_contains_pipeline_sections_and_hash() -> None:
    with TestClient(app) as client:
        evidence_id, original = _uploaded_evidence(client)
        response = client.post("/reports/generate", json={"evidence_id": evidence_id, "format": "json"})
        assert response.status_code == 200
        report = response.json()
        assert report["evidence_information"]["evidence_id"] == evidence_id
        assert report["integrity_information"]["original_sha256"]
        assert report["integrity_information"]["original_md5"] == hashlib.md5(original).hexdigest()
        assert report["integrity_information"]["acquired_md5"] == hashlib.md5(original).hexdigest()
        assert report["integrity_information"]["original_md5"] == report["integrity_information"]["acquired_md5"]
        assert report["integrity_information"]["acquired_sha256"] == report["integrity_information"]["original_sha256"]
        assert report["integrity_information"]["verified"] is True
        assert "timeline" in report
        assert "multi_camera_correlation" in report
        assert "recovery_findings" in report
        assert report["chain_of_custody"]
        assert isinstance(report["warnings_limitations"], list)
        assert original == b"report evidence bytes"
        latest = client.get(f"/reports/{evidence_id}")
        assert latest.status_code == 200
        assert latest.json()["report_id"] == report["report_header"]["report_id"]


def test_pdf_report_is_downloadable_and_persisted() -> None:
    with TestClient(app) as client:
        evidence_id, _ = _uploaded_evidence(client)
        response = client.post("/reports/generate", json={"evidence_id": evidence_id, "format": "pdf"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/pdf")
        assert response.content.startswith(b"%PDF")
        assert response.headers["x-report-sha256"]
        latest = client.get(f"/reports/{evidence_id}").json()
        assert latest["report_type"] == "pdf"
        assert Path(latest["file_path"]).exists()


def test_report_unknown_evidence_returns_404() -> None:
    with TestClient(app) as client:
        response = client.post("/reports/generate", json={"evidence_id": "missing", "format": "json"})
    assert response.status_code == 404


def test_report_invalid_format_returns_422() -> None:
    with TestClient(app) as client:
        response = client.post("/reports/generate", json={"evidence_id": "missing", "format": "xml"})
    assert response.status_code == 422


def test_report_path_is_generated_under_reports_storage() -> None:
    with TestClient(app) as client:
        evidence_id, _ = _uploaded_evidence(client)
        response = client.post("/reports/generate", json={"evidence_id": evidence_id, "format": "json"})
        report = response.json()
        assert Path(report["report_header"]["report_id"]).name == report["report_header"]["report_id"]
        latest = client.get(f"/reports/{evidence_id}").json()
        assert Path(latest["file_path"]).parent.name == "reports"
