from pathlib import Path

from fastapi.testclient import TestClient

from app.forensic_engine.device_identifier import DeviceIdentifier
from app.forensic_engine.engine import ForensicEngine
from app.forensic_engine.hashing import calculate_file_hashes, calculate_md5, calculate_sha256, verify_sha256
from app.forensic_engine.metadata import extract_metadata
from app.forensic_engine.parsers.dahua import DahuaParser
from app.main import app


def test_hashing_and_verification(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"known forensic bytes")

    hashes = calculate_file_hashes(evidence)
    assert hashes["size_bytes"] == evidence.stat().st_size
    assert hashes["md5"] == calculate_md5(evidence)
    assert hashes["sha256"] == calculate_sha256(evidence)
    assert verify_sha256(evidence, str(hashes["sha256"]))
    assert not verify_sha256(evidence, "0" * 64)


def test_device_identification_is_conservative(tmp_path: Path) -> None:
    evidence = tmp_path / "unknown.dav"
    evidence.write_bytes(b"proprietary")
    result = DeviceIdentifier().identify(evidence)
    assert result["vendor"] == "Unknown"
    assert result["confidence"] == 0.0


def test_vendor_parser_does_not_fake_proprietary_support(tmp_path: Path) -> None:
    result = DahuaParser().parse(tmp_path / "camera.dav")
    assert result["status"] == "unsupported"


def test_metadata_uses_real_file_values(tmp_path: Path) -> None:
    evidence = tmp_path / "sample.bin"
    evidence.write_bytes(b"metadata")
    result = extract_metadata(str(evidence))
    assert result["status"] == "completed"
    assert result["filename"] == "sample.bin"
    assert result["file_size"] == 8
    assert result["duration"] is None


def test_engine_missing_evidence(tmp_path: Path) -> None:
    result = ForensicEngine(storage_root=tmp_path / "storage").analyze(tmp_path / "missing.bin")
    assert result["status"] == "error"
    assert result["integrity"]["verified"] is False


def test_analysis_endpoint_runs_engine(tmp_path: Path) -> None:
    evidence = tmp_path / "sample.bin"
    evidence.write_bytes(b"endpoint evidence")
    with TestClient(app) as client:
        response = client.post("/analysis/run", json={"evidence_path": str(evidence)})
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["status"] == "completed"
    assert body["result"]["integrity"]["verified"] is True


def test_upload_creates_hashes_and_custody_events() -> None:
    with TestClient(app) as client:
        case = client.post("/cases", json={"title": "Upload integrity test"})
        case_id = case.json()["id"]
        response = client.post("/evidence/upload/" + case_id, files={"file": ("upload.bin", b"upload bytes", "application/octet-stream")})
        assert response.status_code == 201
        evidence = response.json()
        assert evidence["sha256"]
        assert evidence["md5"]
        assert evidence["size_bytes"] == 12
        events = client.get("/custody/" + evidence["id"]).json()
        assert {event["action"] for event in events} >= {"EVIDENCE_UPLOADED", "HASH_CALCULATED"}


def test_modified_acquired_evidence_is_compromised() -> None:
    with TestClient(app) as client:
        case = client.post("/cases", json={"title": "Modification integrity test"})
        evidence_response = client.post("/evidence/upload/" + case.json()["id"], files={"file": ("modify.bin", b"original bytes", "application/octet-stream")})
        evidence_id = evidence_response.json()["id"]
        assert client.post("/analysis/run", json={"evidence_id": evidence_id}).status_code == 200
        acquired_path = Path(client.get("/evidence/" + case.json()["id"]).json()[0]["acquired_path"])
        acquired_path.write_bytes(b"modified bytes")
        verification = client.get("/verification/" + evidence_id)
        assert verification.status_code == 200
        assert verification.json()["status"] == "INTEGRITY_COMPROMISED"
        assert verification.json()["verified"] is False


def test_missing_evidence_verification_returns_error() -> None:
    with TestClient(app) as client:
        response = client.get("/verification/does-not-exist")
    assert response.status_code == 404
