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
