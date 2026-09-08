from pathlib import Path

from fastapi.testclient import TestClient

from app.forensic_engine.device_identifier import DeviceIdentifier
from app.forensic_engine.engine import ForensicEngine
from app.forensic_engine.hashing import calculate_file_hashes, calculate_md5, calculate_sha256, verify_sha256
from app.forensic_engine.metadata import extract_metadata
from app.forensic_engine import metadata as metadata_module
from app.forensic_engine.filesystem import FileSystemAnalyzer
from app.forensic_engine.video_extractor import VideoExtractor
from app.forensic_engine.parsers.base import EvidenceParser
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


def test_metadata_uses_real_file_values(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "sample.bin"
    evidence.write_bytes(b"metadata")
    command_paths: list[str] = []
    monkeypatch.setattr(metadata_module.shutil, "which", lambda executable: executable)

    def probe(*args, **kwargs):
        command_paths.append(args[0][-1])
        return type("Completed", (), {
            "returncode": 0,
            "stdout": '{"format":{"format_name":"matroska,webm","format_long_name":"Matroska / WebM","duration":"2.5","bit_rate":"8000","start_time":"0.0","tags":{"encoder":"test"}},"streams":[{"codec_type":"video","codec_name":"h264","codec_long_name":"H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10","profile":"High","width":1920,"height":1080,"pix_fmt":"yuv420p","r_frame_rate":"25/1","avg_frame_rate":"25/1","nb_frames":"63","start_time":"0.0","duration":"2.5"},{"codec_type":"audio","codec_name":"aac","codec_long_name":"AAC","sample_rate":"48000","channels":2,"start_time":"0.0","duration":"2.5"}]}',
            "stderr": "",
        })()

    monkeypatch.setattr(metadata_module.subprocess, "run", probe)
    result = extract_metadata(str(evidence))
    assert result["probe_status"] == "success"
    assert result["filename"] == "sample.bin"
    assert result["file_size_bytes"] == 8
    assert result["format_name"] == "matroska,webm"
    assert result["duration_seconds"] == 2.5
    assert result["video_streams"][0]["width"] == 1920
    assert result["video_streams"][0]["height"] == 1080
    assert result["video_streams"][0]["codec_name"] == "h264"
    assert result["audio_streams"][0]["sample_rate"] == 48000
    assert command_paths == [str(evidence)]


def test_metadata_missing_file_returns_error(tmp_path: Path) -> None:
    result = extract_metadata(tmp_path / "missing.mp4")
    assert result["probe_status"] == "error"
    assert result["error"] == "File does not exist"


def test_metadata_reports_corrupt_video(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "corrupt.mp4"
    evidence.write_bytes(b"not a video")
    monkeypatch.setattr(metadata_module.shutil, "which", lambda executable: executable)
    monkeypatch.setattr(metadata_module.subprocess, "run", lambda *args, **kwargs: type("Completed", (), {"returncode": 1, "stdout": "", "stderr": "Invalid data found"})())
    result = extract_metadata(evidence)
    assert result["probe_status"] == "error"
    assert "Invalid data" in result["error"]


def test_metadata_reports_missing_ffprobe(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "video.mp4"
    evidence.write_bytes(b"video")
    monkeypatch.setattr(metadata_module.shutil, "which", lambda executable: None)
    result = extract_metadata(evidence)
    assert result["probe_status"] == "error"
    assert result["error"] == "FFprobe executable not found"


def test_metadata_reports_malformed_ffprobe_output(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "video.mp4"
    evidence.write_bytes(b"video")
    monkeypatch.setattr(metadata_module.shutil, "which", lambda executable: executable)
    monkeypatch.setattr(metadata_module.subprocess, "run", lambda *args, **kwargs: type("Completed", (), {"returncode": 0, "stdout": "not-json", "stderr": ""})())
    result = extract_metadata(evidence)
    assert result["probe_status"] == "error"
    assert result["error"] == "Malformed FFprobe JSON output"


def test_proprietary_dav_is_unsupported(tmp_path: Path) -> None:
    evidence = tmp_path / "camera.dav"
    evidence.write_bytes(b"proprietary")
    result = FileSystemAnalyzer().analyze(evidence)
    assert result["status"] == "unsupported"
    assert result["candidate_video_files"] == []
    extraction = VideoExtractor().extract([evidence], tmp_path / "extracted")
    assert extraction[0]["status"] == "unsupported"


def test_engine_metadata_and_extraction_use_acquired_copy(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "original.mp4"
    evidence.write_bytes(b"original")
    engine = ForensicEngine(storage_root=tmp_path / "storage")
    observed: dict[str, object] = {}

    def filesystem(path: Path) -> dict[str, object]:
        acquired_video = Path(path).with_name("acquired-video.mp4")
        acquired_video.write_bytes(b"acquired video")
        return {"status": "supported", "candidate_video_files": [str(acquired_video)], "candidate_metadata_files": []}

    def extract(paths: list[str], output: Path) -> list[dict[str, object]]:
        observed["extraction"] = [Path(path) for path in paths]
        return [{"status": "completed", "input_path": paths[0], "output_path": str(output / "extracted.mp4")}]

    def metadata(path: str) -> dict[str, object]:
        observed["metadata"] = Path(path)
        return {"probe_status": "success", "filename": Path(path).name}

    monkeypatch.setattr(engine.filesystem, "analyze", filesystem)
    monkeypatch.setattr(engine.video_extractor, "extract", extract)
    monkeypatch.setattr("app.forensic_engine.engine.extract_metadata", metadata)
    result = engine.analyze(evidence)
    acquired = Path(result["processing_path"])
    assert acquired != evidence
    assert observed["extraction"][0].parent == acquired.parent
    assert observed["metadata"].parent == (tmp_path / "storage" / "extracted")
    assert evidence.read_bytes() == b"original"


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


def test_original_evidence_is_unchanged_and_processing_uses_acquired_copy(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "camera.bin"
    original_bytes = b"read-only original evidence"
    evidence.write_bytes(original_bytes)
    engine = ForensicEngine(storage_root=tmp_path / "storage")
    observed: dict[str, object] = {}
    calls: list[str] = []

    original_acquire = engine.acquisition.acquire

    def acquire(source: Path, destination: Path) -> dict[str, object]:
        calls.append("acquisition")
        return original_acquire(source, destination)

    def identify(path: Path) -> dict[str, object]:
        calls.append("device")
        observed["device"] = Path(path)
        return {"vendor": "Unknown", "confidence": 0.0}

    def filesystem(path: Path) -> dict[str, object]:
        calls.append("filesystem")
        observed["filesystem"] = Path(path)
        return {"status": "supported", "candidate_video_files": [str(path)], "candidate_metadata_files": []}

    class SpyParser(EvidenceParser):
        def can_handle(self, evidence_path: str | Path) -> bool:
            calls.append("parser.can_handle")
            observed["parser.can_handle"] = Path(evidence_path)
            return True

        def parse(self, evidence_path: str | Path) -> dict[str, object]:
            calls.append("parser.parse")
            observed["parser"] = Path(evidence_path)
            return {"status": "supported"}

    def extract(paths: list[str], output: Path) -> list[dict[str, object]]:
        calls.append("video.extract")
        observed["video"] = [Path(path) for path in paths]
        return []

    monkeypatch.setattr(engine.acquisition, "acquire", acquire)
    monkeypatch.setattr(engine.device_identifier, "identify", identify)
    monkeypatch.setattr(engine.filesystem, "analyze", filesystem)
    engine.parsers = [SpyParser(), SpyParser()]
    monkeypatch.setattr(engine.video_extractor, "extract", extract)

    result = engine.analyze(evidence)
    acquired = Path(result["processing_path"])
    assert result["status"] == "completed"
    assert acquired != evidence
    assert acquired.parent.name == "forensic_images"
    assert evidence.read_bytes() == original_bytes
    assert observed["device"] == acquired
    assert observed["filesystem"] == acquired
    assert observed["parser.can_handle"] == acquired
    assert observed["parser"] == acquired
    assert observed["video"] == [acquired]
    assert calls == ["acquisition", "device", "filesystem", "parser.can_handle", "parser.parse", "video.extract"]


def test_integrity_mismatch_stops_before_forensic_processing(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    engine = ForensicEngine(storage_root=tmp_path / "storage")
    monkeypatch.setattr(engine.acquisition, "acquire", lambda source, destination: {
        "status": "INTEGRITY_COMPROMISED",
        "original_sha256": "a" * 64,
        "acquired_sha256": "b" * 64,
        "original_md5": "c" * 32,
        "integrity_verified": False,
        "integrity_status": "INTEGRITY_COMPROMISED",
    })
    monkeypatch.setattr(engine.device_identifier, "identify", lambda path: (_ for _ in ()).throw(AssertionError("device identification must not run")))
    result = engine.analyze(evidence)
    assert result["status"] == "error"
    assert result["integrity"]["verified"] is False
    assert result["integrity"]["status"] == "INTEGRITY_COMPROMISED"
    assert result["videos"] == []
    assert result["metadata"] == []


def test_false_integrity_flag_stops_even_with_completed_status(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    engine = ForensicEngine(storage_root=tmp_path / "storage")
    monkeypatch.setattr(engine.acquisition, "acquire", lambda source, destination: {
        "status": "completed",
        "original_sha256": "a" * 64,
        "acquired_sha256": "b" * 64,
        "integrity_verified": False,
    })
    monkeypatch.setattr(engine.device_identifier, "identify", lambda path: (_ for _ in ()).throw(AssertionError("processing must stop")))
    result = engine.analyze(evidence)
    assert result["status"] == "error"
    assert result["integrity"]["status"] == "INTEGRITY_COMPROMISED"


def test_hash_mismatch_stops_even_when_acquisition_claims_verified(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    engine = ForensicEngine(storage_root=tmp_path / "storage")
    monkeypatch.setattr(engine.acquisition, "acquire", lambda source, destination: {
        "status": "completed",
        "original_sha256": "a" * 64,
        "acquired_sha256": "b" * 64,
        "integrity_verified": True,
        "integrity_status": "VERIFIED",
    })
    monkeypatch.setattr(engine.device_identifier, "identify", lambda path: (_ for _ in ()).throw(AssertionError("processing must stop")))
    result = engine.analyze(evidence)
    assert result["status"] == "error"
    assert result["integrity"]["verified"] is False
    assert result["integrity"]["status"] == "INTEGRITY_COMPROMISED"


def test_acquisition_failure_stops_before_forensic_processing(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    engine = ForensicEngine(storage_root=tmp_path / "storage")
    monkeypatch.setattr(engine.acquisition, "acquire", lambda source, destination: {
        "status": "error",
        "error": "copy failed",
    })
    monkeypatch.setattr(engine.device_identifier, "identify", lambda path: (_ for _ in ()).throw(AssertionError("processing must stop")))
    monkeypatch.setattr(engine.filesystem, "analyze", lambda path: (_ for _ in ()).throw(AssertionError("processing must stop")))
    result = engine.analyze(evidence)
    assert result["status"] == "error"
    assert result["processing_path"] is None
    assert result["videos"] == []
    assert result["integrity"]["status"] == "ACQUISITION_FAILED"


def test_analysis_success_records_started_and_completed_events() -> None:
    with TestClient(app) as client:
        case = client.post("/cases", json={"title": "Custody analysis success"})
        evidence_response = client.post("/evidence/upload/" + case.json()["id"], files={"file": ("success.bin", b"success evidence", "application/octet-stream")})
        evidence_id = evidence_response.json()["id"]
        response = client.post("/analysis/run", json={"evidence_id": evidence_id})
        assert response.status_code == 200
        actions = {event["action"] for event in client.get("/custody/" + evidence_id).json()}
        assert {"ANALYSIS_STARTED", "ACQUISITION_STARTED", "ACQUISITION_COMPLETED", "INTEGRITY_VERIFIED", "ANALYSIS_COMPLETED"} <= actions


def test_analysis_mismatch_records_compromised_event(monkeypatch) -> None:
    from app.api import analysis as analysis_api

    def compromised(self, path):
        return {
            "status": "error",
            "acquisition": {
                "status": "INTEGRITY_COMPROMISED",
                "original_sha256": "a" * 64,
                "acquired_sha256": "b" * 64,
                "integrity_verified": False,
                "integrity_status": "INTEGRITY_COMPROMISED",
            },
            "integrity": {"verified": False, "status": "INTEGRITY_COMPROMISED"},
        }

    monkeypatch.setattr(analysis_api.ForensicEngine, "analyze", compromised)
    with TestClient(app) as client:
        case = client.post("/cases", json={"title": "Custody mismatch"})
        evidence_response = client.post("/evidence/upload/" + case.json()["id"], files={"file": ("mismatch.bin", b"mismatch evidence", "application/octet-stream")})
        evidence_id = evidence_response.json()["id"]
        response = client.post("/analysis/run", json={"evidence_id": evidence_id})
        assert response.status_code == 200
        actions = {event["action"] for event in client.get("/custody/" + evidence_id).json()}
        assert "INTEGRITY_COMPROMISED" in actions
        assert "ANALYSIS_COMPLETED" not in actions
