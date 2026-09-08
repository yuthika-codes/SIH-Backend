from pathlib import Path

from app.forensic_engine import recovery as recovery_module
from app.forensic_engine.hashing import calculate_sha256
from app.forensic_engine.recovery import RecoveryEngine, detect_signature


def _mock_valid_probe(*args, **kwargs):
    return {"probe_status": "success", "duration_seconds": 2.0, "video_streams": [{"codec_name": "h264"}]}


def test_video_signatures(tmp_path: Path) -> None:
    mp4 = tmp_path / "no_extension"
    mp4.write_bytes(b"\x00\x00\x00\x18ftypisom" + b"\x00" * 20)
    avi = tmp_path / "avi.bin"
    avi.write_bytes(b"RIFF" + b"\x00" * 4 + b"AVI " + b"\x00" * 20)
    mkv = tmp_path / "mkv.bin"
    mkv.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 20)
    transport = tmp_path / "transport.bin"
    transport.write_bytes(bytes([0x47]) + b"\x00" * 187 + bytes([0x47]) + b"\x00" * 187)
    h264 = tmp_path / "h264.bin"
    h264.write_bytes(b"\x00\x00\x01\x67\x00\x00\x01\x65")
    h265 = tmp_path / "h265.bin"
    h265.write_bytes(b"\x00\x00\x01\x42")
    assert detect_signature(mp4)["detected_format"] == "mp4"
    assert detect_signature(avi)["detected_format"] == "avi"
    assert detect_signature(mkv)["detected_format"] == "mkv"
    assert detect_signature(transport)["detected_format"] == "mpeg-ts"
    assert detect_signature(h264)["detected_format"] == "h264"
    assert detect_signature(h265)["detected_format"] == "h265"


def test_unknown_and_invalid_signatures_are_not_video(tmp_path: Path) -> None:
    unknown = tmp_path / "random.bin"
    unknown.write_bytes(b"arbitrary binary data")
    missing = tmp_path / "missing.bin"
    assert detect_signature(unknown)["detected_format"] is None
    assert detect_signature(missing)["method"] == "error"


def test_existing_file_validation_and_provenance(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    recovered = tmp_path / "recovered"
    acquired.mkdir()
    video = acquired / "camera.mp4"
    video.write_bytes(b"\x00\x00\x00\x18ftypisom" + b"data")
    monkeypatch.setattr(recovery_module, "extract_metadata", _mock_valid_probe)
    result = RecoveryEngine(acquired, recovered).recover(acquired)
    artifact = result["artifacts"][0]
    assert artifact["classification"] == "VALID"
    assert artifact["method"] == "existing_file_validation"
    assert artifact["validated"] is True
    assert artifact["output_path"]
    assert artifact["sha256"] == calculate_sha256(artifact["output_path"])
    assert Path(artifact["output_path"]).parent == recovered
    assert video.read_bytes() == b"\x00\x00\x00\x18ftypisomdata"


def test_missing_extension_and_wrong_extension_are_signature_recovered(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    recovered = tmp_path / "recovered"
    acquired.mkdir()
    for name in ("camera_without_extension", "camera.txt"):
        (acquired / name).write_bytes(b"\x00\x00\x00\x18ftypisom" + b"data")
    monkeypatch.setattr(recovery_module, "extract_metadata", _mock_valid_probe)
    artifacts = RecoveryEngine(acquired, recovered).recover(acquired)["artifacts"]
    assert {artifact["method"] for artifact in artifacts} == {"signature_scan"}
    assert all(Path(artifact["output_path"]).suffix == ".mp4" for artifact in artifacts)


def test_ffprobe_unavailable_does_not_claim_valid(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    acquired.mkdir()
    video = acquired / "camera.mp4"
    video.write_bytes(b"\x00\x00\x00\x18ftypisomdata")
    monkeypatch.setattr(recovery_module, "extract_metadata", lambda path: {"probe_status": "error", "error": "FFprobe executable not found"})
    artifact = RecoveryEngine(acquired, tmp_path / "recovered").recover(acquired)["artifacts"][0]
    assert artifact["classification"] == "UNKNOWN"
    assert artifact["validation"] == "not_available"
    assert artifact["output_path"] is None


def test_ffprobe_failure_is_corrupted_and_partial_is_explicit(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    acquired.mkdir()
    corrupt = acquired / "corrupt.mp4"
    corrupt.write_bytes(b"\x00\x00\x00\x18ftypisomdata")
    monkeypatch.setattr(recovery_module, "extract_metadata", lambda path: {"probe_status": "error", "error": "Invalid data"})
    artifact = RecoveryEngine(acquired, tmp_path / "recovered").recover(acquired)["artifacts"][0]
    assert artifact["classification"] == "CORRUPTED"
    monkeypatch.setattr(recovery_module, "extract_metadata", lambda path: {"probe_status": "success", "duration_seconds": None})
    partial = RecoveryEngine(acquired, tmp_path / "recovered-partial").recover(acquired)["artifacts"][0]
    assert partial["classification"] == "PARTIALLY_RECOVERABLE"
    assert partial["validated"] is False


def test_recovery_is_collision_safe_and_blocks_path_traversal(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    recovered = tmp_path / "recovered"
    acquired.mkdir()
    video = acquired / ".._evil.mp4"
    video.write_bytes(b"\x00\x00\x00\x18ftypisomdata")
    monkeypatch.setattr(recovery_module, "extract_metadata", _mock_valid_probe)
    engine = RecoveryEngine(acquired, recovered)
    first = engine.recover(video)["artifacts"][0]["output_path"]
    second = engine.recover(video)["artifacts"][0]["output_path"]
    assert first != second
    assert Path(first).parent == recovered
    assert Path(second).parent == recovered
    outside = tmp_path / "outside.mp4"
    outside.write_bytes(video.read_bytes())
    blocked = engine.recover(outside)
    assert blocked["status"] == "error"


def test_recovery_engine_only_reads_acquired_copy(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    recovered = tmp_path / "recovered"
    acquired.mkdir()
    source = acquired / "camera.mp4"
    source.write_bytes(b"\x00\x00\x00\x18ftypisomdata")
    monkeypatch.setattr(recovery_module, "extract_metadata", _mock_valid_probe)
    result = RecoveryEngine(acquired, recovered).recover(source)
    assert Path(result["artifacts"][0]["source_path"]) == source
    assert not (tmp_path / "original.mp4").exists()


def test_embedded_mp4_is_carved_with_offset_and_provenance(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    recovered = tmp_path / "recovered"
    acquired.mkdir()
    raw = acquired / "disk.img"
    prefix = b"header" * 20
    payload = (24).to_bytes(4, "big") + b"ftypisom" + b"payload-data"
    raw.write_bytes(prefix + payload + b"trailer")
    monkeypatch.setattr(recovery_module, "extract_metadata", _mock_valid_probe)
    artifacts = RecoveryEngine(acquired, recovered).recover(raw)["artifacts"]
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["source_offset"] == len(prefix)
    assert artifact["method"] == "signature_scan"
    assert artifact["source_path"] == str(raw)
    assert artifact["sha256"] == calculate_sha256(artifact["output_path"])
    assert Path(artifact["output_path"]).parent == recovered
    assert raw.read_bytes() == prefix + payload + b"trailer"


def test_multiple_embedded_candidates_are_reported(tmp_path: Path, monkeypatch) -> None:
    acquired = tmp_path / "forensic_images"
    acquired.mkdir()
    raw = acquired / "raw.bin"
    raw.write_bytes(b"x" * 10 + (24).to_bytes(4, "big") + b"ftypisom" + b"a" * 12 + b"y" * 10 + (24).to_bytes(4, "big") + b"ftypisom" + b"b" * 12)
    monkeypatch.setattr(recovery_module, "extract_metadata", _mock_valid_probe)
    artifacts = RecoveryEngine(acquired, tmp_path / "recovered").recover(raw)["artifacts"]
    assert len(artifacts) == 2
    assert {artifact["source_offset"] for artifact in artifacts} == {10, 44}
