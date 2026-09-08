from datetime import datetime, timezone
from pathlib import Path

from app.forensic_engine.timestamp import extract_camera_id, extract_filename_timestamp, extract_timestamp


def test_container_timestamp_has_high_provenance() -> None:
    result = extract_timestamp({"container_metadata": {"creation_time": "2026-09-08T10:15:32+05:30"}}, "CAM01.mp4")
    assert result == {
        "timestamp": "2026-09-08T10:15:32+05:30",
        "source": "container_metadata",
        "confidence": "high",
        "timezone": "known",
    }


def test_filename_timestamp_is_conservative(tmp_path: Path) -> None:
    valid = extract_filename_timestamp(tmp_path / "CAM01_20260908_101532.mp4")
    invalid = extract_filename_timestamp(tmp_path / "random_video_12345.mp4")
    assert valid["timestamp"] == "2026-09-08T10:15:32"
    assert valid["source"] == "filename"
    assert invalid["timestamp"] is None
    assert invalid["source"] == "unknown"


def test_filename_timestamp_supports_dashed_pattern(tmp_path: Path) -> None:
    result = extract_filename_timestamp(tmp_path / "CAMERA01_2026-09-08_10-15-32.mp4")
    assert result["timestamp"] == "2026-09-08T10:15:32"


def test_timestamp_falls_back_with_explicit_filesystem_provenance(tmp_path: Path) -> None:
    mtime = datetime(2026, 9, 8, 10, 15, 32, tzinfo=timezone.utc)
    result = extract_timestamp({}, tmp_path / "video.mp4", mtime)
    assert result["timestamp"] == mtime.isoformat()
    assert result["source"] == "filesystem_mtime"
    assert result["confidence"] == "low"


def test_missing_timestamp_is_unknown() -> None:
    result = extract_timestamp({}, "random_video_12345.mp4")
    assert result == {"timestamp": None, "source": "unknown", "confidence": "none", "timezone": "unknown"}


def test_camera_identification_is_conservative() -> None:
    assert extract_camera_id("CAM01_20260908_101532.mp4") == "CAM01"
    assert extract_camera_id("CHANNEL02_video.mp4") == "CHANNEL02"
    assert extract_camera_id("random_video_12345.mp4") == "UNKNOWN"
    assert extract_camera_id("video.mp4", {"camera_id": "cam03"}) == "CAM03"
