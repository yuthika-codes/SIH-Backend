from datetime import datetime, timezone
from pathlib import Path

from app.forensic_engine.correlation import correlate_events
from app.forensic_engine.timestamp import extract_camera_id, extract_filename_timestamp, extract_timestamp
from app.forensic_engine.timeline import TimelineAnalyzer


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


def test_timeline_sorts_known_events_and_separates_unknown() -> None:
    result = TimelineAnalyzer().build_result([
        {"timestamp": None, "camera_id": "UNKNOWN", "event_type": "video_recording"},
        {"timestamp": "2026-09-08T10:15:34", "timestamp_source": "filename", "timestamp_confidence": "medium", "camera_id": "CAM02"},
        {"timestamp": "2026-09-08T10:15:30", "timestamp_source": "container_metadata", "timestamp_confidence": "high", "camera_id": "CAM01"},
    ])
    assert [event["camera_id"] for event in result["events"]] == ["CAM01", "CAM02"]
    assert len(result["unknown_timestamp_events"]) == 1


def test_multi_camera_events_within_tolerance_correlate() -> None:
    events = [
        {"timestamp": "2026-09-08T10:15:30", "timestamp_source": "filename", "camera_id": "CAM01"},
        {"timestamp": "2026-09-08T10:15:34", "timestamp_source": "container_metadata", "camera_id": "CAM02"},
        {"timestamp": "2026-09-08T10:15:31", "timestamp_source": "filename", "camera_id": "CAM03"},
    ]
    result = correlate_events(events, tolerance_seconds=5)
    assert len(result) == 1
    assert result[0]["cameras"] == ["CAM01", "CAM02", "CAM03"]
    assert result[0]["event_count"] == 3


def test_events_outside_tolerance_and_unknown_do_not_correlate() -> None:
    events = [
        {"timestamp": "2026-09-08T10:15:30", "timestamp_source": "filename", "camera_id": "CAM01"},
        {"timestamp": "2026-09-08T10:15:36", "timestamp_source": "filename", "camera_id": "CAM02"},
        {"timestamp": None, "timestamp_source": "unknown", "camera_id": "CAM03"},
        {"timestamp": "2026-09-08T10:15:32", "timestamp_source": "filesystem_mtime", "camera_id": "CAM04"},
    ]
    assert correlate_events(events, tolerance_seconds=5) == []