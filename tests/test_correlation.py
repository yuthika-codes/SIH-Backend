from app.forensic_engine.correlation import correlate_events


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
