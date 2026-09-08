from app.forensic_engine.timeline import TimelineAnalyzer


def test_timeline_sorts_known_events_and_separates_unknown() -> None:
    result = TimelineAnalyzer().build_result([
        {"timestamp": None, "camera_id": "UNKNOWN", "event_type": "video_recording"},
        {"timestamp": "2026-09-08T10:15:34", "timestamp_source": "filename", "timestamp_confidence": "medium", "camera_id": "CAM02"},
        {"timestamp": "2026-09-08T10:15:30", "timestamp_source": "container_metadata", "timestamp_confidence": "high", "camera_id": "CAM01"},
    ])
    assert [event["camera_id"] for event in result["events"]] == ["CAM01", "CAM02"]
    assert len(result["unknown_timestamp_events"]) == 1
