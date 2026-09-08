from datetime import datetime, timezone
from uuid import uuid4


class TimelineAnalyzer:
    def build(self, events: list[dict[str, object]]) -> list[dict[str, object]]:
        result = self.build_result(events)
        return result["events"] + result["unknown_timestamp_events"]

    def build_result(self, events: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
        known = []
        unknown = []
        for event in events:
            timestamp = event.get("timestamp")
            normalized = {
                "event_id": str(event.get("event_id", uuid4())),
                "camera_id": event.get("camera_id") or "UNKNOWN",
                "timestamp": str(timestamp),
                "timestamp_source": event.get("timestamp_source", "unknown"),
                "timestamp_confidence": event.get("timestamp_confidence", "none"),
                "event_type": str(event.get("event_type", "unknown")),
                "description": str(event.get("description", "")),
                "evidence_path": event.get("evidence_path", event.get("source", "unknown")),
                "timezone": event.get("timezone", "unknown"),
            } if timestamp else {
                "event_id": str(event.get("event_id", uuid4())),
                "camera_id": event.get("camera_id") or "UNKNOWN",
                "timestamp": None,
                "timestamp_source": "unknown",
                "timestamp_confidence": "none",
                "event_type": str(event.get("event_type", "unknown")),
                "description": str(event.get("description", "")),
                "evidence_path": event.get("evidence_path", event.get("source", "unknown")),
                "timezone": "unknown",
            }
            if normalized["timestamp"]:
                known.append(normalized)
            else:
                unknown.append(normalized)
        return {
            "events": sorted(known, key=lambda event: _sort_key(str(event["timestamp"]))),
            "unknown_timestamp_events": unknown,
        }


def _sort_key(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return float("inf")


def build_timeline(events: list[dict[str, object]]) -> list[dict[str, object]]:
    return TimelineAnalyzer().build(events)
