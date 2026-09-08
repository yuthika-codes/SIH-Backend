from datetime import datetime


class TimelineAnalyzer:
    def build(self, events: list[dict[str, object]]) -> list[dict[str, object]]:
        normalized = []
        for event in events:
            timestamp = event.get("timestamp")
            if not timestamp:
                continue
            normalized.append({
                "timestamp": str(timestamp),
                "source": str(event.get("source", "unknown")),
                "camera_id": event.get("camera_id"),
                "event_type": str(event.get("event_type", "unknown")),
                "description": str(event.get("description", "")),
                "timezone": event.get("timezone", "unknown"),
            })
        return sorted(normalized, key=lambda event: _sort_key(str(event["timestamp"])))


def _sort_key(value: str) -> tuple[int, datetime | str]:
    try:
        return (0, datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return (1, value)


def build_timeline(events: list[dict[str, object]]) -> list[dict[str, object]]:
    return TimelineAnalyzer().build(events)
