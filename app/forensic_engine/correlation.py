from datetime import datetime, timezone
from uuid import uuid4


RELIABLE_SOURCES = {"container_metadata", "filename"}


def correlate(records: list[dict[str, object]], key: str) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for record in records:
        value = str(record.get(key, "unknown"))
        result.setdefault(value, []).append(record)
    return result


def correlate_events(events: list[dict[str, object]], tolerance_seconds: int = 5) -> list[dict[str, object]]:
    candidates = []
    for event in events:
        if event.get("timestamp_source") not in RELIABLE_SOURCES:
            continue
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is not None:
            candidates.append((timestamp, event))
    candidates.sort(key=lambda item: item[0])
    groups: list[list[tuple[datetime, dict[str, object]]]] = []
    for timestamp, event in candidates:
        if not groups or (timestamp - groups[-1][0][0]).total_seconds() > tolerance_seconds:
            groups.append([(timestamp, event)])
        else:
            groups[-1].append((timestamp, event))
    correlations = []
    for group in groups:
        cameras = sorted({str(event.get("camera_id", "UNKNOWN")) for _, event in group})
        if len(cameras) < 2:
            continue
        correlations.append({
            "correlation_id": str(uuid4()),
            "start_time": group[0][0].isoformat(),
            "end_time": group[-1][0].isoformat(),
            "cameras": cameras,
            "event_count": len(group),
            "time_window_seconds": tolerance_seconds,
        })
    return correlations


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
