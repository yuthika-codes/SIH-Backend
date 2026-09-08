import re
from datetime import datetime
from pathlib import Path
from typing import Any

FILENAME_PATTERNS = (
    re.compile(r"(?<!\d)(\d{8})[_-](\d{6})(?!\d)"),
    re.compile(r"(?<!\d)(\d{4}-\d{2}-\d{2})[ _-](\d{2})[-:](\d{2})[-:](\d{2})(?!\d)"),
)
CONTAINER_KEYS = (
    "creation_time",
    "creation_date",
    "recording_time",
    "recorded_at",
    "timestamp",
    "date",
    "encoded_date",
    "com.apple.quicktime.creationdate",
)


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(value.strip(), pattern)
            except ValueError:
                continue
    return None


def _timestamp_value(value: object) -> str | None:
    parsed = _parse_datetime(value)
    return parsed.isoformat() if parsed else None


def extract_filename_timestamp(path: str | Path) -> dict[str, object]:
    name = Path(path).stem
    match = FILENAME_PATTERNS[0].search(name)
    if match:
        try:
            value = datetime.strptime(f"{match.group(1)}_{match.group(2)}", "%Y%m%d_%H%M%S")
            return {"timestamp": value.isoformat(), "source": "filename", "confidence": "medium", "timezone": "unknown"}
        except ValueError:
            pass
    match = FILENAME_PATTERNS[1].search(name)
    if match:
        try:
            value = datetime.strptime(" ".join(match.groups()), "%Y-%m-%d %H %M %S")
            return {"timestamp": value.isoformat(), "source": "filename", "confidence": "medium", "timezone": "unknown"}
        except ValueError:
            pass
    return {"timestamp": None, "source": "unknown", "confidence": "none", "timezone": "unknown"}


def extract_timestamp(metadata: dict[str, Any] | None, path: str | Path, filesystem_mtime: datetime | None = None) -> dict[str, object]:
    metadata = metadata or {}
    containers: dict[str, object] = {}
    containers.update({key: metadata.get(key) for key in CONTAINER_KEYS if key in metadata})
    raw_container = metadata.get("container_metadata")
    if isinstance(raw_container, dict):
        containers.update(raw_container)
    raw_format = metadata.get("format")
    if isinstance(raw_format, dict) and isinstance(raw_format.get("tags"), dict):
        containers.update(raw_format["tags"])
    for key in CONTAINER_KEYS:
        timestamp = _timestamp_value(containers.get(key))
        if timestamp:
            parsed = _parse_datetime(containers[key])
            return {
                "timestamp": timestamp,
                "source": "container_metadata",
                "confidence": "high",
                "timezone": "known" if parsed and parsed.tzinfo else "unknown",
            }
    filename_result = extract_filename_timestamp(path)
    if filename_result["timestamp"]:
        return filename_result
    if filesystem_mtime is not None:
        return {
            "timestamp": filesystem_mtime.isoformat(),
            "source": "filesystem_mtime",
            "confidence": "low",
            "timezone": "known" if filesystem_mtime.tzinfo else "unknown",
        }
    return {"timestamp": None, "source": "unknown", "confidence": "none", "timezone": "unknown"}


def extract_camera_id(path: str | Path, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    for key in ("camera_id", "camera", "channel", "channel_id"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    match = re.search(r"(?<![A-Z])((?:CAM(?:ERA)?|CH(?:ANNEL)?)\s*\d+)(?!\d)", Path(path).stem.upper())
    if match:
        return re.sub(r"\s+", "", match.group(1))
    return "UNKNOWN"
