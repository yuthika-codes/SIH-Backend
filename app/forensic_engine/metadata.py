from pathlib import Path
import json
import shutil
import subprocess
from datetime import datetime, timezone


def _ffprobe_metadata(path: Path) -> dict[str, object]:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        return {}
    command = [ffprobe, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(path)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return {}
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}


def extract_metadata(path: str) -> dict[str, object]:
    file = Path(path)
    if not file.exists():
        return {"status": "error", "path": str(file), "error": "File does not exist"}
    try:
        stat = file.stat()
        probe = _ffprobe_metadata(file)
        format_data = probe.get("format", {})
        stream = next((item for item in probe.get("streams", []) if item.get("codec_type") == "video"), {})
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        return {
            "status": "completed",
            "filename": file.name,
            "file_size": stat.st_size,
            "format": format_data.get("format_name") or file.suffix.lower().lstrip("."),
            "duration": _number_or_none(format_data.get("duration")),
            "width": stream.get("width"),
            "height": stream.get("height"),
            "frame_rate": _frame_rate(stream.get("r_frame_rate")),
            "codec": stream.get("codec_name"),
            "creation_time": format_data.get("tags", {}).get("creation_time"),
            "modification_time": modified,
            "timezone": "UTC for filesystem timestamp; media timezone unknown",
        }
    except (OSError, PermissionError) as exc:
        return {"status": "error", "path": str(file), "error": str(exc)}


def _number_or_none(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _frame_rate(value: object) -> float | None:
    if not isinstance(value, str) or "/" not in value:
        return _number_or_none(value)
    numerator, denominator = value.split("/", 1)
    try:
        return float(numerator) / float(denominator)
    except (ValueError, ZeroDivisionError):
        return None
