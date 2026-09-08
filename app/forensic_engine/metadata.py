import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _number_or_none(value: object) -> int | float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def _frame_rate(value: object) -> float | None:
    if not isinstance(value, str) or "/" not in value:
        result = _number_or_none(value)
        return float(result) if result is not None else None
    numerator, denominator = value.split("/", 1)
    try:
        return float(numerator) / float(denominator)
    except (ValueError, ZeroDivisionError):
        return None


def _stream_metadata(stream: dict[str, Any], stream_type: str) -> dict[str, object]:
    if stream_type == "video":
        return {
            "codec_name": stream.get("codec_name"),
            "codec_long_name": stream.get("codec_long_name"),
            "profile": stream.get("profile"),
            "width": stream.get("width"),
            "height": stream.get("height"),
            "pixel_format": stream.get("pix_fmt"),
            "frame_rate": _frame_rate(stream.get("r_frame_rate")),
            "average_frame_rate": _frame_rate(stream.get("avg_frame_rate")),
            "bit_rate": _number_or_none(stream.get("bit_rate")),
            "frame_count": _number_or_none(stream.get("nb_frames")),
            "stream_start_time": _number_or_none(stream.get("start_time")),
            "stream_duration": _number_or_none(stream.get("duration")),
        }
    return {
        "codec_name": stream.get("codec_name"),
        "codec_long_name": stream.get("codec_long_name"),
        "sample_rate": _number_or_none(stream.get("sample_rate")),
        "channels": stream.get("channels"),
        "bit_rate": _number_or_none(stream.get("bit_rate")),
        "stream_start_time": _number_or_none(stream.get("start_time")),
        "stream_duration": _number_or_none(stream.get("duration")),
    }


def extract_metadata(path: str | Path, *, probe_executable: str = "ffprobe", timeout: float = 30.0) -> dict[str, object]:
    file = Path(path)
    if not file.exists():
        return {"probe_status": "error", "input_path": str(file), "error": "File does not exist"}
    if not file.is_file():
        return {"probe_status": "error", "input_path": str(file), "error": "Path is not a file"}
    try:
        file_size = file.stat().st_size
    except (OSError, PermissionError) as exc:
        return {"probe_status": "error", "input_path": str(file), "error": str(exc)}
    executable = shutil.which(probe_executable)
    if executable is None:
        return {"probe_status": "error", "input_path": str(file), "error": "FFprobe executable not found"}
    command = [executable, "-v", "error", "-show_format", "-show_streams", "-of", "json", str(file)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except FileNotFoundError:
        return {"probe_status": "error", "input_path": str(file), "error": "FFprobe executable not found"}
    except subprocess.TimeoutExpired:
        return {"probe_status": "error", "input_path": str(file), "error": "FFprobe timed out"}
    except (OSError, PermissionError) as exc:
        return {"probe_status": "error", "input_path": str(file), "error": str(exc)}
    if completed.returncode != 0:
        return {"probe_status": "error", "input_path": str(file), "error": completed.stderr.strip() or "FFprobe failed"}
    try:
        probe = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"probe_status": "error", "input_path": str(file), "error": "Malformed FFprobe JSON output"}
    if not isinstance(probe, dict):
        return {"probe_status": "error", "input_path": str(file), "error": "Malformed FFprobe JSON output"}
    format_data = probe.get("format") if isinstance(probe.get("format"), dict) else {}
    streams = probe.get("streams") if isinstance(probe.get("streams"), list) else []
    video_streams = [_stream_metadata(stream, "video") for stream in streams if isinstance(stream, dict) and stream.get("codec_type") == "video"]
    audio_streams = [_stream_metadata(stream, "audio") for stream in streams if isinstance(stream, dict) and stream.get("codec_type") == "audio"]
    return {
        "probe_status": "success",
        "input_path": str(file),
        "filename": file.name,
        "file_size_bytes": file_size,
        "format_name": format_data.get("format_name"),
        "format_long_name": format_data.get("format_long_name"),
        "duration_seconds": _number_or_none(format_data.get("duration")),
        "bitrate": _number_or_none(format_data.get("bit_rate")),
        "start_time": _number_or_none(format_data.get("start_time")),
        "video_streams": video_streams,
        "audio_streams": audio_streams,
        "container_metadata": format_data.get("tags") if isinstance(format_data.get("tags"), dict) else {},
    }
