import shutil
import subprocess
from pathlib import Path

SUPPORTED_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".h264", ".h265", ".ts", ".m2ts", ".webm"}


class VideoExtractor:
    def extract(self, video_paths: list[str | Path], output_dir: str | Path) -> list[dict[str, object]]:
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        return [self._extract_one(Path(path), destination) for path in video_paths]

    def _extract_one(self, source: Path, destination: Path) -> dict[str, object]:
        extension = source.suffix.lower()
        if extension == ".dav" or extension not in SUPPORTED_EXTENSIONS:
            return {"status": "unsupported", "source": str(source), "format": extension, "message": "Proprietary or unsupported format requires a validated parser."}
        if not source.exists():
            return {"status": "error", "source": str(source), "error": "Video file does not exist"}
        output = destination / source.name
        ffmpeg = shutil.which("ffmpeg")
        try:
            if not ffmpeg:
                return {"status": "unsupported", "source": str(source), "format": extension, "message": "FFmpeg is required to validate and extract this video format."}
            command = [ffmpeg, "-y", "-i", str(source), "-c", "copy", str(output)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            if completed.returncode != 0:
                return {"status": "error", "source": str(source), "format": extension, "error": completed.stderr[-1000:]}
            return {"status": "completed", "source": str(source), "output_path": str(output), "format": extension}
        except (OSError, PermissionError) as exc:
            return {"status": "error", "source": str(source), "format": extension, "error": str(exc)}


def extract_video_frames(path: str, output_dir: str) -> dict[str, str | object]:
    return VideoExtractor().extract([path], output_dir)[0]
