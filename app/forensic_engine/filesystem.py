from pathlib import Path
import mimetypes

VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".h264", ".h265", ".ts", ".m2ts", ".dav"}
METADATA_EXTENSIONS = {".json", ".xml", ".csv", ".txt", ".log"}


class FileSystemAnalyzer:
    def analyze(self, evidence_path: str | Path) -> dict[str, object]:
        path = Path(evidence_path)
        if not path.exists():
            return {"status": "error", "error": "Evidence path does not exist", "path": str(path)}
        try:
            if path.is_file():
                stat = path.stat()
                return {
                    "status": "supported",
                    "path": str(path),
                    "kind": "file",
                    "size_bytes": stat.st_size,
                    "extension": path.suffix.lower(),
                    "file_type": mimetypes.guess_type(path.name)[0],
                    "number_of_files": 1,
                    "candidate_video_files": [str(path)] if path.suffix.lower() in VIDEO_EXTENSIONS else [],
                    "candidate_metadata_files": [str(path)] if path.suffix.lower() in METADATA_EXTENSIONS else [],
                    "container_indicators": [],
                }
            files = [child for child in path.rglob("*") if child.is_file()]
            videos = [str(file) for file in files if file.suffix.lower() in VIDEO_EXTENSIONS]
            metadata = [str(file) for file in files if file.suffix.lower() in METADATA_EXTENSIONS]
            return {
                "status": "supported",
                "path": str(path),
                "kind": "directory",
                "size_bytes": sum(file.stat().st_size for file in files),
                "extension": None,
                "file_type": "directory",
                "number_of_files": len(files),
                "candidate_video_files": videos,
                "candidate_metadata_files": metadata,
                "container_indicators": [],
            }
        except (OSError, PermissionError) as exc:
            return {"status": "error", "path": str(path), "error": str(exc)}


def inventory(root: str) -> list[str]:
    return [str(path) for path in Path(root).rglob("*") if path.is_file()]
