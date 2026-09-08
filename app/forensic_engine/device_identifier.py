import mimetypes
from pathlib import Path


VENDOR_MARKERS = {
    "dahua": "Dahua",
    "hikvision": "Hikvision",
    "cpplus": "CP Plus",
    "cp-plus": "CP Plus",
    "uniview": "Uniview",
    "honeywell": "Honeywell",
    "matrix": "Matrix",
}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".h264", ".h265", ".dav"}


class DeviceIdentifier:
    def identify(self, evidence_path: str | Path) -> dict[str, object]:
        path = Path(evidence_path)
        filename = path.name
        extension = path.suffix.lower()
        mime_type = mimetypes.guess_type(filename)[0]
        evidence_type = "directory" if path.is_dir() else "video" if extension in VIDEO_EXTENSIONS or (mime_type or "").startswith("video/") else "file"

        for marker, vendor in VENDOR_MARKERS.items():
            if marker in filename.lower() or marker in str(path.parent).lower():
                return {
                    "filename": filename,
                    "extension": extension,
                    "mime_type": mime_type,
                    "vendor": vendor,
                    "confidence": 0.85,
                    "evidence_type": evidence_type,
                    "detection_method": "filename/path marker",
                    "details": {},
                }
        return {
            "filename": filename,
            "extension": extension,
            "mime_type": mime_type,
            "vendor": "Unknown",
            "confidence": 0.0,
            "evidence_type": evidence_type,
            "detection_method": "generic fallback",
            "details": {},
        }


def identify_device(path: str | Path) -> dict[str, object]:
    return DeviceIdentifier().identify(path)
