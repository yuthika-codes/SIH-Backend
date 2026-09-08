import mimetypes
import re
from pathlib import Path
from typing import Any


VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".webm", ".ts", ".m2ts", ".h264", ".h265", ".265", ".hevc", ".dav"}
VENDOR_RULES = {
    "Dahua": ("dahua", "dhav", "dahua technology"),
    "Hikvision": ("hikvision", "hikvis", "hik-connect"),
    "CP Plus": ("cp plus", "cp-plus", "cpplus"),
    "Honeywell": ("honeywell", "honeywell security"),
    "TP-Link": ("tp-link", "tplink", "tapo"),
    "Godrej": ("godrej", "godrej security"),
    "Uniview": ("uniview", "uniarch"),
    "Matrix": ("matrix", "matrix comsec"),
}
MODEL_PATTERN = re.compile(r"(?:model|device[ _-]*model|product[ _-]*model)[ :=_-]+([A-Z0-9][A-Z0-9._-]{2,})", re.IGNORECASE)
CONTAINER_NAMES = {"mp4", "avi", "matroska", "webm", "mpegts"}


class DeviceIdentifier:
    """Read-only, explainable device/vendor indicator detector.

    Detection is an evidence summary, not proof of proprietary parsing support.
    """

    def identify(
        self,
        evidence_path: str | Path,
        metadata: dict[str, Any] | None = None,
        filesystem: dict[str, Any] | None = None,
    ) -> dict[str, object]:
        path = Path(evidence_path)
        filename = path.name
        extension = path.suffix.lower()
        mime_type = mimetypes.guess_type(filename)[0]
        evidence_type, device_type = self._classify_type(path, extension, mime_type)
        indicators: list[dict[str, object]] = []
        filename_text = filename.lower()
        binary_text = self._read_binary_text(path)
        vendor_candidates: dict[str, list[str]] = {}

        for vendor, markers in VENDOR_RULES.items():
            filename_matches = [marker for marker in markers if marker in filename_text]
            binary_matches = [marker for marker in markers if marker in binary_text]
            if filename_matches:
                vendor_candidates.setdefault(vendor, []).append("filename indicator")
                indicators.append({"vendor": vendor, "layer": "filename", "strength": "weak", "markers": filename_matches})
            if binary_matches:
                vendor_candidates.setdefault(vendor, []).append("binary marker")
                indicators.append({"vendor": vendor, "layer": "binary", "strength": "medium", "markers": binary_matches})

        metadata_vendor = self._metadata_vendor(metadata)
        if metadata_vendor:
            vendor_candidates.setdefault(metadata_vendor, []).append("metadata marker")
            indicators.append({"vendor": metadata_vendor, "layer": "metadata", "strength": "strong", "markers": [metadata_vendor]})

        filesystem_vendor = self._filesystem_vendor(filesystem)
        if filesystem_vendor:
            vendor_candidates.setdefault(filesystem_vendor, []).append("filesystem indicator")
            indicators.append({"vendor": filesystem_vendor, "layer": "filesystem", "strength": "medium", "markers": [filesystem_vendor]})

        vendor, evidence_sources = self._choose_vendor(vendor_candidates)
        model = self._extract_model(metadata, binary_text) if vendor != "Unknown" else "Unknown"
        confidence = self._confidence(vendor, evidence_sources)
        matched_indicators = [f"{item['vendor']} {item['layer']} marker" for item in indicators if item["vendor"] == vendor]
        detection_method = "combined_indicators" if len(evidence_sources) > 1 else ("binary_marker" if evidence_sources == ["binary marker"] else "filename_indicator" if evidence_sources == ["filename indicator"] else "generic_fallback")
        return {
            "filename": filename,
            "extension": extension,
            "mime_type": mime_type,
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "evidence_type": evidence_type,
            "confidence": confidence,
            "detection_method": detection_method,
            "matched_indicators": matched_indicators,
            "details": {
                "evidence_strength": self._strength(confidence),
                "model_detection": "explicit_metadata_or_marker" if model != "Unknown" else "not_available",
                "indicators": indicators,
                "format_indicator": extension or (mime_type or "Unknown"),
            },
        }

    @staticmethod
    def _read_binary_text(path: Path) -> str:
        if not path.is_file():
            return ""
        try:
            return path.read_bytes()[:1024 * 1024].decode("latin-1", errors="ignore").lower()
        except (OSError, PermissionError):
            return ""

    @staticmethod
    def _classify_type(path: Path, extension: str, mime_type: str | None) -> tuple[str, str]:
        if path.is_dir():
            return "directory", "raw forensic evidence"
        if extension in VIDEO_EXTENSIONS or (mime_type or "").startswith("video/"):
            lower_name = path.name.lower()
            if any(token in lower_name for token in ("dvr", "nvr", "channel", "ch01", "cam")):
                return "video", "camera/IP camera"
            return "video", "video file"
        if extension in {".img", ".dd", ".raw", ".bin"}:
            return "raw evidence", "raw forensic evidence"
        return "file", "unknown"

    @staticmethod
    def _metadata_vendor(metadata: dict[str, Any] | None) -> str | None:
        if not metadata:
            return None
        values = [metadata.get(key) for key in ("format_name", "format_long_name", "encoder", "vendor", "manufacturer")]
        text = " ".join(str(value).lower() for value in values if value)
        return next((vendor for vendor, markers in VENDOR_RULES.items() if any(marker in text for marker in markers)), None)

    @staticmethod
    def _filesystem_vendor(filesystem: dict[str, Any] | None) -> str | None:
        if not filesystem:
            return None
        text = str(filesystem).lower()
        return next((vendor for vendor, markers in VENDOR_RULES.items() if any(marker in text for marker in markers)), None)

    @staticmethod
    def _choose_vendor(candidates: dict[str, list[str]]) -> tuple[str, list[str]]:
        if not candidates:
            return "Unknown", []
        vendor, sources = max(candidates.items(), key=lambda item: (len(set(item[1])), len(item[1])))
        unique_sources = list(dict.fromkeys(sources))
        if len(unique_sources) == 1 and unique_sources[0] == "filename indicator":
            return vendor, unique_sources
        return vendor, unique_sources

    @staticmethod
    def _confidence(vendor: str, sources: list[str]) -> int:
        if vendor == "Unknown":
            return 0
        weights = {"filename indicator": 20, "binary marker": 45, "metadata marker": 65, "filesystem indicator": 35}
        score = min(100, sum(weights.get(source, 0) for source in sources) + max(0, len(sources) - 1) * 10)
        return score

    @staticmethod
    def _strength(confidence: int) -> str:
        if confidence >= 80:
            return "high"
        if confidence >= 60:
            return "medium-high"
        if confidence >= 35:
            return "medium"
        if confidence > 0:
            return "low"
        return "none"

    @staticmethod
    def _extract_model(metadata: dict[str, Any] | None, binary_text: str) -> str:
        values = [str(value) for value in (metadata or {}).values() if isinstance(value, str)]
        match = MODEL_PATTERN.search(" ".join(values)) or MODEL_PATTERN.search(binary_text)
        return match.group(1).upper() if match else "Unknown"


def identify_device(path: str | Path) -> dict[str, object]:
    return DeviceIdentifier().identify(path)
