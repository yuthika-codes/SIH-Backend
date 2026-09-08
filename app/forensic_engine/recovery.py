import shutil
from pathlib import Path
from uuid import uuid4

from app.forensic_engine.hashing import calculate_file_hashes
from app.forensic_engine.metadata import extract_metadata

SUPPORTED_FORMATS = {"mp4", "avi", "mkv", "mpeg-ts", "h264", "h265"}
EXTENSION_FORMATS = {".mp4": "mp4", ".avi": "avi", ".mkv": "mkv", ".ts": "mpeg-ts", ".h264": "h264", ".h265": "h265", ".265": "h265", ".hevc": "h265"}


def detect_signature(file_path: str | Path) -> dict[str, object]:
    path = Path(file_path)
    try:
        with path.open("rb") as file:
            header = file.read(1024 * 1024)
    except (OSError, PermissionError) as exc:
        return {"detected_format": None, "confidence": "none", "method": "error", "error": str(exc)}
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"AVI ":
        return {"detected_format": "avi", "confidence": "high", "method": "magic_bytes"}
    if len(header) >= 8 and header[:4] == b"\x1a\x45\xdf\xa3":
        return {"detected_format": "mkv", "confidence": "high", "method": "magic_bytes"}
    if len(header) >= 8 and header[4:8] == b"ftyp":
        return {"detected_format": "mp4", "confidence": "high", "method": "magic_bytes"}
    if _looks_like_mpeg_ts(header):
        return {"detected_format": "mpeg-ts", "confidence": "medium", "method": "transport_sync_bytes"}
    if _looks_like_h264(header):
        return {"detected_format": "h264", "confidence": "medium", "method": "annex_b_nal_signature"}
    if _looks_like_h265(header):
        return {"detected_format": "h265", "confidence": "medium", "method": "annex_b_nal_signature"}
    return {"detected_format": None, "confidence": "none", "method": "unknown"}


def _looks_like_mpeg_ts(data: bytes) -> bool:
    return len(data) >= 376 and data[0] == 0x47 and data[188] == 0x47


def _annex_b_nal_types(data: bytes) -> list[int]:
    types = []
    for marker in (b"\x00\x00\x01", b"\x00\x00\x00\x01"):
        offset = 0
        while True:
            offset = data.find(marker, offset)
            if offset < 0 or offset + len(marker) >= len(data):
                break
            types.append(data[offset + len(marker)])
            offset += len(marker)
    return types


def _looks_like_h264(data: bytes) -> bool:
    return any((nal & 0x1F) in {1, 5, 7, 8} for nal in _annex_b_nal_types(data))


def _looks_like_h265(data: bytes) -> bool:
    return any(((nal >> 1) & 0x3F) in {19, 20, 32, 33, 34} for nal in _annex_b_nal_types(data))


def _safe_format_suffix(detected_format: str) -> str:
    return {"mpeg-ts": ".ts", "h264": ".h264", "h265": ".h265"}.get(detected_format, f".{detected_format}")


class RecoveryEngine:
    def __init__(self, acquired_root: str | Path, recovered_root: str | Path) -> None:
        self.acquired_root = Path(acquired_root).resolve()
        self.recovered_root = Path(recovered_root).resolve()

    def recover(self, evidence_path: str | Path) -> dict[str, object]:
        try:
            source = Path(evidence_path).resolve()
            if not source.exists():
                return {"status": "error", "artifacts": [], "error": "Acquired evidence path does not exist"}
            if not self._within(source, self.acquired_root):
                return {"status": "error", "artifacts": [], "error": "Evidence path is outside the forensic image root"}
            candidates = [source] if source.is_file() else [item for item in source.rglob("*") if item.is_file()]
            artifacts = [artifact for candidate in candidates if (artifact := self._inspect_candidate(candidate)) is not None]
            return {"status": "completed", "artifacts": artifacts, "reconstruction": "unsupported"}
        except (OSError, PermissionError) as exc:
            return {"status": "error", "artifacts": [], "error": str(exc)}

    def _inspect_candidate(self, source: Path) -> dict[str, object]:
        signature = detect_signature(source)
        detected_format = signature.get("detected_format")
        extension_format = EXTENSION_FORMATS.get(source.suffix.lower())
        if detected_format is None and extension_format:
            detected_format = extension_format
            signature = {**signature, "detected_format": detected_format, "method": "extension_then_ffprobe"}
        if detected_format not in SUPPORTED_FORMATS:
            return {
                "recovery_id": str(uuid4()), "source_path": str(source), "output_path": None,
                "method": "signature_scan", "detected_format": None, "classification": "UNKNOWN",
                "sha256": None, "size_bytes": source.stat().st_size, "validated": False,
                "validation": "not_attempted", "signature": signature, "reconstruction": "unsupported",
            }
        validation = extract_metadata(source)
        probe_status = validation.get("probe_status")
        if probe_status == "success":
            if validation.get("duration_seconds") is None:
                classification, validation_state = "PARTIALLY_RECOVERABLE", "validated_incomplete"
            else:
                classification, validation_state = "VALID", "validated"
        elif validation.get("error") == "FFprobe executable not found":
            classification, validation_state = "UNKNOWN", "not_available"
        else:
            classification, validation_state = "CORRUPTED", "failed"
        recovery_id = str(uuid4())
        output_path = self._copy_artifact(source, recovery_id, str(detected_format)) if classification != "UNKNOWN" else None
        hashes = calculate_file_hashes(output_path) if output_path else {"sha256": None, "size_bytes": source.stat().st_size}
        return {
            "recovery_id": recovery_id, "source_path": str(source), "output_path": str(output_path) if output_path else None,
            "method": "existing_file_validation" if source.suffix.lower().lstrip(".") == detected_format else "signature_scan",
            "detected_format": detected_format, "classification": classification, "sha256": hashes["sha256"],
            "size_bytes": hashes["size_bytes"], "validated": classification == "VALID", "validation": validation_state,
            "metadata": validation, "signature": signature, "reconstruction": "unsupported",
        }

    def _copy_artifact(self, source: Path, recovery_id: str, detected_format: str) -> Path:
        self.recovered_root.mkdir(parents=True, exist_ok=True)
        safe_stem = "".join(character if character.isalnum() or character in "-_" else "_" for character in source.stem).strip("._") or "artifact"
        target = self.recovered_root / f"{recovery_id}_{safe_stem}{_safe_format_suffix(detected_format)}"
        with source.open("rb") as input_file, target.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
        return target

    @staticmethod
    def _within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False


def recover_deleted(path: str) -> dict[str, object]:
    source = Path(path)
    return RecoveryEngine(source.parent, Path("storage") / "recovered").recover(source)
