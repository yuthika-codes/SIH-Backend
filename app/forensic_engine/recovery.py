import shutil
from pathlib import Path
from uuid import uuid4

from app.forensic_engine.hashing import calculate_file_hashes
from app.forensic_engine.metadata import extract_metadata

SUPPORTED_FORMATS = {"mp4", "avi", "mkv", "mpeg-ts", "h264", "h265"}
EXTENSION_FORMATS = {".mp4": "mp4", ".avi": "avi", ".mkv": "mkv", ".ts": "mpeg-ts", ".h264": "h264", ".h265": "h265", ".265": "h265", ".hevc": "h265"}
MP4_BOX_TYPES = {"ftyp", "styp", "moov", "mdat", "free", "skip", "wide", "uuid", "sidx", "mfra", "moof", "mvex", "edts", "trak", "meta"}
SCAN_CHUNK_SIZE = 1024 * 1024
MAX_CARVED_BYTES = 512 * 1024 * 1024


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


def _parse_mp4_box(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 8 > len(data):
        return None
    size = int.from_bytes(data[offset:offset + 4], "big")
    box_type = data[offset + 4:offset + 8]
    header_size = 8
    if size == 1:
        if offset + 16 > len(data):
            return None
        size = int.from_bytes(data[offset + 8:offset + 16], "big")
        header_size = 16
    elif size == 0:
        size = len(data) - offset
    if size < header_size or offset + size > len(data) or box_type.decode("ascii", errors="ignore") not in MP4_BOX_TYPES:
        return None
    return size, header_size


def _find_mp4_signatures(data: bytes) -> list[tuple[int, int]]:
    candidates: list[tuple[int, int]] = []
    search_from = 0
    while True:
        ftyp_offset = data.find(b"ftyp", search_from)
        if ftyp_offset < 0:
            return candidates
        container_offset = ftyp_offset - 4
        parsed = _parse_mp4_box(data, container_offset)
        if parsed and data[container_offset + 4:container_offset + 8] == b"ftyp":
            box_size = parsed[0]
            payload = data[container_offset + parsed[1] + 4:container_offset + box_size]
            if len(payload) >= 8 and any(32 <= value < 127 for value in payload[:8]):
                candidates.append((container_offset, _estimate_mp4_end(data, container_offset)))
        search_from = ftyp_offset + 4


def _estimate_mp4_end(data: bytes, start: int) -> int:
    offset = start
    while True:
        parsed = _parse_mp4_box(data, offset)
        if parsed is None:
            return offset
        offset += parsed[0]
        if offset - start >= MAX_CARVED_BYTES or offset >= len(data):
            return min(offset, start + MAX_CARVED_BYTES, len(data))


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
            artifacts = []
            for candidate in candidates:
                artifacts.extend(self._recover_file(candidate))
            return {"status": "completed", "artifacts": artifacts, "reconstruction": "unsupported"}
        except (OSError, PermissionError) as exc:
            return {"status": "error", "artifacts": [], "error": str(exc)}

    def _recover_file(self, source: Path) -> list[dict[str, object]]:
        signature = detect_signature(source)
        extension_format = EXTENSION_FORMATS.get(source.suffix.lower())
        data = source.read_bytes()
        mp4_regions = _find_mp4_signatures(data)
        if mp4_regions and (source.suffix.lower() not in EXTENSION_FORMATS or mp4_regions[0][0] != 0):
            return [self._inspect_carved_region(source, offset, "mp4", end - offset, method="signature_carving") for offset, end in mp4_regions]
        if signature.get("detected_format"):
            return [self._inspect_candidate(source, offset=0, method="existing_file_validation")]
        regions = self._scan_regions(source)
        if regions:
            return [self._inspect_carved_region(source, offset, detected_format, size, method="signature_carving") for offset, detected_format, size in regions]
        if extension_format:
            return [self._inspect_candidate(source, offset=0, method="existing_file_validation")]
        return [self._inspect_candidate(source, offset=0, method="signature_scan")]

    def _inspect_candidate(self, source: Path, *, offset: int, method: str) -> dict[str, object]:
        signature = detect_signature(source)
        detected_format = signature.get("detected_format")
        extension_format = EXTENSION_FORMATS.get(source.suffix.lower())
        if detected_format is None and extension_format:
            detected_format = extension_format
            signature = {**signature, "detected_format": detected_format, "method": "extension_then_ffprobe"}
        if detected_format not in SUPPORTED_FORMATS:
            return {
                "recovery_id": str(uuid4()), "source_path": str(source), "output_path": None,
                    "source_offset": offset, "method": method, "detected_format": None, "classification": "UNKNOWN",
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
            "source_offset": offset,
            "method": method if method != "existing_file_validation" else ("existing_file_validation" if source.suffix.lower().lstrip(".") == detected_format else "signature_scan"),
            "detected_format": detected_format, "classification": classification, "sha256": hashes["sha256"],
            "size_bytes": hashes["size_bytes"], "md5": hashes.get("md5"), "validated": classification == "VALID", "validation": validation_state,
            "metadata": validation, "signature": signature, "reconstruction": "unsupported",
        }

    def _scan_regions(self, source: Path) -> list[tuple[int, str, int]]:
        data = source.read_bytes()
        regions: list[tuple[int, str, int]] = []
        mp4_regions = _find_mp4_signatures(data)
        regions.extend((start, "mp4", end - start) for start, end in mp4_regions)
        for marker, detected_format in ((b"RIFF", "avi"), (b"\x1a\x45\xdf\xa3", "mkv")):
            for start in self._find_offsets(data, marker):
                if detected_format == "avi" and data[start + 8:start + 12] != b"AVI ":
                    continue
                size = int.from_bytes(data[start + 4:start + 8], "little") + 8 if detected_format == "avi" and start + 8 <= len(data) else 0
                length = size if 8 <= size <= MAX_CARVED_BYTES and start + size <= len(data) else min(MAX_CARVED_BYTES, len(data) - start)
                regions.append((start, detected_format, length))
        for start in range(0, max(0, len(data) - 187), 188):
            if data[start] == 0x47 and data[start + 188] == 0x47:
                regions.append((start, "mpeg-ts", min(MAX_CARVED_BYTES, len(data) - start)))
        mp4_ranges = [(start, end) for start, end in mp4_regions]
        for marker, detected_format in ((b"\x00\x00\x01", "h264"), (b"\x00\x00\x00\x01", "h265")):
            for start in self._find_offsets(data, marker):
                if any(region_start <= start < region_end for region_start, region_end in mp4_ranges):
                    continue
                fragment = data[start:start + min(MAX_CARVED_BYTES, len(data) - start)]
                if (detected_format == "h264" and _looks_like_h264(fragment)) or (detected_format == "h265" and _looks_like_h265(fragment)):
                    regions.append((start, detected_format, len(fragment)))
        unique: dict[tuple[int, str], tuple[int, str, int]] = {}
        for region in regions:
            unique[(region[0], region[1])] = region
        return sorted(unique.values())

    @staticmethod
    def _find_offsets(data: bytes, marker: bytes) -> list[int]:
        offsets = []
        start = 0
        while True:
            index = data.find(marker, start)
            if index < 0:
                return offsets
            offsets.append(index)
            start = index + 1

    def _inspect_carved_region(self, source: Path, offset: int, detected_format: str, size: int, method: str = "signature_scan") -> dict[str, object]:
        recovery_id = str(uuid4())
        target = self.recovered_root / f"{recovery_id}_offset_{offset}{_safe_format_suffix(detected_format)}"
        self.recovered_root.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_file, target.open("xb") as output_file:
            input_file.seek(offset)
            remaining = size
            while remaining > 0:
                chunk = input_file.read(min(SCAN_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                output_file.write(chunk)
                remaining -= len(chunk)
        artifact = self._inspect_candidate(target, offset=offset, method=method)
        artifact["source_path"] = str(source)
        artifact["output_path"] = str(target)
        artifact["source_offset"] = offset
        artifact["recovery_id"] = recovery_id
        artifact["method"] = method
        hashes = calculate_file_hashes(target)
        artifact["sha256"] = hashes["sha256"]
        artifact["md5"] = hashes["md5"]
        artifact["size_bytes"] = hashes["size_bytes"]
        return artifact

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
