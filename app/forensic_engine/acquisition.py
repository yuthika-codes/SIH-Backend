import shutil
from pathlib import Path
from uuid import uuid4

from app.forensic_engine.hashing import calculate_file_hashes, verify_sha256
from app.services.storage import ROOT, ensure_storage


class AcquisitionService:
    def acquire(self, evidence_path: str | Path, destination_dir: str | Path | None = None) -> dict[str, object]:
        source = Path(evidence_path)
        if not source.exists():
            return {"status": "error", "error": "Evidence path does not exist", "path": str(source)}
        if not source.is_file():
            return {"status": "unsupported", "error": "Directory acquisition requires a validated container workflow", "path": str(source)}
        try:
            original = calculate_file_hashes(source)
            ensure_storage()
            target_dir = Path(destination_dir) if destination_dir else ROOT / "forensic_images"
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / f"{uuid4()}_{source.name}"
            with source.open("rb") as input_file, target.open("wb") as output_file:
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            acquired = calculate_file_hashes(target)
            integrity_verified = verify_sha256(target, str(original["sha256"]))
            return {
                "status": "completed" if integrity_verified else "INTEGRITY_COMPROMISED",
                "source_path": str(source),
                "acquired_path": str(target),
                "original_sha256": original["sha256"],
                "original_md5": original["md5"],
                "size_bytes": original["size_bytes"],
                "acquired_sha256": acquired["sha256"],
                "integrity_verified": integrity_verified,
                "integrity_status": "VERIFIED" if integrity_verified else "INTEGRITY_COMPROMISED",
            }
        except (OSError, PermissionError) as exc:
            return {"status": "error", "path": str(source), "error": str(exc)}


def acquire(source: str, destination: str) -> str:
    """Backward-compatible copy helper used by older callers."""
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open("rb") as input_file, target.open("wb") as output_file:
        shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
    return str(target)
