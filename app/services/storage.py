import hashlib
import os
from pathlib import Path

ROOT = Path(os.getenv("STORAGE_ROOT", "storage"))
BUCKETS = ("evidence", "forensic_images", "extracted", "recovered", "reports")


def ensure_storage() -> None:
    for bucket in BUCKETS:
        (ROOT / bucket).mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
