import hashlib
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024


def _update_digest(file: BinaryIO, digest: "hashlib._Hash") -> None:
    for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
        digest.update(chunk)


def calculate_md5(file_path: str | Path) -> str:
    digest = hashlib.md5()
    with Path(file_path).open("rb") as file:
        _update_digest(file, digest)
    return digest.hexdigest()


def calculate_sha256(file_path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(file_path).open("rb") as file:
        _update_digest(file, digest)
    return digest.hexdigest()


def calculate_file_hashes(file_path: str | Path) -> dict[str, str | int]:
    path = Path(file_path)
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            md5.update(chunk)
            sha256.update(chunk)
            size_bytes += len(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest(), "size_bytes": size_bytes}


def verify_sha256(file_path: str | Path, expected_hash: str) -> bool:
    return calculate_sha256(file_path).lower() == expected_hash.strip().lower()


def sha256(path: str | Path) -> str:
    """Backward-compatible alias for the primary integrity hash."""
    return calculate_sha256(path)
