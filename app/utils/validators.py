import re

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def is_sha256(value: str) -> bool:
    return bool(SHA256_PATTERN.fullmatch(value))
