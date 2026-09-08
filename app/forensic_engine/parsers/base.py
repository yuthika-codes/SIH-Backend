from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class EvidenceParser(ABC):
    vendor = "Unknown"

    @abstractmethod
    def can_handle(self, evidence_path: str | Path) -> bool:
        raise NotImplementedError

    def identify(self, evidence_path: str | Path) -> dict[str, object]:
        return {"vendor": self.vendor, "path": str(evidence_path), "status": "identified" if self.can_handle(evidence_path) else "not_applicable"}

    @abstractmethod
    def parse(self, evidence_path: str | Path) -> dict[str, object]:
        raise NotImplementedError

    def extract_videos(self, evidence_path: str | Path) -> list[str]:
        return []

    def extract_metadata(self, evidence_path: str | Path) -> list[dict[str, Any]]:
        return []

    def recover_deleted(self, evidence_path: str | Path) -> dict[str, object]:
        return {"status": "unsupported", "vendor": self.vendor, "message": "Validated evidence sample required for deleted-file recovery."}


class UnsupportedVendorParser(EvidenceParser):
    markers: tuple[str, ...] = ()

    def can_handle(self, evidence_path: str | Path) -> bool:
        value = str(evidence_path).lower()
        return any(marker in value for marker in self.markers)

    def parse(self, evidence_path: str | Path) -> dict[str, object]:
        return {
            "status": "unsupported",
            "vendor": self.vendor,
            "path": str(evidence_path),
            "message": "Validated evidence sample required for proprietary filesystem parsing.",
        }
