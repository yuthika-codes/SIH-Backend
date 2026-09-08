from pathlib import Path

from app.forensic_engine.filesystem import FileSystemAnalyzer
from app.forensic_engine.parsers.base import EvidenceParser


class GenericParser(EvidenceParser):
    vendor = "Unknown"

    def can_handle(self, evidence_path: str | Path) -> bool:
        return Path(evidence_path).exists()

    def parse(self, evidence_path: str | Path) -> dict[str, object]:
        analysis = FileSystemAnalyzer().analyze(evidence_path)
        return {"status": analysis.get("status", "error"), "vendor": self.vendor, "filesystem": analysis}

    def extract_videos(self, evidence_path: str | Path) -> list[str]:
        analysis = FileSystemAnalyzer().analyze(evidence_path)
        return [str(path) for path in analysis.get("candidate_video_files", [])]


def parse(path: str) -> dict[str, object]:
    return GenericParser().parse(path)
