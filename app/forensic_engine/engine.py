import json
from datetime import datetime, timezone
from pathlib import Path

from app.forensic_engine.acquisition import AcquisitionService
from app.forensic_engine.ai_analysis import AIAnalysisEngine
from app.forensic_engine.device_identifier import DeviceIdentifier
from app.forensic_engine.filesystem import FileSystemAnalyzer
from app.forensic_engine.metadata import extract_metadata
from app.forensic_engine.recovery import RecoveryEngine
from app.forensic_engine.parsers.base import EvidenceParser
from app.forensic_engine.parsers.cp_plus import CpPlusParser
from app.forensic_engine.parsers.dahua import DahuaParser
from app.forensic_engine.parsers.generic import GenericParser
from app.forensic_engine.parsers.hikvision import HikvisionParser
from app.forensic_engine.parsers.honeywell import HoneywellParser
from app.forensic_engine.parsers.matrix import MatrixParser
from app.forensic_engine.parsers.uniview import UniviewParser
from app.forensic_engine.timeline import TimelineAnalyzer
from app.forensic_engine.timestamp import extract_camera_id, extract_timestamp
from app.forensic_engine.correlation import correlate_events
from app.forensic_engine.video_extractor import VideoExtractor
from app.services.storage import ROOT


class ForensicEngine:
    def __init__(self, storage_root: str | Path | None = None) -> None:
        self.storage_root = Path(storage_root) if storage_root else ROOT
        self.acquisition = AcquisitionService()
        self.device_identifier = DeviceIdentifier()
        self.filesystem = FileSystemAnalyzer()
        self.video_extractor = VideoExtractor()
        self.ai_analysis = AIAnalysisEngine()
        self.timeline = TimelineAnalyzer()
        self.parsers: list[EvidenceParser] = [
            DahuaParser(), HikvisionParser(), CpPlusParser(), UniviewParser(), HoneywellParser(), MatrixParser(), GenericParser()
        ]

    def analyze(self, evidence_path: str | Path) -> dict[str, object]:
        path = Path(evidence_path)
        if not path.exists():
            return self._error_result(path, "Evidence path does not exist")

        acquisition = self.acquisition.acquire(path, self.storage_root / "forensic_images")
        original_sha256 = acquisition.get("original_sha256")
        acquired_sha256 = acquisition.get("acquired_sha256")
        hashes_available = isinstance(original_sha256, str) and isinstance(acquired_sha256, str)
        hashes_match = (
            hashes_available
            and original_sha256.lower() == acquired_sha256.lower()
        )
        if acquisition.get("status") != "completed" or acquisition.get("integrity_verified") is not True or not hashes_match:
            integrity_status = acquisition.get("integrity_status")
            if acquisition.get("status") == "INTEGRITY_COMPROMISED" or acquisition.get("integrity_verified") is False or (hashes_available and not hashes_match):
                integrity_status = "INTEGRITY_COMPROMISED"
            return {
                "status": "error",
                "evidence": {"path": str(path), "exists": True},
                "processing_path": None,
                "device": {},
                "filesystem": {},
                "recovery": {"status": "not_run", "artifacts": []},
                "acquisition": acquisition,
                "videos": [],
                "metadata": [],
                "timeline": [],
                "ai_analysis": {"status": "not_run", "events": [], "summary": {"detection_counts": {}}},
                "integrity": {
                    "sha256": acquisition.get("original_sha256"),
                    "md5": acquisition.get("original_md5"),
                    "verified": False,
                    "status": integrity_status or "ACQUISITION_FAILED",
                },
            }
        processing_path = Path(str(acquisition["acquired_path"]))
        device = self.device_identifier.identify(processing_path)
        filesystem = self.filesystem.analyze(processing_path)
        try:
            recovery = RecoveryEngine(
                self.storage_root / "forensic_images",
                self.storage_root / "recovered",
            ).recover(processing_path)
        except (OSError, PermissionError) as exc:
            recovery = {"status": "error", "artifacts": [], "error": str(exc)}
        parser = self._select_parser(processing_path)
        parser_result = parser.parse(processing_path)
        candidate_videos = [str(item) for item in filesystem.get("candidate_video_files", [])]
        extraction = self.video_extractor.extract(candidate_videos, self.storage_root / "extracted")
        metadata = []
        events = []
        for item in extraction:
            output_path = item.get("output_path")
            if item.get("status") != "completed" or not output_path:
                continue
            item_metadata = extract_metadata(str(output_path))
            try:
                filesystem_mtime = datetime.fromtimestamp(Path(output_path).stat().st_mtime, timezone.utc)
            except (OSError, PermissionError):
                filesystem_mtime = None
            timestamp = extract_timestamp(item_metadata, output_path, filesystem_mtime)
            item_metadata["timestamp"] = timestamp
            item_metadata["camera_id"] = extract_camera_id(output_path, item_metadata.get("container_metadata"))
            metadata.append(item_metadata)
            events.append({
                "timestamp": timestamp.get("timestamp"),
                "timestamp_source": timestamp.get("source"),
                "timestamp_confidence": timestamp.get("confidence"),
                "camera_id": item_metadata["camera_id"],
                "event_type": "video_recording",
                "evidence_path": str(output_path),
                "description": "CCTV recording event; filesystem fallback is not recording time",
                "timezone": timestamp.get("timezone", "unknown"),
            })
        timeline = self.timeline.build_result(events)
        correlations = correlate_events(timeline["events"])
        ai_paths = [str(item["output_path"]) for item in extraction if item.get("status") == "completed" and item.get("output_path")]
        ai_paths.extend(str(item["output_path"]) for item in recovery.get("artifacts", []) if item.get("output_path") and item.get("classification") in {"VALID", "PARTIALLY_RECOVERABLE"})
        ai_analysis = self.ai_analysis.analyze_videos(list(dict.fromkeys(ai_paths)))
        has_fatal_error = acquisition.get("status") == "error" or filesystem.get("status") == "error"
        return {
            "status": "error" if has_fatal_error else "completed",
            "evidence": {"path": str(path), "exists": True},
            "processing_path": str(processing_path),
            "device": device,
            "filesystem": filesystem,
            "recovery": recovery,
            "parser": parser_result,
            "acquisition": acquisition,
            "videos": extraction,
            "metadata": metadata,
            "timeline": timeline,
            "correlations": correlations,
            "ai_analysis": ai_analysis,
            "integrity": {
                "sha256": acquisition.get("original_sha256"),
                "md5": acquisition.get("original_md5"),
                "verified": acquisition.get("integrity_verified", False),
                "status": acquisition.get("integrity_status", "UNKNOWN"),
            },
        }

    def _select_parser(self, path: Path) -> EvidenceParser:
        for parser in self.parsers[:-1]:
            if parser.can_handle(path):
                return parser
        return self.parsers[-1]

    @staticmethod
    def _error_result(path: Path, message: str) -> dict[str, object]:
        return {
            "status": "error",
            "evidence": {"path": str(path), "exists": False},
            "error": message,
            "device": {},
            "filesystem": {"status": "error", "error": message},
            "recovery": {"status": "not_run", "artifacts": []},
            "videos": [],
            "metadata": [],
            "timeline": [],
            "correlations": [],
            "ai_analysis": {"status": "not_run", "events": [], "summary": {"detection_counts": {}}},
            "integrity": {"sha256": None, "md5": None, "verified": False},
        }


def serialize_result(result: dict[str, object]) -> str:
    return json.dumps(result, default=str)