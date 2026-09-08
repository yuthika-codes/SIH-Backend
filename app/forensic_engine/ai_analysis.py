import os
from collections import Counter
from pathlib import Path
from typing import Any


class AIAnalysisEngine:
    """Configurable, sampled, read-only video analysis.

    YOLO is loaded only when an explicit model path is configured. No model
    download or identity recognition is performed by this class.
    """

    def __init__(
        self,
        sampling_interval_seconds: float = 1.0,
        model_path: str | None = None,
        confidence_threshold: float = 0.25,
        enable_motion: bool = True,
        enable_person_detection: bool = True,
        enable_object_detection: bool = True,
        enable_face_detection: bool = True,
        motion_group_gap_seconds: float = 3.0,
    ) -> None:
        self.sampling_interval_seconds = max(0.1, sampling_interval_seconds)
        self.model_path = self._resolve_model_path(model_path or os.getenv("SIH_AI_MODEL"))
        self.confidence_threshold = min(1.0, max(0.0, confidence_threshold))
        self.enable_motion = enable_motion
        self.enable_person_detection = enable_person_detection
        self.enable_object_detection = enable_object_detection
        self.enable_face_detection = enable_face_detection
        self.motion_group_gap_seconds = max(0.0, motion_group_gap_seconds)
        self._cv2: Any = None
        self._cv2_error: str | None = None
        self._model: Any = None
        self._model_error: str | None = None
        self._face_classifier: Any = None
        self._face_loaded = False

    def analyze_videos(self, video_paths: list[str | Path]) -> dict[str, object]:
        videos = [self.analyze_video(video_path) for video_path in video_paths]
        events = [event for video in videos for event in video.get("events", [])]
        counts = Counter(str(event.get("label")) for event in events if event.get("label"))
        statuses = {str(video.get("status")) for video in videos}
        if not videos:
            status = "not_configured"
        elif all(status == "unavailable" for status in statuses):
            status = "unavailable"
        elif any(status == "error" for status in statuses):
            status = "partial"
        else:
            status = "completed"
        return {
            "status": status,
            "videos": videos,
            "events": events,
            "summary": {"detection_counts": dict(counts), "video_count": len(videos), "event_count": len(events)},
        }

    def analyze_video(self, video_path: str | Path) -> dict[str, object]:
        path = Path(video_path)
        base = {"source_video": str(path), "events": [], "summary": {"detection_counts": {}}}
        if not path.exists():
            return {**base, "status": "error", "error": "Video file does not exist"}
        cv2 = self._load_cv2()
        if cv2 is None:
            return {**base, "status": "unavailable", "error": self._cv2_error or "OpenCV is not installed"}
        capture = cv2.VideoCapture(str(path))
        if not capture.isOpened():
            capture.release()
            return {**base, "status": "error", "error": "Unable to open video"}
        fps = float(capture.get(cv2.CAP_PROP_FPS) or 0.0)
        frame_step = max(1, int(round(fps * self.sampling_interval_seconds))) if fps > 0 else 1
        previous_gray = None
        frame_number = 0
        events: list[dict[str, object]] = []
        try:
            while True:
                success, frame = capture.read()
                if not success:
                    break
                if frame_number % frame_step == 0:
                    timestamp = frame_number / fps if fps > 0 else None
                    if self.enable_motion:
                        events.extend(self._detect_motion(cv2, frame, previous_gray, frame_number, timestamp, path))
                    if self.enable_face_detection:
                        events.extend(self._detect_faces(cv2, frame, frame_number, timestamp, path))
                    if self.enable_person_detection or self.enable_object_detection:
                        events.extend(self._detect_objects(frame, frame_number, timestamp, path))
                    previous_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                frame_number += 1
        finally:
            capture.release()
        events = self._aggregate_events(events)
        counts = Counter(str(event["label"]) for event in events)
        component_status = self._component_status(cv2)
        usable = bool(events) or any(value == "available" for value in component_status.values())
        return {
            **base,
            "status": "completed" if usable else "unavailable",
            "events": events,
            "components": component_status,
            "summary": {"detection_counts": dict(counts), "frames_sampled": (frame_number + frame_step - 1) // frame_step if frame_number else 0},
        }

    def _load_cv2(self) -> Any:
        if self._cv2 is not None or self._cv2_error is not None:
            return self._cv2
        try:
            import cv2
            self._cv2 = cv2
        except ImportError as exc:
            self._cv2_error = f"OpenCV unavailable: {exc}"
        return self._cv2

    def _detect_motion(self, cv2: Any, frame: Any, previous_gray: Any, frame_number: int, timestamp: float | None, path: Path) -> list[dict[str, object]]:
        if previous_gray is None:
            return []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        difference = cv2.absdiff(previous_gray, gray)
        _, threshold = cv2.threshold(difference, 25, 255, cv2.THRESH_BINARY)
        if int(cv2.countNonZero(threshold)) == 0:
            return []
        return [self._event(timestamp, "motion", "motion", 1.0, frame_number, path)]

    def _detect_faces(self, cv2: Any, frame: Any, frame_number: int, timestamp: float | None, path: Path) -> list[dict[str, object]]:
        classifier = self._load_face_classifier(cv2)
        if classifier is None:
            return []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = classifier.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4)
        return [self._event(timestamp, "face", "face", 1.0, frame_number, path) for _ in faces]

    def _load_face_classifier(self, cv2: Any) -> Any:
        if self._face_loaded:
            return self._face_classifier
        self._face_loaded = True
        cascade_data = getattr(cv2, "data", None)
        if cascade_data is None or not hasattr(cv2, "CascadeClassifier"):
            return None
        classifier = cv2.CascadeClassifier(str(Path(cascade_data.haarcascades) / "haarcascade_frontalface_default.xml"))
        self._face_classifier = None if classifier.empty() else classifier
        return self._face_classifier

    def _detect_objects(self, frame: Any, frame_number: int, timestamp: float | None, path: Path) -> list[dict[str, object]]:
        model = self._load_model()
        if model is None:
            return []
        events = []
        for result in model(frame, verbose=False, conf=self.confidence_threshold, stream=True):
            names = getattr(result, "names", {})
            for box in getattr(result, "boxes", []):
                confidence = float(box.conf[0]) if getattr(box, "conf", None) is not None else None
                if confidence is None or confidence < self.confidence_threshold:
                    continue
                class_id = int(box.cls[0]) if getattr(box, "cls", None) is not None else -1
                label = str(names.get(class_id, "unknown"))
                if label == "person" and self.enable_person_detection:
                    events.append(self._event(timestamp, "person", "person", confidence, frame_number, path))
                elif label != "person" and self.enable_object_detection:
                    events.append(self._event(timestamp, "object", label, confidence, frame_number, path))
        return events

    def _load_model(self) -> Any:
        if not self.model_path:
            self._model_error = "YOLO model not found: configure SIH_AI_MODEL or place yolo11n.pt at the backend project root"
            return None
        if self._model is not None or self._model_error is not None:
            return self._model
        try:
            from ultralytics import YOLO
            self._model = YOLO(self.model_path)
        except (ImportError, OSError, RuntimeError) as exc:
            self._model_error = f"YOLO model unavailable: {exc}"
        return self._model

    @staticmethod
    def _resolve_model_path(model_path: str | None) -> str | None:
        project_root = Path(__file__).resolve().parents[2]
        if model_path:
            configured = Path(model_path).expanduser()
            candidates = [configured] if configured.is_absolute() else [Path.cwd() / configured, project_root / configured]
            for candidate in candidates:
                if candidate.is_file():
                    return str(candidate.resolve())
            return str(candidates[0].resolve())
        default_model = project_root / "yolo11n.pt"
        return str(default_model) if default_model.is_file() else None

    def _component_status(self, cv2: Any) -> dict[str, str]:
        return {
            "motion": "available" if self.enable_motion else "disabled",
            "face": "available" if self.enable_face_detection and self._face_available(cv2) else "disabled" if not self.enable_face_detection else "unavailable",
            "yolo": "available" if self._model is not None else "model_unavailable" if self.enable_person_detection or self.enable_object_detection else "disabled",
        }

    @staticmethod
    def _face_available(cv2: Any) -> bool:
        return hasattr(cv2, "CascadeClassifier") and hasattr(cv2, "data")

    @staticmethod
    def _event(timestamp: float | None, event_type: str, label: str, confidence: float | None, frame_number: int, path: Path) -> dict[str, object]:
        return {"timestamp": timestamp, "event_type": event_type, "label": label, "confidence": confidence, "frame_number": frame_number, "source_video": str(path)}

    def _aggregate_events(self, events: list[dict[str, object]]) -> list[dict[str, object]]:
        grouped: list[dict[str, object]] = []
        for event in events:
            if event["event_type"] != "motion":
                grouped.append(event)
                continue
            timestamp = event.get("timestamp")
            previous = next((candidate for candidate in reversed(grouped) if candidate["event_type"] == "motion" and candidate["source_video"] == event["source_video"]), None)
            if previous is not None and timestamp is not None and previous.get("timestamp") is not None and float(timestamp) - float(previous["timestamp"]) <= self.motion_group_gap_seconds:
                if (event.get("confidence") or 0) > (previous.get("confidence") or 0):
                    previous.update(event)
                continue
            grouped.append(event)
        return grouped


def analyze_evidence(analysis_type: str) -> dict[str, object]:
    return {"status": "not_configured", "message": "Use AIAnalysisEngine with verified acquired video paths", "type": analysis_type, "events": [], "summary": {"detection_counts": {}}}
