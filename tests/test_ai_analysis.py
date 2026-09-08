from pathlib import Path
import sys
from types import SimpleNamespace

from app.forensic_engine.ai_analysis import AIAnalysisEngine, analyze_evidence


def test_ai_module_initializes_with_schema() -> None:
    result = analyze_evidence("metadata")
    assert result["status"] == "not_configured"
    assert result["events"] == []
    assert "detection_counts" in result["summary"]


def test_missing_dependency_is_explicit(tmp_path: Path, monkeypatch) -> None:
    video = tmp_path / "video.mp4"
    video.write_bytes(b"not-video")
    engine = AIAnalysisEngine()
    monkeypatch.setattr(engine, "_load_cv2", lambda: None)
    engine._cv2_error = "OpenCV unavailable in test"
    result = engine.analyze_video(video)
    assert result["status"] == "unavailable"
    assert result["events"] == []
    assert "OpenCV" in result["error"]


def test_invalid_video_is_handled_safely(tmp_path: Path, monkeypatch) -> None:
    video = tmp_path / "invalid.mp4"
    original = b"invalid video bytes"
    video.write_bytes(original)
    class FakeCapture:
        def isOpened(self):
            return False

        def release(self):
            pass

    class FakeCV2:
        CAP_PROP_FPS = 5

        def VideoCapture(self, path):
            return FakeCapture()

    engine = AIAnalysisEngine()
    monkeypatch.setattr(engine, "_load_cv2", lambda: FakeCV2())
    result = engine.analyze_video(video)
    assert result["status"] == "error"
    assert "Unable to open" in result["error"]
    assert video.read_bytes() == original


def test_motion_processing_does_not_crash_and_source_is_unchanged(tmp_path: Path, monkeypatch) -> None:
    video = tmp_path / "sample.mp4"
    original = b"source remains untouched"
    video.write_bytes(original)
    engine = AIAnalysisEngine()
    monkeypatch.setattr(engine, "_load_cv2", lambda: None)
    engine._cv2_error = "OpenCV unavailable in test"
    result = engine.analyze_videos([video])
    assert result["videos"][0]["status"] == "unavailable"
    assert video.read_bytes() == original


def test_event_schema_is_stable() -> None:
    event = AIAnalysisEngine._event(1.0, "object", "person", 0.9, 30, Path("acquired.mp4"))
    assert set(event) == {"timestamp", "event_type", "label", "confidence", "frame_number", "source_video"}


def test_motion_events_are_grouped_by_time() -> None:
    engine = AIAnalysisEngine(motion_group_gap_seconds=2.0)
    events = [
        engine._event(1.0, "motion", "motion", 1.0, 10, Path("acquired.mp4")),
        engine._event(2.0, "motion", "motion", 1.0, 20, Path("acquired.mp4")),
        engine._event(6.0, "motion", "motion", 1.0, 60, Path("acquired.mp4")),
    ]
    grouped = engine._aggregate_events(events)
    assert len(grouped) == 2
    assert grouped[0]["source_video"] == "acquired.mp4"


def test_yolo_person_and_object_events_use_threshold_and_schema() -> None:
    class Box:
        def __init__(self, confidence, class_id):
            self.conf = [confidence]
            self.cls = [class_id]

    class Result:
        names = {0: "person", 2: "car", 7: "truck"}
        boxes = [Box(0.9, 0), Box(0.8, 2), Box(0.1, 7)]

    class Model:
        def __call__(self, frame, **kwargs):
            assert kwargs["conf"] == 0.5
            return [Result()]

    engine = AIAnalysisEngine(model_path="model.pt", confidence_threshold=0.5)
    engine._model = Model()
    events = engine._detect_objects(object(), 4, 1.0, Path("acquired.mp4"))
    assert [(event["event_type"], event["label"]) for event in events] == [("person", "person"), ("object", "car")]
    assert all(event["source_video"] == "acquired.mp4" for event in events)


def test_yolo_model_unavailable_is_explicit() -> None:
    engine = AIAnalysisEngine(model_path="missing-model.pt")
    engine._model_error = "YOLO model unavailable"
    status = engine._component_status(type("CV2", (), {"CascadeClassifier": object, "data": object})())
    assert status["yolo"] == "model_unavailable"


def test_detection_toggles_disable_components() -> None:
    engine = AIAnalysisEngine(enable_motion=False, enable_person_detection=False, enable_object_detection=False, enable_face_detection=False)
    status = engine._component_status(object())
    assert status == {"motion": "disabled", "face": "disabled", "yolo": "disabled"}


def test_sampling_interval_is_configurable() -> None:
    engine = AIAnalysisEngine(sampling_interval_seconds=2.5)
    assert engine.sampling_interval_seconds == 2.5


def test_default_model_resolves_relative_to_backend_root(monkeypatch, tmp_path: Path) -> None:
    import app.forensic_engine.ai_analysis as module

    project_root = tmp_path / "backend"
    model = project_root / "yolo11n.pt"
    model.parent.mkdir()
    model.write_bytes(b"model")
    monkeypatch.setattr(module, "__file__", str(project_root / "app" / "forensic_engine" / "ai_analysis.py"))
    monkeypatch.chdir(tmp_path)
    engine = AIAnalysisEngine()
    assert Path(engine.model_path) == model


def test_existing_model_loads_once(monkeypatch, tmp_path: Path) -> None:
    import app.forensic_engine.ai_analysis as module

    model = tmp_path / "yolo11n.pt"
    model.write_bytes(b"model")
    load_count = []

    class FakeYOLO:
        def __init__(self, path):
            load_count.append(path)

    monkeypatch.setitem(sys.modules, "ultralytics", SimpleNamespace(YOLO=FakeYOLO))
    engine = AIAnalysisEngine(model_path=str(model))
    assert engine._load_model() is engine._load_model()
    assert load_count == [str(model)]


def test_missing_model_has_diagnostic_reason(monkeypatch, tmp_path: Path) -> None:
    import app.forensic_engine.ai_analysis as module

    monkeypatch.delenv("SIH_AI_MODEL", raising=False)
    monkeypatch.setattr(module, "__file__", str(tmp_path / "app" / "forensic_engine" / "ai_analysis.py"))
    engine = AIAnalysisEngine()
    assert engine._load_model() is None
    assert "YOLO model not found" in engine._model_error
    assert engine._component_status(object())["yolo"] == "model_unavailable"


def test_yolo_inference_uses_stream_mode() -> None:
    calls = []

    class Model:
        def __call__(self, frame, **kwargs):
            calls.append(kwargs)
            return iter([])

    engine = AIAnalysisEngine(model_path="model.pt")
    engine._model = Model()
    assert engine._detect_objects(object(), 1, 0.1, Path("acquired.mp4")) == []
    assert calls[0]["stream"] is True