from pathlib import Path

import pytest

from app.forensic_engine.device_identifier import DeviceIdentifier


@pytest.mark.parametrize("vendor,marker", [
    ("Hikvision", b"HIKVISION NVR"),
    ("Dahua", b"Dahua Technology DVR"),
    ("CP Plus", b"CP PLUS DVR"),
    ("Honeywell", b"Honeywell Security"),
    ("TP-Link", b"TP-LINK Tapo"),
    ("Godrej", b"Godrej Security"),
    ("Uniview", b"UNIVIEW NVR"),
    ("Matrix", b"Matrix Comsec DVR"),
])
def test_synthetic_binary_vendor_indicator(tmp_path: Path, vendor: str, marker: bytes) -> None:
    evidence = tmp_path / "raw.bin"
    evidence.write_bytes(marker)
    result = DeviceIdentifier().identify(evidence)
    assert result["vendor"] == vendor
    assert result["model"] == "Unknown"
    assert result["confidence"] >= 45
    assert result["matched_indicators"]


def test_generic_mp4_and_random_binary_are_unknown(tmp_path: Path) -> None:
    mp4 = tmp_path / "video.mp4"
    mp4.write_bytes(b"\x00\x00\x00\x18ftypisom")
    random_file = tmp_path / "random.bin"
    random_file.write_bytes(b"random bytes")
    assert DeviceIdentifier().identify(mp4)["vendor"] == "Unknown"
    assert DeviceIdentifier().identify(random_file)["vendor"] == "Unknown"


def test_filename_only_is_weak_and_model_stays_unknown(tmp_path: Path) -> None:
    evidence = tmp_path / "hikvision_camera.mp4"
    evidence.write_bytes(b"video")
    result = DeviceIdentifier().identify(evidence)
    assert result["vendor"] == "Hikvision"
    assert result["model"] == "Unknown"
    assert result["confidence"] < 45
    assert result["detection_method"] == "filename_indicator"


def test_multiple_independent_indicators_raise_confidence(tmp_path: Path) -> None:
    evidence = tmp_path / "hikvision_camera.mp4"
    evidence.write_bytes(b"HIKVISION model: DS-7608NI\x00")
    result = DeviceIdentifier().identify(evidence, metadata={"vendor": "Hikvision"})
    assert result["vendor"] == "Hikvision"
    assert result["model"] == "DS-7608NI"
    assert result["confidence"] > 60
    assert result["detection_method"] == "combined_indicators"


def test_codec_and_container_alone_do_not_identify_vendor(tmp_path: Path) -> None:
    evidence = tmp_path / "video.h264"
    evidence.write_bytes(b"\x00\x00\x01\x67\x00\x00\x01\x65")
    result = DeviceIdentifier().identify(evidence, metadata={"format_name": "mov,mp4,m4a,3gp,3g2,mj2", "codec_name": "h264"})
    assert result["vendor"] == "Unknown"