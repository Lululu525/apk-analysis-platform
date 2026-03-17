"""Tests for file type detection."""
import zipfile
import pytest
from pathlib import Path
from app.extractors.type_detector import detect


# ── helpers ────────────────────────────────────────────────────────────────────

def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _make_apk(tmp_path: Path) -> Path:
    p = tmp_path / "sample.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"\x64\x65\x78\x0a")
    return p


def _make_zip_no_manifest(tmp_path: Path) -> Path:
    p = tmp_path / "ota.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("payload.bin", b"\x00" * 10)
    return p


# ── tests ──────────────────────────────────────────────────────────────────────

def test_detect_elf(tmp_path):
    p = _write(tmp_path, "busybox", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
    assert detect(p) == "elf"


def test_detect_apk(tmp_path):
    p = _make_apk(tmp_path)
    assert detect(p) == "apk"


def test_detect_zip_without_manifest_is_firmware(tmp_path):
    p = _make_zip_no_manifest(tmp_path)
    assert detect(p) == "firmware"


def test_detect_gzip(tmp_path):
    p = _write(tmp_path, "fw.bin", b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    assert detect(p) == "firmware"


def test_detect_squashfs_le(tmp_path):
    p = _write(tmp_path, "fs.img", b"hsqs" + b"\x00" * 60)
    assert detect(p) == "firmware"


def test_detect_extension_fallback_bin(tmp_path):
    # random bytes but .bin extension → firmware
    p = _write(tmp_path, "unknown.bin", b"\xde\xad\xbe\xef" * 10)
    assert detect(p) == "firmware"


def test_detect_extension_fallback_apk(tmp_path):
    # APK extension without valid zip → still "apk" by extension
    p = _write(tmp_path, "broken.apk", b"\xde\xad\xbe\xef" * 10)
    assert detect(p) == "apk"


def test_detect_unknown(tmp_path):
    p = _write(tmp_path, "mystery.xyz", b"\xca\xfe\xba\xbe" * 4)
    assert detect(p) == "unknown"
