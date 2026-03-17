"""Tests for string extraction strategies."""
import pytest
from pathlib import Path
from app.detectors.strings_detector import (
    extract_strings,
    extract_strings_from_dir,
    _strings_python,
)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ── Python fallback ────────────────────────────────────────────────────────────

def test_python_fallback_extracts_ascii():
    data = b"\x00\x01hello\x00world\x00\xff"
    result = _strings_python(data, min_len=4)
    assert "hello" in result
    assert "world" in result


def test_python_fallback_respects_min_len():
    data = b"\x00hi\x00hello\x00"
    result = _strings_python(data, min_len=4)
    assert "hello" in result
    assert "hi" not in result   # too short


def test_python_fallback_respects_limit():
    # Generate many strings
    data = b"\x00".join(b"string%02d" % i for i in range(200))
    result = _strings_python(data, min_len=4, limit=10)
    assert len(result) <= 10


# ── extract_strings auto-strategy ─────────────────────────────────────────────

def test_extract_strings_returns_list_and_method(tmp_path):
    p = _write(tmp_path, "fw.bin", b"\x00hello world\x00password123\x00" + b"\x00" * 20)
    strings, method = extract_strings(p, min_len=4)
    assert isinstance(strings, list)
    assert method in ("rodata", "system_strings", "python_fallback")


def test_extract_strings_finds_known_text(tmp_path):
    payload = b"\x00" * 8 + b"telnetd enabled\x00api_key=secret\x00" + b"\x00" * 8
    p = _write(tmp_path, "fw.bin", payload)
    strings, _ = extract_strings(p, min_len=4)
    combined = " ".join(strings)
    # at least one of these should be found
    assert "telnetd" in combined or "api_key" in combined


def test_extract_strings_empty_file(tmp_path):
    p = _write(tmp_path, "empty.bin", b"")
    strings, method = extract_strings(p)
    assert strings == []


# ── extract_strings_from_dir ──────────────────────────────────────────────────

def test_extract_from_dir_basic(tmp_path):
    fs = tmp_path / "extracted"
    fs.mkdir()
    (fs / "script.sh").write_text("#!/bin/sh\ntelnetd -l /bin/sh\npassword=admin\n")
    (fs / "config.conf").write_text("api_key=AKIAIOSFODNN7EXAMPLE\n")

    result = extract_strings_from_dir(fs, min_len=4)
    all_strings = [s for strings in result.values() for s in strings]
    combined = " ".join(all_strings)
    assert "telnetd" in combined or "password" in combined


def test_extract_from_dir_skips_image_files(tmp_path):
    fs = tmp_path / "extracted"
    fs.mkdir()
    (fs / "logo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
    result = extract_strings_from_dir(fs)
    assert "logo.jpg" not in result
