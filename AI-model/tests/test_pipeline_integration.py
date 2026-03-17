"""
Integration tests — run full pipeline with synthetic firmware/APK inputs.
These tests verify that all components wire together correctly.
"""
import json
import zipfile
import pytest
from pathlib import Path
from app.schemas import AnalyzeRequest
from app.pipeline import run_pipeline


def _make_request(fw_path: Path, job_id: str = "test-job") -> AnalyzeRequest:
    return AnalyzeRequest.model_validate({
        "schema_version": "1.0",
        "job_id": job_id,
        "firmware": {"name": fw_path.name, "file_path": str(fw_path)},
        "options": {"run_static_scan": True},
    })


# ── firmware pipeline ──────────────────────────────────────────────────────────

def test_firmware_pipeline_basic(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00hello world\x00" + b"\x55" * 100)

    report = run_pipeline(_make_request(fw), output_dir=tmp_path / "out")

    assert report.job_id == "test-job"
    assert report.status == "success"
    assert report.summary.risk_score >= 0
    assert isinstance(report.findings, list)


def test_firmware_pipeline_detects_telnet_and_password(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(
        b'password="admin123"\x00telnetd -l /bin/sh\x00' + b"\x00" * 200
    )

    report = run_pipeline(_make_request(fw))
    ids = {f.finding_id for f in report.findings}

    assert "HARDCODED_PASSWORD" in ids
    assert "TELNET_ENABLED" in ids


def test_firmware_pipeline_private_key(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEo\n-----END RSA PRIVATE KEY-----\n"
        + b"\x00" * 50
    )

    report = run_pipeline(_make_request(fw))
    ids = {f.finding_id for f in report.findings}
    assert "PRIVATE_KEY_PEM" in ids

    f = next(f for f in report.findings if f.finding_id == "PRIVATE_KEY_PEM")
    assert f.severity == "critical"


def test_firmware_pipeline_writes_artifacts(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"telnetd\x00" + b"\x00" * 100)
    out_dir = tmp_path / "artifacts"

    report = run_pipeline(_make_request(fw, "artifact-test"), output_dir=out_dir)

    assert out_dir.exists()
    features_file = out_dir / "artifact-test.features.json"
    assert features_file.exists()

    data = json.loads(features_file.read_text())
    assert data["job_id"] == "artifact-test"
    assert "stats" in data


def test_firmware_pipeline_missing_file(tmp_path):
    report = run_pipeline(AnalyzeRequest.model_validate({
        "schema_version": "1.0",
        "job_id": "missing-file",
        "firmware": {"name": "ghost.bin", "file_path": "/nonexistent/path/fw.bin"},
    }))
    assert report.status == "failed"
    assert len(report.errors) > 0


def test_firmware_pipeline_high_entropy_encrypted(tmp_path):
    """Near-random bytes (encrypted firmware) should trigger HIGH_ENTROPY_ENCRYPTED."""
    import os
    fw = tmp_path / "encrypted.bin"
    fw.write_bytes(os.urandom(200_000))   # cryptographically random = max entropy

    report = run_pipeline(_make_request(fw))
    ids = {f.finding_id for f in report.findings}
    assert "HIGH_ENTROPY_ENCRYPTED" in ids

    f = next(f for f in report.findings if f.finding_id == "HIGH_ENTROPY_ENCRYPTED")
    assert f.severity == "medium"
    assert "CWE-311" in f.cwe
    assert f.confidence > 0.9
    assert "entropy_bits_per_byte" in f.evidence


def test_firmware_pipeline_low_entropy_no_warning(tmp_path):
    """Plaintext / uncompressed binary should NOT trigger entropy warning."""
    fw = tmp_path / "plain.bin"
    fw.write_bytes(b"A" * 50_000)   # single repeated byte = entropy ~0

    report = run_pipeline(_make_request(fw))
    ids = {f.finding_id for f in report.findings}
    assert "HIGH_ENTROPY_ENCRYPTED" not in ids


def test_firmware_pipeline_clean_binary(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00\x01\x02\x03" * 100)   # no suspicious strings

    report = run_pipeline(_make_request(fw))
    security_ids = {
        f.finding_id for f in report.findings
        if f.category != "analysis_limitation"
    }
    assert len(security_ids) == 0


# ── APK pipeline ───────────────────────────────────────────────────────────────

def _make_apk(tmp_path: Path, name: str = "app.apk", extra_content: str = "") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='com.example'/>")
        zf.writestr("classes.dex", b"\x64\x65\x78\x0a\x00" * 10)
        if extra_content:
            zf.writestr("assets/config.txt", extra_content)
    return p


def test_apk_pipeline_basic(tmp_path):
    apk = _make_apk(tmp_path)
    report = run_pipeline(_make_request(apk, "apk-test"))

    assert report.status == "success"
    assert report.job_id == "apk-test"


def test_apk_pipeline_detects_hardcoded_secret(tmp_path):
    apk = _make_apk(tmp_path, extra_content='api_key="AKIAIOSFODNN7EXAMPLE"\n')
    report = run_pipeline(_make_request(apk))
    ids = {f.finding_id for f in report.findings}
    assert "AWS_ACCESS_KEY" in ids


# ── routing ────────────────────────────────────────────────────────────────────

def test_router_sends_elf_to_firmware_pipeline(tmp_path):
    elf = tmp_path / "busybox"
    elf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)

    report = run_pipeline(_make_request(elf))
    assert report.status == "success"


def test_router_explicit_file_type_hint(tmp_path):
    # Give firmware file_type hint even if extension is wrong
    fw = tmp_path / "mystery.dat"
    fw.write_bytes(b"telnetd\x00" + b"\x00" * 50)

    req = AnalyzeRequest.model_validate({
        "schema_version": "1.0",
        "job_id": "hint-test",
        "firmware": {
            "name": "mystery.dat",
            "file_path": str(fw),
            "file_type": "firmware",
        },
    })
    report = run_pipeline(req)
    assert report.status == "success"
