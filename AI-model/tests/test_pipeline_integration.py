"""
Integration tests for APK pipeline Android-risk rules.
"""
import json
import zipfile
from pathlib import Path

from app.schemas import AnalyzeRequest
from app.pipeline import run_pipeline


def _make_request(fw_path: Path, job_id: str = "test-job") -> AnalyzeRequest:
    return AnalyzeRequest.model_validate({
        "schema_version": "1.0",
        "job_id": job_id,
        "firmware": {
            "name": fw_path.name,
            "file_path": str(fw_path),
        },
        "options": {
            "run_static_scan": True,
        },
    })


def _make_apk(tmp_path: Path, name: str = "app.apk", extra_content: str = "") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='com.example'/>")
        zf.writestr("classes.dex", b"\x64\x65\x78\x0a\x00" * 10)
        if extra_content:
            zf.writestr("assets/config.txt", extra_content)
    return p


def test_apk_pipeline_android_permission_rule_integration(tmp_path, monkeypatch):
    """
    Verify that pipeline_apk calls Android-specific risk rules after
    androguard analysis succeeds.
    """
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "android-risk.apk")

    class DummyAgResult:
        def __init__(self):
            self.success = True
            self.permissions = [
                "android.permission.READ_SMS",
                "android.permission.INTERNET",
            ]
            self.exported_components = []
            self.package_name = "com.example.smsapp"
            self.app_name = "SMS App"
            self.errors = []

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: DummyAgResult())
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "apk-android-risk"), output_dir=tmp_path / "out")
    ids = {f.finding_id for f in report.findings}

    assert report.status == "success"
    assert "APK_HIGH_RISK_PERMISSION_READ_SMS" in ids
    assert "APK_SMS_EXFILTRATION" in ids


def test_apk_pipeline_android_exported_component_integration(tmp_path, monkeypatch):
    """
    Verify exported-component findings are surfaced through the APK pipeline.
    """
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "exported-risk.apk")

    class DummyAgResult:
        def __init__(self):
            self.success = True
            self.permissions = [
                "android.permission.INTERNET",
            ]
            self.exported_components = [
                "com.example.MainActivity",
            ]
            self.package_name = "com.example.exportedapp"
            self.app_name = "Exported App"
            self.errors = []

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: DummyAgResult())
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "apk-exported-risk"), output_dir=tmp_path / "out")
    ids = {f.finding_id for f in report.findings}

    assert report.status == "success"
    assert "APK_EXPORTED_COMPONENT" in ids


def test_apk_pipeline_android_manifest_features_written(tmp_path, monkeypatch):
    """
    Verify manifest_analysis is written into features artifact when
    androguard analysis succeeds.
    """
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "manifest-features.apk")
    out_dir = tmp_path / "artifacts"

    class DummyAgResult:
        def __init__(self):
            self.success = True
            self.permissions = [
                "android.permission.READ_CONTACTS",
                "android.permission.INTERNET",
            ]
            self.exported_components = [
                "com.example.SyncService",
            ]
            self.package_name = "com.example.contactsapp"
            self.app_name = "Contacts App"
            self.errors = []

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: DummyAgResult())
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "apk-manifest-features"), output_dir=out_dir)

    assert report.status == "success"

    features_file = out_dir / "apk-manifest-features.features.json"
    assert features_file.exists()

    data = json.loads(features_file.read_text(encoding="utf-8"))
    assert "manifest_analysis" in data
    assert data["manifest_analysis"]["package_name"] == "com.example.contactsapp"
    assert data["manifest_analysis"]["permissions_count"] == 2
    assert data["manifest_analysis"]["exported_count"] == 1