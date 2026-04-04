"""
Integration tests for APK pipeline with privilege_rules.

Verifies that pipeline_apk correctly calls privilege_rules.check_combinations
and surfaces the new finding IDs introduced in Sprint 2.
"""
import json
import zipfile
from pathlib import Path

import pytest

from app.schemas import AnalyzeRequest
from app.pipeline import run_pipeline
from app.extractors.androguard_analyzer import AnalysisResult, ComponentInfo


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_request(fw_path: Path, job_id: str = "test-job") -> AnalyzeRequest:
    return AnalyzeRequest.model_validate({
        "schema_version": "1.0",
        "job_id": job_id,
        "firmware": {
            "name": fw_path.name,
            "file_path": str(fw_path),
        },
        "options": {"run_static_scan": True},
    })


def _make_apk(tmp_path: Path, name: str = "app.apk") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='com.example'/>")
        zf.writestr("classes.dex", b"\x64\x65\x78\x0a\x00" * 10)
    return p


def _make_ag_result(permissions=None, components=None) -> AnalysisResult:
    """Build a minimal AnalysisResult compatible with privilege_rules."""
    result = AnalysisResult(success=True)
    result.permissions = {p: None for p in (permissions or [])}
    result.components = components or []
    result.package_name = "com.example.testapp"
    result.app_name = "Test App"
    result.sensitive_api_calls = []
    result.target_sdk = 33
    result.min_sdk = 21
    result.version_name = "1.0"
    result.version_code = 1
    result.risk_findings = []
    result.errors = []
    return result


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_combo_sms_exfil_surfaced_through_pipeline(tmp_path, monkeypatch):
    """COMBO_SMS_EXFIL must appear when app has READ_SMS + INTERNET."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "sms.apk")
    ag = _make_ag_result(permissions=[
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ])

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "sms-exfil-job"), output_dir=tmp_path / "out")
    ids = {f.finding_id for f in report.findings}

    assert report.status == "success"
    assert "COMBO_SMS_EXFIL" in ids


def test_ipc_service_hijack_surfaced_through_pipeline(tmp_path, monkeypatch):
    """IPC_SERVICE_HIJACK must appear for an unprotected exported service."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "service.apk")
    service = ComponentInfo(
        type="service",
        name="com.example.DataService",
        exported=True,
        permissions_required=None,
    )
    ag = _make_ag_result(components=[service])

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "service-hijack-job"), output_dir=tmp_path / "out")
    ids = {f.finding_id for f in report.findings}

    assert report.status == "success"
    assert "IPC_SERVICE_HIJACK" in ids


def test_ipc_provider_redelegation_surfaced_through_pipeline(tmp_path, monkeypatch):
    """IPC_PROVIDER_REDELEGATION must appear for an unprotected exported provider."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "provider.apk")
    provider = ComponentInfo(
        type="provider",
        name="com.example.UserProvider",
        exported=True,
        permissions_required=None,
    )
    ag = _make_ag_result(components=[provider])

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "provider-job"), output_dir=tmp_path / "out")
    ids = {f.finding_id for f in report.findings}

    assert report.status == "success"
    assert "IPC_PROVIDER_REDELEGATION" in ids


def test_old_apk_rules_finding_ids_no_longer_appear(tmp_path, monkeypatch):
    """Verify deleted apk_rules finding IDs are gone from the pipeline output."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "legacy.apk")
    ag = _make_ag_result(permissions=[
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ])

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "legacy-job"), output_dir=tmp_path / "out")
    ids = {f.finding_id for f in report.findings}

    assert "APK_SMS_EXFILTRATION" not in ids
    assert "APK_HIGH_RISK_PERMISSION_READ_SMS" not in ids
    assert "APK_EXPORTED_COMPONENT" not in ids
    assert "APK_TOO_MANY_PERMISSIONS" not in ids


def test_manifest_features_written_correctly(tmp_path, monkeypatch):
    """manifest_analysis in features JSON must reflect permissions and exported components."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "manifest.apk")
    out_dir = tmp_path / "artifacts"

    service = ComponentInfo(
        type="service",
        name="com.example.SyncService",
        exported=True,
        permissions_required=None,
    )
    ag = _make_ag_result(
        permissions=[
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ],
        components=[service],
    )

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(pipeline_apk, "ag_to_findings", lambda _: [])

    report = run_pipeline(_make_request(apk, "manifest-job"), output_dir=out_dir)
    assert report.status == "success"

    features_file = out_dir / "manifest-job.features.json"
    assert features_file.exists()

    data = json.loads(features_file.read_text(encoding="utf-8"))
    ma = data["manifest_analysis"]

    assert ma["package_name"] == "com.example.testapp"
    assert ma["permissions_count"] == 2
    assert "android.permission.READ_CONTACTS" in ma["permissions"]
    assert ma["exported_count"] == 1
    assert "com.example.SyncService" in ma["exported_components"]


def test_androguard_missing_produces_info_finding(tmp_path, monkeypatch):
    """When androguard is unavailable, an info-level finding must be produced."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "noandroguard.apk")
    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", False)

    report = run_pipeline(_make_request(apk, "no-ag-job"))
    ids = {f.finding_id for f in report.findings}

    assert report.status == "success"
    assert "TOOL_ANDROGUARD_MISSING" in ids
