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
    result.errors = []
    return result


def _model_features_stub(sample_id: str = "test-job") -> dict:
    return {
        "intent_rows": [{
            "sample_id": sample_id,
            "package_name": "com.example.testapp",
            "component_name": "<UNKNOWN>",
            "component_type": "<UNKNOWN>",
            "actions": [],
            "categories": [],
            "data_types": [],
            "data_schemes": [],
            "permission": None,
            "is_explicit": False,
            "source": "manifest_only",
        }],
        "filter_rows": [{
            "sample_id": sample_id,
            "package_name": "com.example.testapp",
            "component_name": "com.example.DataService",
            "component_type": "service",
            "actions": [],
            "categories": [],
            "data_types": [],
            "data_schemes": [],
            "permission": None,
            "exported": True,
            "protected": False,
        }],
        "resolution_rows": [{
            "sample_id": sample_id,
            "intent_component_name": "<UNKNOWN>",
            "intent_component_type": "<UNKNOWN>",
            "intent_actions": [],
            "intent_categories": [],
            "intent_data_types": [],
            "intent_data_schemes": [],
            "intent_permission": None,
            "filter_component_name": "com.example.DataService",
            "filter_component_type": "service",
            "filter_actions": [],
            "filter_categories": [],
            "filter_data_types": [],
            "filter_data_schemes": [],
            "filter_permission": None,
            "filter_exported": True,
            "filter_protected": False,
            "match_action": True,
            "match_category": True,
            "match_type": True,
            "caller_permission": None,
            "callee_permission": None,
            "risk_hint": "IPC_SERVICE_HIJACK",
        }],
        "app_summary": {"package_name": "com.example.testapp"},
    }


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
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

    report = run_pipeline(_make_request(apk, "sms-exfil-job"), output_dir=tmp_path / "out")
    ids = {f.id for f in report.findings}

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
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

    report = run_pipeline(_make_request(apk, "service-hijack-job"), output_dir=tmp_path / "out")
    ids = {f.id for f in report.findings}

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
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

    report = run_pipeline(_make_request(apk, "provider-job"), output_dir=tmp_path / "out")
    ids = {f.id for f in report.findings}

    assert report.status == "success"
    assert "IPC_PROVIDER_REDELEGATION" in ids


def test_apk_rules_module_must_not_exist():
    """Tripwire: app.apk_rules was deleted in Sprint 2 and must never be re-added.

    Rules that were previously here live in app.detectors.privilege_rules now.
    If this test fails, someone (or a bad merge) re-created apk_rules.py;
    check git history for the resurrection commit before re-deleting.
    """
    import importlib

    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("app.apk_rules")


def test_pipeline_apk_must_not_import_apk_rules():
    """Tripwire: pipeline_apk must not import deleted or legacy APK risk entrypoints."""
    from pathlib import Path

    source = Path(__file__).resolve().parent.parent / "app" / "pipeline_apk.py"
    text = source.read_text(encoding="utf-8")

    assert "from .apk_rules" not in text, (
        "pipeline_apk.py is importing from deleted apk_rules module"
    )
    assert "analyze_android_risk" not in text, (
        "pipeline_apk.py references analyze_android_risk (deleted in Sprint 2)"
    )
    assert "ag_to_findings" not in text
    assert "to_findings" not in text


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
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

    report = run_pipeline(_make_request(apk, "legacy-job"), output_dir=tmp_path / "out")
    ids = {f.id for f in report.findings}

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
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

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


def test_ml_features_artifact_written_correctly(tmp_path, monkeypatch):
    """Pipeline writes row-level ML features when the feature builder succeeds."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "ml.apk")
    out_dir = tmp_path / "artifacts"
    ag = _make_ag_result()

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

    report = run_pipeline(_make_request(apk, "ml-job"), output_dir=out_dir)

    assert report.status == "success"
    assert report.artifacts.ml_features_path == str(out_dir / "ml-job.ml_features.json")

    ml_features_file = out_dir / "ml-job.ml_features.json"
    assert ml_features_file.exists()

    data = json.loads(ml_features_file.read_text(encoding="utf-8"))
    assert set(data.keys()) == {
        "intent_rows",
        "filter_rows",
        "resolution_rows",
        "app_summary",
    }
    assert data["filter_rows"][0]["sample_id"] == "ml-job"


def test_ml_feature_extraction_failure_is_non_fatal(tmp_path, monkeypatch):
    """Feature-builder failures must not write half artifacts or fail the report."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "ml-fail.apk")
    out_dir = tmp_path / "artifacts"
    ag = _make_ag_result()

    def failing_stub(_apk, sample_id=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(pipeline_apk, "build_model_features", failing_stub)

    report = run_pipeline(_make_request(apk, "ml-fail-job"), output_dir=out_dir)
    ids = {f.id for f in report.findings}

    assert report.status == "success"
    assert report.artifacts.ml_features_path is None
    assert not (out_dir / "ml-fail-job.ml_features.json").exists()
    assert "ML_FEATURE_EXTRACTION_FAILED" in ids


def test_ml_predictions_written_when_model_available(tmp_path, monkeypatch):
    """Pipeline writes model predictions and surfaces the app-level ML risk."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "ml-predict.apk")
    out_dir = tmp_path / "artifacts"
    ag = _make_ag_result()
    predictions = [{
        "row_id": "ml-predict-job__filter__com.example.DataService",
        "row_type": "filter",
        "risk_probability": 0.9,
        "predicted_label": 1,
        "top_features": [],
        "model_version": "rf_filter_v1",
    }]

    class FakePredictor:
        def predict_raw_rows(self, raw_filter_rows):
            assert raw_filter_rows == _model_features_stub("ml-predict-job")["filter_rows"]
            return predictions

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )
    monkeypatch.setattr(
        pipeline_apk.FilterRowPredictor,
        "load",
        lambda _model_dir: FakePredictor(),
    )

    report = run_pipeline(_make_request(apk, "ml-predict-job"), output_dir=out_dir)
    ids = {f.id for f in report.findings}

    assert report.status == "success"
    assert report.artifacts.ml_predictions_path == str(
        out_dir / "ml-predict-job.ml_predictions.json"
    )
    predictions_file = out_dir / "ml-predict-job.ml_predictions.json"
    assert predictions_file.exists()
    assert json.loads(predictions_file.read_text(encoding="utf-8")) == predictions
    assert "ML_RISK_ASSESSMENT" in ids
    from app.report.builder import summarize

    scored_findings = [
        finding.model_copy(deep=True)
        for finding in report.findings
        if finding.id != "ML_RISK_ASSESSMENT"
    ]
    assert report.summary.risk_score == summarize(scored_findings).risk_score
    assert report.summary.counts["info"] == sum(
        finding.severity == "info" for finding in report.findings
    )


def test_model_not_available_finding_when_model_missing(tmp_path, monkeypatch):
    """A missing model is reported without failing the static-analysis pipeline."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "ml-model-missing.apk")
    out_dir = tmp_path / "artifacts"
    ag = _make_ag_result()

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )

    def missing_model(_model_dir):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(
        pipeline_apk.FilterRowPredictor,
        "load",
        missing_model,
    )

    report = run_pipeline(_make_request(apk, "ml-model-missing-job"), output_dir=out_dir)
    ids = {f.id for f in report.findings}

    assert report.status == "success"
    assert "MODEL_NOT_AVAILABLE" in ids
    assert report.artifacts.ml_predictions_path is None


def test_ml_prediction_failure_is_non_fatal(tmp_path, monkeypatch):
    """Prediction errors do not fail the report or leave a partial artifact."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "ml-prediction-fail.apk")
    out_dir = tmp_path / "artifacts"
    ag = _make_ag_result()

    class FailingPredictor:
        def predict_raw_rows(self, _raw_filter_rows):
            raise RuntimeError("prediction boom")

    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pipeline_apk, "analyze_apk", lambda _: ag)
    monkeypatch.setattr(
        pipeline_apk,
        "build_model_features",
        lambda _apk, sample_id=None: _model_features_stub(sample_id or "test-job"),
    )
    monkeypatch.setattr(
        pipeline_apk.FilterRowPredictor,
        "load",
        lambda _model_dir: FailingPredictor(),
    )

    report = run_pipeline(_make_request(apk, "ml-prediction-fail-job"), output_dir=out_dir)
    ids = {f.id for f in report.findings}

    assert report.status == "success"
    assert "ML_PREDICTION_FAILED" in ids
    assert report.artifacts.ml_predictions_path is None
    assert not (out_dir / "ml-prediction-fail-job.ml_predictions.json").exists()


def test_androguard_missing_produces_info_finding(tmp_path, monkeypatch):
    """When androguard is unavailable, an info-level finding must be produced."""
    import app.pipeline_apk as pipeline_apk

    apk = _make_apk(tmp_path, "noandroguard.apk")
    monkeypatch.setattr(pipeline_apk, "ANDROGUARD_AVAILABLE", False)

    report = run_pipeline(_make_request(apk, "no-ag-job"))
    ids = {f.id for f in report.findings}

    assert report.status == "success"
    assert "TOOL_ANDROGUARD_MISSING" in ids
