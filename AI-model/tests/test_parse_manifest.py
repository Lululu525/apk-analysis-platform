"""
Tests for app.tools.parse_manifest — manifest feature extraction CLI.

The CLI reuses androguard_analyzer.analyze_apk under the hood, so the
tests monkeypatch analyze_apk to return a hand-built AnalysisResult and
assert the resulting JSON structure. A separate test covers the
RuntimeError branch when androguard is unavailable.
"""
from __future__ import annotations

import json
from typing import Dict, List

import pytest

from app.extractors.androguard_analyzer import (
    AnalysisResult,
    ComponentInfo,
    PermissionInfo,
)
from app.tools import parse_manifest as pm


def _ag_result() -> AnalysisResult:
    """Minimal AnalysisResult with one of each component type and a
    couple of intent-filters to exercise the flattener.
    """
    result = AnalysisResult(success=True)
    result.package_name = "com.example.app"
    result.version_code = 42
    result.version_name = "1.2.3"
    result.min_sdk = 21
    result.target_sdk = 33
    result.permissions = {
        "android.permission.INTERNET": PermissionInfo(
            name="android.permission.INTERNET", risk_level="中風險", is_declared=True
        ),
        "android.permission.READ_SMS": PermissionInfo(
            name="android.permission.READ_SMS", risk_level="高風險", is_declared=True
        ),
    }
    result.components = [
        ComponentInfo(
            type="activity",
            name="com.example.MainActivity",
            exported=True,
            intent_filters=[{
                "actions": ["android.intent.action.MAIN"],
                "categories": ["android.intent.category.LAUNCHER"],
            }],
        ),
        ComponentInfo(
            type="activity",
            name="com.example.ShareActivity",
            exported=True,
            intent_filters=[{
                "actions": ["android.intent.action.SEND"],
                "categories": ["android.intent.category.DEFAULT"],
                "data_types": ["image/*"],
            }],
        ),
        ComponentInfo(
            type="service",
            name="com.example.SyncService",
            exported=True,
            permissions_required=None,
        ),
        ComponentInfo(
            type="provider",
            name="com.example.UserProvider",
            exported=True,
            permissions_required=["com.example.permission.READ_USERS"],
        ),
        ComponentInfo(
            type="receiver",
            name="com.example.BootReceiver",
            exported=True,
            intent_filters=[{
                "actions": ["android.intent.action.BOOT_COMPLETED"],
            }],
        ),
    ]
    result.sensitive_api_calls = []
    result.errors = []
    return result


def test_build_features_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    features = pm.build_features(tmp_path / "does-not-matter.apk")

    assert features["package_name"] == "com.example.app"
    assert features["version_code"] == 42
    assert features["version_name"] == "1.2.3"
    assert features["min_sdk"] == 21
    assert features["target_sdk"] == 33

    assert features["permission_count"] == 2
    assert features["permissions"] == [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
    ]

    comps: Dict[str, List[str]] = features["components"]
    assert comps["activities"] == [
        "com.example.MainActivity",
        "com.example.ShareActivity",
    ]
    assert comps["services"] == ["com.example.SyncService"]
    assert comps["providers"] == ["com.example.UserProvider"]
    assert comps["receivers"] == ["com.example.BootReceiver"]

    # Provider has permissions_required, so it must NOT appear in exported_unprotected
    assert "com.example.UserProvider" not in features["exported_unprotected"]
    assert set(features["exported_unprotected"]) == {
        "com.example.MainActivity",
        "com.example.ShareActivity",
        "com.example.SyncService",
        "com.example.BootReceiver",
    }


def test_intents_flattened(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    features = pm.build_features(tmp_path / "x.apk")
    intents = features["intents"]

    main_row = next(i for i in intents if i["action"] == "android.intent.action.MAIN")
    assert main_row == {
        "component": "com.example.MainActivity",
        "action": "android.intent.action.MAIN",
        "category": "android.intent.category.LAUNCHER",
        "data_scheme": None,
        "data_type": None,
        "permission": None,
    }

    boot_row = next(
        i for i in intents if i["action"] == "android.intent.action.BOOT_COMPLETED"
    )
    assert boot_row["component"] == "com.example.BootReceiver"
    assert boot_row["category"] is None
    assert boot_row["permission"] is None

    send_row = next(
        i for i in intents if i["action"] == "android.intent.action.SEND"
    )
    assert send_row == {
        "component": "com.example.ShareActivity",
        "action": "android.intent.action.SEND",
        "category": "android.intent.category.DEFAULT",
        "data_scheme": None,
        "data_type": "image/*",
        "permission": None,
    }


def test_build_features_raises_when_androguard_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", False)

    with pytest.raises(RuntimeError, match="androguard"):
        pm.build_features(tmp_path / "x.apk")


def test_build_features_raises_on_parse_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(
        pm, "analyze_apk",
        lambda _: AnalysisResult(success=False, errors=["bad zip"]),
    )

    with pytest.raises(ValueError, match="bad zip"):
        pm.build_features(tmp_path / "x.apk")


def test_cli_writes_to_out_file(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"not a real apk")
    out = tmp_path / "out" / "features.json"

    rc = pm.main([str(apk), "--out", str(out), "--pretty"])
    assert rc == 0
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["package_name"] == "com.example.app"
    assert data["permission_count"] == 2


def test_cli_returns_error_code_for_missing_apk(tmp_path, capsys):
    rc = pm.main([str(tmp_path / "nope.apk")])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


# ── Unit test for the XML-level extractor ─────────────────────────────────────
# Guards the contract that _extract_intent_filters actually pulls
# android:mimeType from <data> elements. If this breaks, parse_manifest's
# data_type column silently goes back to None.

def test_extract_intent_filters_captures_mimetype():
    from xml.etree import ElementTree as ET

    from app.extractors.androguard_analyzer import _extract_intent_filters

    xml = """
    <activity xmlns:android="http://schemas.android.com/apk/res/android">
      <intent-filter>
        <action android:name="android.intent.action.SEND"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:mimeType="image/*"/>
        <data android:scheme="content"/>
      </intent-filter>
    </activity>
    """
    elem = ET.fromstring(xml)
    filters = _extract_intent_filters(elem)

    assert len(filters) == 1
    f = filters[0]
    assert f["actions"] == ["android.intent.action.SEND"]
    assert f["categories"] == ["android.intent.category.DEFAULT"]
    assert f["data_schemes"] == ["content"]
    assert f["data_types"] == ["image/*"]


# ── build_model_features tests ────────────────────────────────────────────────

def test_build_model_features_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    out = pm.build_model_features(tmp_path / "app.apk", sample_id="test-001")

    assert set(out.keys()) == {"intent_rows", "filter_rows", "resolution_rows", "app_summary"}
    # app_summary must be identical to build_features()
    summary = pm.build_features(tmp_path / "app.apk")
    assert out["app_summary"] == summary
    # 1:1:1 invariant
    assert len(out["intent_rows"]) == len(out["filter_rows"])
    assert len(out["resolution_rows"]) == len(out["filter_rows"])
    # fixture produces 5 filter_rows: MainActivity(1), ShareActivity(1),
    # SyncService(1,no-filter), UserProvider(1,no-filter), BootReceiver(1)
    assert len(out["filter_rows"]) == 5


def test_build_model_features_sample_id_default(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    apk = tmp_path / "myapp.apk"
    out = pm.build_model_features(apk)
    assert out["filter_rows"][0]["sample_id"] == "myapp"


def test_filter_rows_component_fields(monkeypatch, tmp_path):
    """Every filter_row carries component_name, component_type, exported, protected."""
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["filter_rows"]
    for row in rows:
        assert "component_name" in row
        assert "component_type" in row
        assert isinstance(row["exported"], bool)
        assert isinstance(row["protected"], bool)


def test_filter_rows_protected_vs_unprotected(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["filter_rows"]
    by_comp = {r["component_name"]: r for r in rows}

    # UserProvider has permissions_required → protected=True
    assert by_comp["com.example.UserProvider"]["protected"] is True
    assert by_comp["com.example.UserProvider"]["permission"] == "com.example.permission.READ_USERS"
    # SyncService has no permissions_required → protected=False
    assert by_comp["com.example.SyncService"]["protected"] is False
    assert by_comp["com.example.SyncService"]["permission"] is None


def test_filter_rows_exported_without_intent_filter(monkeypatch, tmp_path):
    """Exported components with no intent-filter still emit one all-None filter_row."""
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["filter_rows"]
    by_comp = {r["component_name"]: r for r in rows}

    for name in ("com.example.SyncService", "com.example.UserProvider"):
        row = by_comp[name]
        assert row["action"] is None
        assert row["category"] is None
        assert row["data_type"] is None


def test_filter_rows_multiple_intent_filters(monkeypatch, tmp_path):
    """A component with 2 intent-filters produces 2+ filter_rows."""
    result = _ag_result()
    result.components = [
        ComponentInfo(
            type="activity",
            name="com.example.MultiFilter",
            exported=True,
            intent_filters=[
                {"actions": ["android.intent.action.VIEW"]},
                {"actions": ["android.intent.action.EDIT"]},
            ],
        )
    ]
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: result)

    rows = pm.build_model_features(tmp_path / "app.apk")["filter_rows"]
    actions = [r["action"] for r in rows]
    assert "android.intent.action.VIEW" in actions
    assert "android.intent.action.EDIT" in actions
    assert len(rows) == 2


def test_filter_rows_missing_action(monkeypatch, tmp_path):
    """Intent-filter with no <action> produces a row with action=None."""
    result = _ag_result()
    result.components = [
        ComponentInfo(
            type="activity",
            name="com.example.NoAction",
            exported=True,
            intent_filters=[{"categories": ["android.intent.category.DEFAULT"]}],
        )
    ]
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: result)

    rows = pm.build_model_features(tmp_path / "app.apk")["filter_rows"]
    assert len(rows) == 1
    assert rows[0]["action"] is None
    assert rows[0]["category"] == "android.intent.category.DEFAULT"


def test_intent_rows_manifest_only_fields(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["intent_rows"]
    for row in rows:
        assert row["component_name"] == "<UNKNOWN>"
        assert row["component_type"] == "<UNKNOWN>"
        assert row["is_explicit"] is False
        assert row["source"] == "manifest_only"
        assert row["permission"] is None


def test_resolution_rows_risk_hint_service_hijack(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["resolution_rows"]
    service_row = next(r for r in rows if r["filter_component_name"] == "com.example.SyncService")
    assert service_row["risk_hint"] == "IPC_SERVICE_HIJACK"


def test_resolution_rows_risk_hint_broadcast_theft(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["resolution_rows"]
    boot_row = next(r for r in rows if r["filter_component_name"] == "com.example.BootReceiver")
    assert boot_row["risk_hint"] == "IPC_BROADCAST_THEFT"


def test_resolution_rows_risk_hint_confused_deputy(monkeypatch, tmp_path):
    # _ag_result has READ_SMS in permissions → activities get CONFUSED_DEPUTY
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["resolution_rows"]
    main_row = next(r for r in rows if r["filter_component_name"] == "com.example.MainActivity")
    assert main_row["risk_hint"] == "IPC_CONFUSED_DEPUTY"


def test_resolution_rows_protected_no_hint(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(pm, "analyze_apk", lambda _: _ag_result())

    rows = pm.build_model_features(tmp_path / "app.apk")["resolution_rows"]
    provider_row = next(r for r in rows if r["filter_component_name"] == "com.example.UserProvider")
    assert provider_row["risk_hint"] is None


def test_build_model_features_raises_when_androguard_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="androguard"):
        pm.build_model_features(tmp_path / "app.apk")


def test_build_model_features_raises_on_parse_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    monkeypatch.setattr(
        pm,
        "analyze_apk",
        lambda _: AnalysisResult(success=False, errors=["bad zip"]),
    )

    with pytest.raises(ValueError, match="bad zip"):
        pm.build_model_features(tmp_path / "app.apk")


def test_risk_hint_values_align_with_privilege_rules(monkeypatch, tmp_path):
    """Lock parse_manifest risk hints to privilege_rules' public finding IDs."""
    from app.detectors.privilege_rules import check_combinations

    monkeypatch.setattr(pm, "ANDROGUARD_AVAILABLE", True)
    result = _ag_result()
    monkeypatch.setattr(pm, "analyze_apk", lambda _: result)

    rule_ids = {finding.id for finding in check_combinations(result)}
    hints = {
        row["risk_hint"]
        for row in pm.build_model_features(tmp_path / "app.apk")["resolution_rows"]
        if row["risk_hint"] is not None
    }
    normalized_rule_ids = set(rule_ids)
    if any(rule_id.startswith("IPC_BROADCAST_THEFT_") for rule_id in rule_ids):
        normalized_rule_ids.add("IPC_BROADCAST_THEFT")

    assert hints.issubset(normalized_rule_ids)


def test_extract_intent_filters_omits_empty_data_keys():
    """When <data> has neither scheme nor mimeType, the dict should not
    contain empty data_schemes / data_types keys."""
    from xml.etree import ElementTree as ET

    from app.extractors.androguard_analyzer import _extract_intent_filters

    xml = """
    <activity xmlns:android="http://schemas.android.com/apk/res/android">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    """
    elem = ET.fromstring(xml)
    filters = _extract_intent_filters(elem)

    assert filters == [{"actions": ["android.intent.action.MAIN"]}]
