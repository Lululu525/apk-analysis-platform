"""
Tests for app.tools.parse_manifest — manifest feature extraction CLI.

The CLI reuses androguard_analyzer.analyze_apk under the hood, so the
tests monkeypatch analyze_apk to return a hand-built AnalysisResult and
assert the resulting JSON structure. A separate test covers the
RuntimeError branch when androguard is unavailable.
"""
from __future__ import annotations

import json
from pathlib import Path
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
    result.risk_findings = []
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
    assert comps["activities"] == ["com.example.MainActivity"]
    assert comps["services"] == ["com.example.SyncService"]
    assert comps["providers"] == ["com.example.UserProvider"]
    assert comps["receivers"] == ["com.example.BootReceiver"]

    # Provider has permissions_required, so it must NOT appear in exported_unprotected
    assert "com.example.UserProvider" not in features["exported_unprotected"]
    assert set(features["exported_unprotected"]) == {
        "com.example.MainActivity",
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
