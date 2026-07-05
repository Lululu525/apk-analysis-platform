"""Tests for Android static findings derived from extracted AnalysisResult facts."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

from app.detectors.android_static_detector import findings_from_analysis
from app.extractors.androguard_analyzer import (
    AnalysisResult,
    ComponentInfo,
    PermissionInfo,
    _extract_components,
)


def _result() -> AnalysisResult:
    result = AnalysisResult(success=True)
    result.package_name = "com.example.app"
    result.permissions = {}
    result.components = []
    result.sensitive_api_calls = []
    result.target_sdk = 33
    return result


def _ids(result: AnalysisResult) -> set[str]:
    return {finding.id for finding in findings_from_analysis(result)}


def test_failed_result_returns_empty():
    assert findings_from_analysis(AnalysisResult(success=False)) == []


def test_dangerous_permissions_grouped_by_risk_level():
    result = _result()
    result.permissions = {
        "android.permission.READ_SMS": PermissionInfo(
            name="android.permission.READ_SMS",
            risk_level="高風險",
            is_declared=True,
        ),
        "android.permission.INTERNET": PermissionInfo(
            name="android.permission.INTERNET",
            risk_level="中風險",
            is_declared=True,
        ),
    }

    ids = _ids(result)

    assert "DANGEROUS_PERMISSIONS_高" in ids
    assert "DANGEROUS_PERMISSIONS_中" in ids


def test_exported_unprotected_activity_finding():
    result = _result()
    result.components = [
        ComponentInfo(
            type="activity",
            name="com.example.PublicActivity",
            exported=True,
            permissions_required=None,
        )
    ]

    findings = findings_from_analysis(result)
    finding = next(f for f in findings if f.id == "EXPORTED_UNPROTECTED_ACTIVITY")

    assert finding.severity == "medium"
    assert finding.evidence["components"][0]["name"] == "com.example.PublicActivity"


def test_exported_unprotected_receiver_finding():
    result = _result()
    result.components = [
        ComponentInfo(
            type="receiver",
            name="com.example.PublicReceiver",
            exported=True,
            permissions_required=None,
        )
    ]

    assert "EXPORTED_UNPROTECTED_RECEIVER" in _ids(result)


def test_service_and_provider_left_to_privilege_rules():
    result = _result()
    result.components = [
        ComponentInfo(
            type="service",
            name="com.example.PublicService",
            exported=True,
            permissions_required=None,
        ),
        ComponentInfo(
            type="provider",
            name="com.example.PublicProvider",
            exported=True,
            permissions_required=None,
        ),
    ]

    ids = _ids(result)

    assert "EXPORTED_UNPROTECTED_SERVICE" not in ids
    assert "EXPORTED_UNPROTECTED_PROVIDER" not in ids


def test_sensitive_api_calls_finding():
    result = _result()
    result.sensitive_api_calls = [
        "java/lang/Runtime/exec",
        "java/lang/reflect/Method/invoke",
    ]

    finding = next(f for f in findings_from_analysis(result) if f.id == "SENSITIVE_API_CALLS")

    assert finding.severity == "medium"
    assert "java/lang/Runtime/exec" in finding.evidence["calls"]


def test_low_target_sdk_finding():
    result = _result()
    result.target_sdk = 22

    finding = next(f for f in findings_from_analysis(result) if f.id == "LOW_TARGET_SDK")

    assert finding.evidence["target_sdk"] == 22


def test_activity_with_android_permission_attr_parsed_correctly():
    """Regression: exported activity with android:permission should have
    permissions_required populated (not None) after _extract_components fix."""
    NS = "http://schemas.android.com/apk/res/android"
    manifest_xml = ET.fromstring(
        f'<manifest xmlns:android="{NS}" package="com.example.app">'
        f'  <application>'
        f'    <activity'
        f'      android:name="com.example.ProtectedActivity"'
        f'      android:exported="true"'
        f'      android:permission="com.example.permission.ACCESS_PROTECTED" />'
        f'  </application>'
        f'</manifest>'
    )

    mock_axml = MagicMock()
    mock_axml.get_xml_obj.return_value = manifest_xml
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_axml.return_value = mock_axml

    components = _extract_components(mock_apk)
    activity = next(c for c in components if c.type == "activity")

    assert activity.exported is True
    assert activity.permissions_required is not None
    assert "com.example.permission.ACCESS_PROTECTED" in activity.permissions_required
