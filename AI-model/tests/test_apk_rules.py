"""Tests for Android-specific APK risk rules."""
from app.apk_rules import analyze_android_risk


class DummyAgResult:
    """Minimal fake androguard result for unit testing."""

    def __init__(self, success=True, permissions=None, exported_components=None):
        self.success = success
        self.permissions = permissions or []
        self.exported_components = exported_components or []


def _ids(findings):
    return {f.finding_id for f in findings}


def test_high_risk_permission_read_sms():
    ag = DummyAgResult(
        permissions=["android.permission.READ_SMS"]
    )
    findings = analyze_android_risk(ag)
    ids = _ids(findings)
    assert "APK_HIGH_RISK_PERMISSION_READ_SMS" in ids


def test_sms_exfiltration_combo():
    ag = DummyAgResult(
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        ]
    )
    findings = analyze_android_risk(ag)
    ids = _ids(findings)
    assert "APK_SMS_EXFILTRATION" in ids


def test_contacts_exfiltration_combo():
    ag = DummyAgResult(
        permissions=[
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ]
    )
    findings = analyze_android_risk(ag)
    ids = _ids(findings)
    assert "APK_CONTACTS_EXFILTRATION" in ids


def test_audio_spying_combo():
    ag = DummyAgResult(
        permissions=[
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
        ]
    )
    findings = analyze_android_risk(ag)
    ids = _ids(findings)
    assert "APK_AUDIO_SPYING" in ids


def test_exported_component():
    ag = DummyAgResult(
        permissions=[],
        exported_components=["com.example.MainActivity"]
    )
    findings = analyze_android_risk(ag)
    ids = _ids(findings)
    assert "APK_EXPORTED_COMPONENT" in ids


def test_too_many_permissions():
    perms = [f"android.permission.TEST_{i}" for i in range(16)]
    ag = DummyAgResult(permissions=perms)
    findings = analyze_android_risk(ag)
    ids = _ids(findings)
    assert "APK_TOO_MANY_PERMISSIONS" in ids


def test_failed_result_returns_empty():
    ag = DummyAgResult(success=False)
    findings = analyze_android_risk(ag)
    assert findings == []