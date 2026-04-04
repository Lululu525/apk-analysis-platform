"""
Unit tests for app/detectors/privilege_rules.py

Coverage:
  Layer 1 — OVER_PRIVILEGE threshold
  Layer 2 — 7 combination rules (COMBO_*)
  Layer 3 — 4 IPC privilege escalation rules (IPC_*)
  Edge cases — failed result, None fields
"""
import pytest
from app.detectors.privilege_rules import check_combinations
from app.extractors.androguard_analyzer import AnalysisResult, ComponentInfo


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_result(permissions=None, components=None, success=True) -> AnalysisResult:
    """Build a minimal AnalysisResult for testing.

    permissions: list of permission name strings (converted to dict internally)
    components:  list of ComponentInfo objects
    """
    result = AnalysisResult(success=success)
    result.permissions = {p: None for p in (permissions or [])}
    result.components = components or []
    return result


def _make_component(comp_type, name, exported=True, permissions_required=None,
                    intent_actions=None) -> ComponentInfo:
    intent_filters = []
    if intent_actions:
        intent_filters = [{"actions": intent_actions}]
    return ComponentInfo(
        type=comp_type,
        name=name,
        exported=exported,
        permissions_required=permissions_required,
        intent_filters=intent_filters,
    )


def _ids(findings):
    return {f.finding_id for f in findings}


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_failed_result_returns_empty():
    result = _make_result(success=False)
    assert check_combinations(result) == []


def test_none_result_returns_empty():
    assert check_combinations(None) == []


def test_empty_permissions_and_components_no_crash():
    result = _make_result()
    findings = check_combinations(result)
    assert isinstance(findings, list)


def test_none_permissions_no_crash():
    result = AnalysisResult(success=True)
    result.permissions = None
    result.components = []
    findings = check_combinations(result)
    assert isinstance(findings, list)


def test_none_components_no_crash():
    result = AnalysisResult(success=True)
    result.permissions = {}
    result.components = None
    findings = check_combinations(result)
    assert isinstance(findings, list)


# ── Layer 1: Over-privilege ───────────────────────────────────────────────────

def test_over_privilege_fires_above_threshold():
    perms = [f"android.permission.PERM_{i}" for i in range(26)]
    result = _make_result(permissions=perms)
    assert "OVER_PRIVILEGE" in _ids(check_combinations(result))


def test_over_privilege_not_fired_at_threshold():
    perms = [f"android.permission.PERM_{i}" for i in range(25)]
    result = _make_result(permissions=perms)
    assert "OVER_PRIVILEGE" not in _ids(check_combinations(result))


def test_over_privilege_severity_is_high():
    perms = [f"android.permission.PERM_{i}" for i in range(26)]
    result = _make_result(permissions=perms)
    finding = next(f for f in check_combinations(result) if f.finding_id == "OVER_PRIVILEGE")
    assert finding.severity == "high"


def test_over_privilege_evidence_contains_count():
    perms = [f"android.permission.PERM_{i}" for i in range(30)]
    result = _make_result(permissions=perms)
    finding = next(f for f in check_combinations(result) if f.finding_id == "OVER_PRIVILEGE")
    assert finding.evidence["permission_count"] == 30


# ── Layer 2: Combination rules ────────────────────────────────────────────────

def test_combo_stalkerware_all_three_perms():
    result = _make_result(permissions=[
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
    ])
    assert "COMBO_STALKERWARE" in _ids(check_combinations(result))


def test_combo_stalkerware_partial_no_trigger():
    result = _make_result(permissions=[
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        # ACCESS_FINE_LOCATION absent
    ])
    assert "COMBO_STALKERWARE" not in _ids(check_combinations(result))


def test_combo_sms_exfil():
    result = _make_result(permissions=[
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ])
    assert "COMBO_SMS_EXFIL" in _ids(check_combinations(result))


def test_combo_sms_exfil_no_internet_no_trigger():
    result = _make_result(permissions=["android.permission.READ_SMS"])
    assert "COMBO_SMS_EXFIL" not in _ids(check_combinations(result))


def test_combo_audio_exfil():
    result = _make_result(permissions=[
        "android.permission.RECORD_AUDIO",
        "android.permission.INTERNET",
    ])
    assert "COMBO_AUDIO_EXFIL" in _ids(check_combinations(result))


def test_combo_contact_exfil():
    result = _make_result(permissions=[
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
    ])
    assert "COMBO_CONTACT_EXFIL" in _ids(check_combinations(result))


def test_combo_call_intercept():
    result = _make_result(permissions=[
        "android.permission.READ_CALL_LOG",
        "android.permission.RECORD_AUDIO",
    ])
    assert "COMBO_CALL_INTERCEPT" in _ids(check_combinations(result))


def test_combo_overlay_abuse():
    result = _make_result(permissions=[
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ])
    assert "COMBO_OVERLAY_ABUSE" in _ids(check_combinations(result))


def test_combo_location_exfil():
    result = _make_result(permissions=[
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.INTERNET",
    ])
    assert "COMBO_LOCATION_EXFIL" in _ids(check_combinations(result))


def test_combo_severity_critical_for_sms_exfil():
    result = _make_result(permissions=[
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ])
    finding = next(f for f in check_combinations(result) if f.finding_id == "COMBO_SMS_EXFIL")
    assert finding.severity == "critical"


def test_combo_evidence_lists_matched_permissions():
    result = _make_result(permissions=[
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
    ])
    finding = next(f for f in check_combinations(result) if f.finding_id == "COMBO_CONTACT_EXFIL")
    matched = set(finding.evidence["matched_permissions"])
    assert "android.permission.READ_CONTACTS" in matched
    assert "android.permission.INTERNET" in matched


def test_multiple_combos_can_trigger_simultaneously():
    result = _make_result(permissions=[
        "android.permission.READ_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.INTERNET",
    ])
    ids = _ids(check_combinations(result))
    assert "COMBO_SMS_EXFIL" in ids
    assert "COMBO_AUDIO_EXFIL" in ids


# ── Layer 3a: Service Hijacking ───────────────────────────────────────────────

def test_ipc_service_hijack_unprotected():
    service = _make_component("service", "com.example.DataService",
                               exported=True, permissions_required=None)
    result = _make_result(components=[service])
    assert "IPC_SERVICE_HIJACK" in _ids(check_combinations(result))


def test_ipc_service_hijack_not_fired_when_protected():
    service = _make_component("service", "com.example.DataService",
                               exported=True,
                               permissions_required=["com.example.BIND"])
    result = _make_result(components=[service])
    assert "IPC_SERVICE_HIJACK" not in _ids(check_combinations(result))


def test_ipc_service_hijack_not_fired_when_not_exported():
    service = _make_component("service", "com.example.DataService",
                               exported=False)
    result = _make_result(components=[service])
    assert "IPC_SERVICE_HIJACK" not in _ids(check_combinations(result))


def test_ipc_service_hijack_evidence_lists_service_name():
    service = _make_component("service", "com.example.SecretService",
                               exported=True, permissions_required=None)
    result = _make_result(components=[service])
    finding = next(f for f in check_combinations(result)
                   if f.finding_id == "IPC_SERVICE_HIJACK")
    assert "com.example.SecretService" in finding.evidence["services"]


# ── Layer 3b: Broadcast Theft ─────────────────────────────────────────────────

def test_ipc_broadcast_theft_sensitive_action():
    receiver = _make_component(
        "receiver", "com.example.SmsReceiver",
        exported=True, permissions_required=None,
        intent_actions=["android.provider.Telephony.SMS_RECEIVED"],
    )
    result = _make_result(components=[receiver])
    ids = _ids(check_combinations(result))
    assert any(i.startswith("IPC_BROADCAST_THEFT_") for i in ids)


def test_ipc_broadcast_theft_non_sensitive_action_no_trigger():
    receiver = _make_component(
        "receiver", "com.example.MyReceiver",
        exported=True, permissions_required=None,
        intent_actions=["com.example.SOME_CUSTOM_ACTION"],
    )
    result = _make_result(components=[receiver])
    ids = _ids(check_combinations(result))
    assert not any(i.startswith("IPC_BROADCAST_THEFT_") for i in ids)


def test_ipc_broadcast_theft_protected_receiver_no_trigger():
    receiver = _make_component(
        "receiver", "com.example.SmsReceiver",
        exported=True,
        permissions_required=["android.permission.RECEIVE_SMS"],
        intent_actions=["android.provider.Telephony.SMS_RECEIVED"],
    )
    result = _make_result(components=[receiver])
    ids = _ids(check_combinations(result))
    assert not any(i.startswith("IPC_BROADCAST_THEFT_") for i in ids)


def test_ipc_broadcast_theft_boot_completed():
    receiver = _make_component(
        "receiver", "com.example.BootReceiver",
        exported=True, permissions_required=None,
        intent_actions=["android.intent.action.BOOT_COMPLETED"],
    )
    result = _make_result(components=[receiver])
    ids = _ids(check_combinations(result))
    assert any(i.startswith("IPC_BROADCAST_THEFT_") for i in ids)


# ── Layer 3c: Confused Deputy ─────────────────────────────────────────────────

def test_ipc_confused_deputy_fires_with_dangerous_perm():
    activity = _make_component("activity", "com.example.ShareActivity",
                                exported=True, permissions_required=None)
    result = _make_result(
        permissions=["android.permission.READ_SMS"],
        components=[activity],
    )
    assert "IPC_CONFUSED_DEPUTY" in _ids(check_combinations(result))


def test_ipc_confused_deputy_no_dangerous_perm_no_trigger():
    activity = _make_component("activity", "com.example.ShareActivity",
                                exported=True, permissions_required=None)
    result = _make_result(
        permissions=["android.permission.VIBRATE"],  # not in DANGEROUS_PERMS_FOR_DEPUTY
        components=[activity],
    )
    assert "IPC_CONFUSED_DEPUTY" not in _ids(check_combinations(result))


def test_ipc_confused_deputy_protected_activity_no_trigger():
    activity = _make_component("activity", "com.example.ShareActivity",
                                exported=True,
                                permissions_required=["com.example.ACCESS"])
    result = _make_result(
        permissions=["android.permission.READ_CONTACTS"],
        components=[activity],
    )
    assert "IPC_CONFUSED_DEPUTY" not in _ids(check_combinations(result))


def test_ipc_confused_deputy_evidence_lists_perms_and_activities():
    activity = _make_component("activity", "com.example.DeputyActivity",
                                exported=True, permissions_required=None)
    result = _make_result(
        permissions=["android.permission.CAMERA"],
        components=[activity],
    )
    finding = next(f for f in check_combinations(result)
                   if f.finding_id == "IPC_CONFUSED_DEPUTY")
    assert "com.example.DeputyActivity" in finding.evidence["unprotected_activities"]
    assert "android.permission.CAMERA" in finding.evidence["dangerous_permissions_held"]


# ── Layer 3d: ContentProvider re-delegation ───────────────────────────────────

def test_ipc_provider_redelegation_unprotected():
    provider = _make_component("provider", "com.example.DataProvider",
                                exported=True, permissions_required=None)
    result = _make_result(components=[provider])
    assert "IPC_PROVIDER_REDELEGATION" in _ids(check_combinations(result))


def test_ipc_provider_redelegation_protected_no_trigger():
    provider = _make_component("provider", "com.example.DataProvider",
                                exported=True,
                                permissions_required=["com.example.READ_DATA"])
    result = _make_result(components=[provider])
    assert "IPC_PROVIDER_REDELEGATION" not in _ids(check_combinations(result))


def test_ipc_provider_redelegation_severity_critical():
    provider = _make_component("provider", "com.example.DataProvider",
                                exported=True, permissions_required=None)
    result = _make_result(components=[provider])
    finding = next(f for f in check_combinations(result)
                   if f.finding_id == "IPC_PROVIDER_REDELEGATION")
    assert finding.severity == "critical"
