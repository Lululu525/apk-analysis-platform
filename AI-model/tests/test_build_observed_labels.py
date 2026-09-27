import pytest

from app.tools import build_observed_labels as lf
from app.tools.canonical_dataset_pilot import ENTRY_METHODS as CANONICAL_ENTRY_METHODS


def _unit(**overrides):
    unit = {
        "review_unit_id": "review-unit-v1:" + "0" * 8,
        "sha256": "a" * 64,
        "component_name": "com.example.Recv",
        "component_type": "receiver",
        "caller_method": "onReceive",
        "linkage_status": "direct_entry_caller",
        "sink_class": "java/lang/reflect/Method",
        "sink_method": "invoke",
        "sink_group_id": "SENSITIVE_API_CODE_EXEC",
    }
    unit.update(overrides)
    return unit


def _manifest(uses_permissions=()):
    return {"uses_permissions": list(uses_permissions)}


def test_entry_method_in_a_component_class_is_positive():
    assert lf.label(_unit(), _manifest()) == (
        "positive",
        "positive_i_trigger_and_s_linkage",
    )


def test_non_entry_method_is_negative_on_i():
    """sink 在非 entry method 裡，要到達需要未分析的內部呼叫鏈，I 不成立。"""
    observed, reason = lf.label(_unit(caller_method="bindRowToViews"), _manifest())

    assert observed == "negative"
    assert reason == "i_refuted_not_entry_method"


def test_i_is_checked_before_s():
    """順序依 guide 的 I → S；I 已否定時不得回報 S 的 reason code。"""
    unit = _unit(
        caller_method="helper",  # 非 entry method
        linkage_status=lf.UNLINKED,  # S 也不明
        sink_class="android/telephony/SmsManager",
        sink_method="sendTextMessage",  # 且 permission 未宣告
    )

    observed, reason = lf.label(unit, _manifest())

    assert observed == "negative"
    assert reason == "i_refuted_not_entry_method"


def test_undeclared_sink_permission_refutes_s():
    unit = _unit(
        sink_class="android/telephony/SmsManager",
        sink_method="sendTextMessage",
        sink_group_id="SENSITIVE_API_SMS_PHONE",
    )

    observed, reason = lf.label(unit, _manifest(["android.permission.INTERNET"]))

    assert observed == "negative"
    assert reason == "s_refuted_sink_permission_undeclared"


def test_declared_sink_permission_does_not_refute_s():
    unit = _unit(
        sink_class="android/telephony/SmsManager",
        sink_method="sendTextMessage",
        sink_group_id="SENSITIVE_API_SMS_PHONE",
    )

    observed, _ = lf.label(unit, _manifest(["android.permission.SEND_SMS"]))

    assert observed == "positive"


def test_sink_without_governing_permission_never_refutes_s():
    """CODE_EXEC 沒有 permission 管轄，不得因為 APK 什麼都沒宣告就判 negative。"""
    observed, _ = lf.label(_unit(), _manifest([]))

    assert observed == "positive"


def test_unlinked_caller_abstains_rather_than_being_negative():
    """S 證據不足不等於 S 被否定（ADR-0001：unknown 不得強迫二分類）。"""
    observed, reason = lf.label(_unit(linkage_status=lf.UNLINKED), _manifest())

    assert observed is None
    assert reason == "s_unknown_caller_class_not_component"


def test_entry_methods_deliberately_extend_the_canonical_set():
    """spec §3.1：刻意比 canonical 寬，且分歧必須是可稽核的。"""
    extra = {
        component_type: sorted(methods - CANONICAL_ENTRY_METHODS.get(component_type, set()))
        for component_type, methods in lf.ENTRY_METHODS.items()
    }

    assert extra["activity"] == ["onResume", "onStart"]
    assert extra["service"] == ["onHandleIntent", "onStart"]
    assert extra["receiver"] == []
    assert extra["provider"] == ["getType"]
    # 不得納入外部無法直接觸發的 callback。
    assert "onActivityResult" not in lf.ENTRY_METHODS["activity"]
    assert "onRestart" not in lf.ENTRY_METHODS["activity"]


def test_externally_triggerable_lifecycle_methods_are_entry_methods():
    for component_type, method in [
        ("activity", "onStart"),
        ("activity", "onResume"),
        ("service", "onStart"),
        ("service", "onHandleIntent"),
        ("provider", "getType"),
    ]:
        unit = _unit(component_type=component_type, caller_method=method)
        assert lf.is_entry_method(unit), f"{component_type}.{method} 應視為 entry method"


def test_unknown_component_type_raises():
    with pytest.raises(ValueError, match="component_type"):
        lf.label(_unit(component_type="activity-alias"), _manifest())


def test_summary_counts_abstain_separately_from_binary():
    rows = [
        {"review_unit_id": "u1", "observed_authz_label": "positive", "reason_code": "a"},
        {"review_unit_id": "u2", "observed_authz_label": "negative", "reason_code": "b"},
        {"review_unit_id": "u3", "observed_authz_label": "negative", "reason_code": "b"},
        {"review_unit_id": "u4", "observed_authz_label": None, "reason_code": "c"},
    ]

    summary = lf.summarise(rows)

    assert summary["units"] == 4
    assert summary["trainable_units"] == 3
    assert summary["abstain"] == 1
    assert summary["positive_share_of_binary"] == pytest.approx(1 / 3)
    assert summary["reason_codes"] == {"a": 1, "b": 2, "c": 1}


def test_lf_does_not_read_exported_or_permission_of_the_component():
    """R 由 r_gate 處理；exported 不得進入訓練標籤（ADR-0002）。

    manifest 只提供 uses_permissions；component 層級的 exported／permission 完全沒給，
    LF 仍必須能判定。
    """
    observed, _ = lf.label(_unit(), {"uses_permissions": []})

    assert observed == "positive"
