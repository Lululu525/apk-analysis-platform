import pytest

from app.tools import build_authz_features as features

BANNED_TOKENS = (
    "exported",
    "protected",
    "linkage",
    "sha256",
    "package",
    "permission_",
    "risk_hint",
    "uses_permissions",
    "min_sdk",
    "target_sdk",
    "call_offset",
    "lifecycle",
    "intent_filter",
    "category",
    "scheme",
    "mime",
)


def _unit(**overrides):
    unit = {
        "review_unit_id": "review-unit-v1:" + "0" * 8,
        "sha256": "a" * 64,
        "component_name": "com.example.Recv",
        "component_type": "receiver",
        "sink_class": "java/lang/reflect/Method",
        "sink_method": "invoke",
        "sink_group_id": "SENSITIVE_API_CODE_EXEC",
    }
    unit.update(overrides)
    return unit


def _manifest(actions=(), uses_permissions=(), declarations=1):
    component = {
        "manifest_name": "com.example.Recv",
        "component_type": "receiver",
        "intent_filters": [{"actions": list(actions), "categories": [], "data": []}],
    }
    return {
        "components": [dict(component) for _ in range(declarations)],
        "uses_permissions": list(uses_permissions),
    }


def _config(fine_sinks=(("java/lang/reflect/Method", "invoke"),)):
    units = [
        _unit(sink_class=api_class, sink_method=api_method)
        for api_class, api_method in fine_sinks
        for _ in range(features.FINE_SINK_MIN_COUNT)
    ]
    return features.build_config(units)


def test_config_is_built_from_the_training_pool_only():
    """詞彙表不得參考 Gold；門檻以下的 sink 不進詞彙表（spec §6）。"""
    units = [_unit() for _ in range(features.FINE_SINK_MIN_COUNT)]
    units += [_unit(sink_class="java/lang/Runtime", sink_method="exec")]

    config = features.build_config(units)

    assert config["fine_sinks"] == [["java/lang/reflect/Method", "invoke"]]
    assert config["provenance"]["gold_consulted"] is False
    assert config["provenance"]["training_units"] == features.FINE_SINK_MIN_COUNT + 1
    assert config["config_version"] == features.CONFIG_VERSION


def test_dimension_count_and_order_are_stable():
    """維度順序屬 configuration lock 的一部分，不得隨 dict 迭代順序改變。"""
    config = _config()

    names = features.feature_names(config)

    # 4 component_type + 9 sink_group + 1 fine sink + 1 OOV + 5 bucket + 2 + 2
    assert len(names) == 24
    assert len(set(names)) == len(names)
    assert features.feature_names(config) == names


def test_no_dimension_names_a_banned_field():
    """spec §8.3 的禁用欄位不得以任何形式出現在維度名稱中。"""
    config = _config()

    names = [name.lower() for name in features.feature_names(config)]

    for token in BANNED_TOKENS:
        offenders = [name for name in names if token in name]
        # sink_permission_* 是 unit 層級的 sink 對應 permission，不是 permission 清單。
        offenders = [name for name in offenders if not name.startswith("sink_permission_")]
        assert offenders == [], f"{token} 出現在維度名稱 {offenders}"


def test_platform_action_lands_in_its_semantic_bucket():
    config = _config()

    vector = features.encode(
        _unit(), _manifest(actions=["android.provider.Telephony.SMS_RECEIVED"]), config
    )

    assert vector["if_action_sms_telephony"] == 1
    assert vector["if_action_boot_power_net"] == 0
    assert vector["if_action_platform_oov"] == 0
    assert vector["has_custom_action"] == 0


def test_main_action_is_excluded_entirely():
    """MAIN 整個排除，不只排除 MAIN+LAUNCHER 組合（spec §3.1）；也不得落入 OOV。"""
    config = _config()

    vector = features.encode(_unit(), _manifest(actions=["android.intent.action.MAIN"]), config)

    assert vector["if_action_platform_oov"] == 0
    assert all(vector[f"if_action_{name}"] == 0 for name in features.ACTION_BUCKETS)


def test_custom_action_never_becomes_its_own_dimension():
    """自訂 action 內嵌 package，屬身分欄位，只能折成單一旗標（spec §6）。"""
    config = _config()

    vector = features.encode(
        _unit(), _manifest(actions=["dsrhki.yjgfqjejkjh.gbjutaxgpStart76"]), config
    )

    assert vector["has_custom_action"] == 1
    assert vector["if_action_platform_oov"] == 0


def test_unbucketed_platform_action_lands_in_platform_oov():
    config = _config()

    vector = features.encode(
        _unit(), _manifest(actions=["com.android.vending.INSTALL_REFERRER"]), config
    )

    assert vector["if_action_platform_oov"] == 1
    assert vector["has_custom_action"] == 0


def test_actions_from_duplicate_declarations_are_unioned():
    """同名 component 重複宣告時，任何一筆帶進來的 action 外部都送得到。"""
    config = _config()
    manifest = _manifest(actions=["android.intent.action.BOOT_COMPLETED"], declarations=2)
    manifest["components"][1]["intent_filters"] = [
        {"actions": ["android.intent.action.VIEW"], "categories": [], "data": []}
    ]

    vector = features.encode(_unit(), manifest, config)

    assert vector["if_action_boot_power_net"] == 1
    assert vector["if_action_implicit_content"] == 1


def test_sink_below_threshold_falls_into_oov_but_keeps_its_group():
    """粗粒度 group 是罕見 sink 的泛化依靠（spec §4.1 A）。"""
    config = _config()

    vector = features.encode(
        _unit(
            sink_class="android/hardware/Camera",
            sink_method="takePicture",
            sink_group_id="SENSITIVE_API_CAMERA",
        ),
        _manifest(),
        config,
    )

    assert vector["sink=__oov__"] == 1
    assert vector["sink_group=SENSITIVE_API_CAMERA"] == 1
    assert vector["sink=java/lang/reflect/Method.invoke"] == 0


def test_sink_permission_applicable_without_declaration():
    """applicable=1、declared=0 才能表達「呼叫了需要 permission 的 sink 但沒宣告」。"""
    config = _config()

    vector = features.encode(
        _unit(
            sink_class="android/telephony/SmsManager",
            sink_method="sendTextMessage",
            sink_group_id="SENSITIVE_API_SMS_PHONE",
        ),
        _manifest(uses_permissions=["android.permission.INTERNET"]),
        config,
    )

    assert vector["sink_permission_applicable"] == 1
    assert vector["sink_permission_declared"] == 0


def test_sink_permission_declared_when_any_alternative_is_present():
    """位置類 sink 由 FINE 或 COARSE 任一即可，對應表存的是集合。"""
    config = _config()

    vector = features.encode(
        _unit(
            sink_class="android/location/LocationManager",
            sink_method="getLastKnownLocation",
            sink_group_id="SENSITIVE_API_GPS",
        ),
        _manifest(uses_permissions=["android.permission.ACCESS_COARSE_LOCATION"]),
        config,
    )

    assert vector["sink_permission_applicable"] == 1
    assert vector["sink_permission_declared"] == 1


def test_sink_without_governing_permission_is_zero_on_both():
    """CODE_EXEC 沒有 permission 管轄，兩維都為 0；這是 applicable 維存在的理由。"""
    config = _config()

    vector = features.encode(_unit(), _manifest(), config)

    assert vector["sink_permission_applicable"] == 0
    assert vector["sink_permission_declared"] == 0


def test_unknown_component_type_raises_instead_of_zero_vector():
    config = _config()

    with pytest.raises(ValueError, match="component_type"):
        features.encode(_unit(component_type="activity-alias"), _manifest(), config)


def test_unknown_sink_group_raises_instead_of_zero_vector():
    config = _config()

    with pytest.raises(ValueError, match="sink_group_id"):
        features.encode(_unit(sink_group_id="SENSITIVE_API_MADE_UP"), _manifest(), config)


def test_audit_reports_distinct_feature_vectors():
    """相異 vector 數是有效容量的上限（spec §7.1）。"""
    config = _config()
    manifest = _manifest(actions=["android.provider.Telephony.SMS_RECEIVED"])
    rows = [
        {"review_unit_id": f"u{index}", "features": features.encode(_unit(), manifest, config)}
        for index in range(5)
    ]
    rows.append(
        {"review_unit_id": "u9", "features": features.encode(_unit(), _manifest(), config)}
    )

    report = features.audit(rows, config)

    assert report["units"] == 6
    assert report["distinct_feature_vectors"] == 2
    assert report["dimensions"] == len(features.feature_names(config))
