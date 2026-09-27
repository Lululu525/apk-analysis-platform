"""依 `docs/authz_feature_spec_v1.md` 產生 I/S 模型的 31 維 feature。

執行順序第 5 項的第一步（ADR-0002）。本模組是 **configuration lock 的產生者**：
詞彙表一旦寫出並 commit，feature 清單即不得再更動。

與 M1 的區隔：`app/ml/encoder.py` 與 `app/ml/feature_schema.json` 是 M1 的
leakage-diagnostic 管線，刻意包含 `exported`、`protected`、`permission`，
不得修改也不得與本模組混用。本模組的檔名、schema 版本字串與欄位前綴都刻意錯開。

三條不變量：

1. **詞彙表只由訓練池統計，絕不參考 Gold**（spec §10）。Gold 出現的新名稱落入 OOV
   維度；`component_type` 與 `sink_group_id` 屬封閉詞彙，出現未知值時直接報錯而非
   靜默產生全零向量。
2. **禁用欄位不進 feature**：`exported`、`protected`、component 的 `permission`、
   `has_intent_filter`、`linkage_status`、身分欄位等，依 `authz_label_spec.md` §8.3。
   `uses_permissions` 只用來判斷「本 unit 的 sink 所需的那一個 permission 有沒有被宣告」，
   整張清單不進 feature（理由見 spec §3.2：清單本身是 APK 指紋）。
3. **輸出不覆寫 `training_units.jsonl`。** 該檔由 `build_training_pool.py` 產生，
   若把 feature 填回原檔，重跑上游會靜默抹掉 feature。改為輸出獨立的 feature 檔，
   以 `review_unit_id` 與上游 join。
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..extractors.sensitive_api_callers import SENSITIVE_API_SPECS
from .gold_consistency import load_identities, load_latest_events
from .r_gate import ManifestCache

CONFIG_VERSION = "authz-feature-v1"

DEFAULT_TRAINING_UNITS = Path("dataset/authz_v2/training_units.jsonl")
DEFAULT_CANDIDATE_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_CONFIG = Path("dataset/authz_v2/authz_feature_config_v1.json")
DEFAULT_TRAINING_FEATURES = Path("dataset/authz_v2/features_training.jsonl")
DEFAULT_GOLD_FEATURES = Path("dataset/authz_v2/features_gold_eval.jsonl")

# --- 封閉詞彙（平台定義或本專題的 sink spec 定義，不由資料估計） ------------------

COMPONENT_TYPES: tuple[str, ...] = ("activity", "provider", "receiver", "service")

SINK_GROUPS: tuple[str, ...] = tuple(
    sorted({spec.group_id for spec in SENSITIVE_API_SPECS})
)

# --- 由訓練池統計的門檻 -------------------------------------------------------

FINE_SINK_MIN_COUNT = 50

# --- intent filter action：5 個語意桶（spec §4） ------------------------------
# 分桶依據是 Android 對各 action 的投遞語意（外部送進來的是什麼），屬先驗知識。
# `android.intent.action.MAIN` 與 `android.intent.category.LAUNCHER` 依 spec §3.1
# 整個排除，不只排除兩者的組合。

EXCLUDED_ACTIONS = frozenset({"android.intent.action.MAIN"})

ACTION_BUCKETS: Mapping[str, frozenset[str]] = {
    "sms_telephony": frozenset(
        {
            "android.provider.Telephony.SMS_RECEIVED",
            "android.intent.action.PHONE_STATE",
            "android.intent.action.NEW_OUTGOING_CALL",
            "android.intent.action.START_SMS_SERVICE",
        }
    ),
    "boot_power_net": frozenset(
        {
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.ACTION_POWER_CONNECTED",
            "android.net.conn.CONNECTIVITY_CHANGE",
        }
    ),
    "camera_media": frozenset(
        {
            "android.media.action.IMAGE_CAPTURE",
            "android.media.action.STILL_IMAGE_CAMERA",
            "android.media.action.VIDEO_CAPTURE",
            "android.media.action.VIDEO_CAMERA",
        }
    ),
    "widget_wallpaper": frozenset(
        {
            "android.appwidget.action.APPWIDGET_UPDATE",
            "android.service.wallpaper.WallpaperService",
        }
    ),
    "implicit_content": frozenset(
        {
            "android.intent.action.VIEW",
            "android.intent.action.SEND",
        }
    ),
}

PLATFORM_PREFIXES = ("android.", "com.android.")

# --- sink → permission（spec §5） --------------------------------------------
# 來源為 AOSP 對各 API 的 permission 要求，屬先驗知識，不由 Gold 或訓練池分布估計。
# 對應建在 API 層級而非 sink group 層級，因為多個 group 內部混用不同 permission
# （例如 SMS_PHONE 同時含 sendTextMessage → SEND_SMS 與 getDeviceId → READ_PHONE_STATE）。
# 未列出者視為「無 permission 管轄」，`sink_permission_applicable` 為 0。

_P = "android.permission."

SINK_PERMISSIONS: Mapping[tuple[str, str], frozenset[str]] = {
    ("android/telephony/SmsManager", "sendTextMessage"): frozenset({_P + "SEND_SMS"}),
    ("android/telephony/SmsManager", "sendMultipartTextMessage"): frozenset({_P + "SEND_SMS"}),
    ("android/telephony/SmsManager", "sendDataMessage"): frozenset({_P + "SEND_SMS"}),
    ("android/telephony/TelephonyManager", "getDeviceId"): frozenset({_P + "READ_PHONE_STATE"}),
    ("android/telephony/TelephonyManager", "getImei"): frozenset({_P + "READ_PHONE_STATE"}),
    ("android/telephony/TelephonyManager", "getSubscriberId"): frozenset({_P + "READ_PHONE_STATE"}),
    ("android/telephony/TelephonyManager", "getLine1Number"): frozenset({_P + "READ_PHONE_STATE"}),
    ("android/telephony/TelephonyManager", "getSimSerialNumber"): frozenset(
        {_P + "READ_PHONE_STATE"}
    ),
    ("android/location/LocationManager", "requestLocationUpdates"): frozenset(
        {_P + "ACCESS_FINE_LOCATION", _P + "ACCESS_COARSE_LOCATION"}
    ),
    ("android/location/LocationManager", "requestSingleUpdate"): frozenset(
        {_P + "ACCESS_FINE_LOCATION", _P + "ACCESS_COARSE_LOCATION"}
    ),
    ("android/location/LocationManager", "getLastKnownLocation"): frozenset(
        {_P + "ACCESS_FINE_LOCATION", _P + "ACCESS_COARSE_LOCATION"}
    ),
    ("android/media/MediaRecorder", "start"): frozenset({_P + "RECORD_AUDIO"}),
    ("android/media/MediaRecorder", "setAudioSource"): frozenset({_P + "RECORD_AUDIO"}),
    ("android/media/AudioRecord", "<init>"): frozenset({_P + "RECORD_AUDIO"}),
    ("android/media/AudioRecord", "startRecording"): frozenset({_P + "RECORD_AUDIO"}),
    ("android/hardware/Camera", "open"): frozenset({_P + "CAMERA"}),
    ("android/hardware/Camera", "startPreview"): frozenset({_P + "CAMERA"}),
    ("android/hardware/Camera", "takePicture"): frozenset({_P + "CAMERA"}),
    ("java/net/URL", "openConnection"): frozenset({_P + "INTERNET"}),
    ("okhttp3/OkHttpClient", "newCall"): frozenset({_P + "INTERNET"}),
    ("android/os/Environment", "getExternalStorageDirectory"): frozenset(
        {_P + "WRITE_EXTERNAL_STORAGE", _P + "READ_EXTERNAL_STORAGE"}
    ),
    ("android/os/Environment", "getExternalStoragePublicDirectory"): frozenset(
        {_P + "WRITE_EXTERNAL_STORAGE", _P + "READ_EXTERNAL_STORAGE"}
    ),
    ("java/io/FileOutputStream", "<init>"): frozenset({_P + "WRITE_EXTERNAL_STORAGE"}),
    ("java/io/FileInputStream", "<init>"): frozenset({_P + "READ_EXTERNAL_STORAGE"}),
    ("android/content/ContentResolver", "query"): frozenset({_P + "READ_CONTACTS"}),
    ("android/net/wifi/WifiInfo", "getMacAddress"): frozenset({_P + "ACCESS_WIFI_STATE"}),
    ("android/bluetooth/BluetoothAdapter", "getAddress"): frozenset({_P + "BLUETOOTH"}),
}

LOGGER = logging.getLogger(__name__)


# --- 讀取 ---------------------------------------------------------------------


def read_units(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            for field in ("review_unit_id", "sha256", "component_name", "component_type"):
                if not row.get(field):
                    raise ValueError(f"{path} line {line_number} 缺少 {field}。")
            rows.append(row)
    return rows


def component_actions(
    manifest: Mapping[str, Any], component_name: str, component_type: str
) -> set[str]:
    """該 component 所有 intent filter 宣告的 action 聯集。

    同名 component 可能被重複宣告（見 r_gate 的 duplicate_declaration_conflict），
    此處取聯集：任何一筆宣告帶進來的 action 都是外部可以送達的。
    """
    actions: set[str] = set()
    for component in manifest.get("components", []):
        if (
            component.get("manifest_name") != component_name
            or component.get("component_type") != component_type
        ):
            continue
        for intent_filter in component.get("intent_filters", []):
            actions.update(intent_filter.get("actions", []))
    return actions - EXCLUDED_ACTIONS


def _is_platform(action: str) -> bool:
    return action.startswith(PLATFORM_PREFIXES)


# --- 詞彙表 -------------------------------------------------------------------


def build_config(training_units: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """只由訓練池統計詞彙表。此函式不得接收 Gold 的任何資料。"""
    counts = collections.Counter(
        (str(unit["sink_class"]), str(unit["sink_method"])) for unit in training_units
    )
    fine_sinks = sorted(key for key, count in counts.items() if count >= FINE_SINK_MIN_COUNT)
    covered = sum(counts[key] for key in fine_sinks)
    return {
        "config_version": CONFIG_VERSION,
        "fine_sink_min_count": FINE_SINK_MIN_COUNT,
        "fine_sinks": [list(key) for key in fine_sinks],
        "component_types": list(COMPONENT_TYPES),
        "sink_groups": list(SINK_GROUPS),
        "action_buckets": {name: sorted(members) for name, members in ACTION_BUCKETS.items()},
        "excluded_actions": sorted(EXCLUDED_ACTIONS),
        "platform_prefixes": list(PLATFORM_PREFIXES),
        "sink_permissions": {
            f"{api_class}.{api_method}": sorted(permissions)
            for (api_class, api_method), permissions in sorted(SINK_PERMISSIONS.items())
        },
        "provenance": {
            "vocabulary_source": str(DEFAULT_TRAINING_UNITS),
            "training_units": len(training_units),
            "fine_sink_coverage": covered,
            "gold_consulted": False,
        },
    }


def feature_names(config: Mapping[str, Any]) -> list[str]:
    """31 個維度的固定順序。順序屬 configuration lock 的一部分。"""
    names = [f"component_type={value}" for value in config["component_types"]]
    names += [f"sink_group={value}" for value in config["sink_groups"]]
    names += [f"sink={api_class}.{api_method}" for api_class, api_method in config["fine_sinks"]]
    names.append("sink=__oov__")
    names += [f"if_action_{name}" for name in sorted(config["action_buckets"])]
    names += ["if_action_platform_oov", "has_custom_action"]
    names += ["sink_permission_applicable", "sink_permission_declared"]
    return names


# --- 編碼 ---------------------------------------------------------------------


def encode(
    unit: Mapping[str, Any], manifest: Mapping[str, Any], config: Mapping[str, Any]
) -> dict[str, int]:
    fine_sinks = {tuple(key) for key in config["fine_sinks"]}
    buckets = {name: frozenset(members) for name, members in config["action_buckets"].items()}

    component_type = str(unit["component_type"])
    if component_type not in config["component_types"]:
        # 封閉詞彙：靜默產生全零向量會讓下游以為這是一筆「什麼都不是」的 component。
        raise ValueError(
            f"未知的 component_type {component_type!r}；"
            f"封閉詞彙為 {config['component_types']}，請先確認 spec 是否需要更新。"
        )
    sink_group = str(unit["sink_group_id"])
    if sink_group not in config["sink_groups"]:
        raise ValueError(
            f"未知的 sink_group_id {sink_group!r}；"
            f"封閉詞彙來自 SENSITIVE_API_SPECS，請先確認 sink spec 是否需要更新。"
        )

    sink_key = (str(unit["sink_class"]), str(unit["sink_method"]))
    actions = component_actions(manifest, str(unit["component_name"]), component_type)
    bucketed = {action for members in buckets.values() for action in members}
    required = SINK_PERMISSIONS.get(sink_key)
    declared = set(manifest.get("uses_permissions", []))

    vector = {name: 0 for name in feature_names(config)}
    vector[f"component_type={component_type}"] = 1
    vector[f"sink_group={sink_group}"] = 1
    if sink_key in fine_sinks:
        vector[f"sink={sink_key[0]}.{sink_key[1]}"] = 1
    else:
        vector["sink=__oov__"] = 1
    for name, members in buckets.items():
        vector[f"if_action_{name}"] = 1 if actions & members else 0
    vector["if_action_platform_oov"] = int(
        any(_is_platform(action) and action not in bucketed for action in actions)
    )
    vector["has_custom_action"] = int(any(not _is_platform(action) for action in actions))
    vector["sink_permission_applicable"] = int(bool(required))
    vector["sink_permission_declared"] = int(bool(required) and bool(required & declared))
    return vector


def encode_all(
    units: Sequence[Mapping[str, Any]], manifests: ManifestCache, config: Mapping[str, Any]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for unit in units:
        manifest = manifests.get(str(unit["sha256"]))
        if not manifest:
            raise ValueError(f"讀不到 {unit['sha256']} 的 manifest，無法產生 feature。")
        rows.append(
            {
                "review_unit_id": unit["review_unit_id"],
                "config_version": CONFIG_VERSION,
                "features": encode(unit, manifest, config),
            }
        )
    return rows


# --- Gold 評估集 ---------------------------------------------------------------


def load_gold_units(
    gold_log: Path, candidate_units: Path
) -> list[dict[str, Any]]:
    """Gold 的 unit identity。只讀 identity，不讀任何 label。"""
    events = load_latest_events(gold_log)
    identities = load_identities(candidate_units, set(events))
    return [
        {"review_unit_id": unit_id, **identity}
        for unit_id, identity in sorted(identities.items())
    ]


# --- 稽核 ---------------------------------------------------------------------


def audit(rows: Sequence[Mapping[str, Any]], config: Mapping[str, Any]) -> dict[str, Any]:
    """回報每個維度的 1 的筆數與相異 feature vector 數。

    相異 vector 數是有效容量的上限（spec §7.1）：模型對同一個 vector 必然輸出同一個
    機率，因此無法區分落在同一格內的樣本。
    """
    names = feature_names(config)
    positives = {name: sum(row["features"][name] for row in rows) for name in names}
    cells = collections.Counter(
        tuple(row["features"][name] for name in names) for row in rows
    )
    return {
        "units": len(rows),
        "dimensions": len(names),
        "distinct_feature_vectors": len(cells),
        "all_zero_dimensions": sorted(name for name, count in positives.items() if count == 0),
        "positives_per_dimension": positives,
    }


def _print_report(name: str, report: Mapping[str, Any]) -> None:
    print(
        f"\n{name}：{report['units']} 筆、{report['dimensions']} 維、"
        f"相異 feature vector {report['distinct_feature_vectors']} 個"
    )
    if report["all_zero_dimensions"]:
        print(f"  全零維度（{len(report['all_zero_dimensions'])} 個）："
              f"{', '.join(report['all_zero_dimensions'])}")
    for dimension, count in report["positives_per_dimension"].items():
        print(f"    {dimension:<56} {count:>5}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-units", type=Path, default=DEFAULT_TRAINING_UNITS)
    parser.add_argument("--candidate-units", type=Path, default=DEFAULT_CANDIDATE_UNITS)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--training-features", type=Path, default=DEFAULT_TRAINING_FEATURES)
    parser.add_argument("--gold-features", type=Path, default=DEFAULT_GOLD_FEATURES)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)

    training_units = read_units(args.training_units)
    config = build_config(training_units)
    manifests = ManifestCache(args.samples)

    training_rows = encode_all(training_units, manifests, config)
    gold_units = load_gold_units(args.gold_log, args.candidate_units)
    gold_rows = encode_all(gold_units, manifests, config)

    training_report = audit(training_rows, config)
    gold_report = audit(gold_rows, config)
    print(
        f"\n詞彙表只由訓練池統計（{len(training_units)} 筆）；"
        f"細粒度 sink 門檻 ≥{FINE_SINK_MIN_COUNT} 次，選入 {len(config['fine_sinks'])} 種，"
        f"涵蓋 {config['provenance']['fine_sink_coverage']} 筆。"
    )
    _print_report("訓練池", training_report)
    _print_report("Gold 評估集", gold_report)

    if args.dry_run:
        return 0
    args.config.parent.mkdir(parents=True, exist_ok=True)
    args.config.write_text(
        json.dumps(
            {**config, "audit": {"training": training_report, "gold_eval": gold_report}},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_jsonl(args.training_features, training_rows)
    _write_jsonl(args.gold_features, gold_rows)
    LOGGER.info("已寫出 %s、%s、%s。", args.config, args.training_features, args.gold_features)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
