"""R（external reachability）確定性規則，以及對 Gold 的驗收。

流程依 R → I → S → A：本模組只判 R。判為 `refuted` 的 unit 在報告與整體評估中
early-stop（風險 0）；`confirmed` 與 `unknown` 都送往後續 I/S 模型——unknown
不得當成 negative（authz_label_spec §6.4）。

規則刻意比人工保守：只在 Manifest 語意確定時給 confirmed／refuted，其餘一律
unknown。判定依據對齊 `docs/authz_annotation_guide.md` Step 1。

本模組會讀 exported、permission、protection level 等欄位。它們依
authz_label_spec §8.3 不得進入模型 feature，但作為確定性規則判定 R 不受此限。
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from .golden_review_packets import extract_manifest_evidence, load_manifest_from_apk

RULE_VERSION = "r-gate-v1"
DEFAULT_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")

LOGGER = logging.getLogger(__name__)

# Android framework 定義、第三方 app 無法取得的 permission（signature 或
# signature|privileged）。來源：AOSP frameworks/base/core/res/AndroidManifest.xml。
# 只收錄已確認等級者；未列出的 framework permission 一律 unknown，不猜。
FRAMEWORK_BLOCKING_PERMISSIONS = frozenset(
    {
        "android.permission.BROADCAST_SMS",
        "android.permission.BROADCAST_WAP_PUSH",
        "android.permission.BIND_JOB_SERVICE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_INPUT_METHOD",
        "android.permission.BIND_WALLPAPER",
        "android.permission.BIND_VPN_SERVICE",
        "android.permission.BIND_REMOTEVIEWS",
        "android.permission.BIND_TEXT_SERVICE",
        "android.permission.BIND_DREAM_SERVICE",
        "android.permission.BIND_QUICK_SETTINGS_TILE",
        "android.permission.BIND_PRINT_SERVICE",
        "android.permission.BIND_NFC_SERVICE",
        "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
        "android.permission.BIND_AUTOFILL_SERVICE",
        "android.permission.BIND_INCALL_SERVICE",
        "android.permission.BIND_SCREENING_SERVICE",
        "android.permission.BIND_CHOOSER_TARGET_SERVICE",
    }
)

# <permission android:protectionLevel> 的 base type（低 4 bit）。
_BASE_NORMAL, _BASE_DANGEROUS, _BASE_SIGNATURE, _BASE_SIGNATURE_OR_SYSTEM = 0, 1, 2, 3
_BASE_INTERNAL = 4
_NAMED_LEVELS = {
    "normal": _BASE_NORMAL,
    "dangerous": _BASE_DANGEROUS,
    "signature": _BASE_SIGNATURE,
    "signatureorsystem": _BASE_SIGNATURE_OR_SYSTEM,
    "internal": _BASE_INTERNAL,
}


def _base_protection_level(raw: str | None) -> int | None:
    if raw is None:
        return None
    text = str(raw).strip()
    try:
        return int(text, 0) & 0xF
    except ValueError:
        head = text.split("|", 1)[0].strip().lower()
        return _NAMED_LEVELS.get(head)


def _verdict(result: str, reason: str, **basis: Any) -> dict[str, Any]:
    return {"rule_version": RULE_VERSION, "result": result, "reason_code": reason, "basis": basis}


def judge_reachability(
    manifest: Mapping[str, Any], component_name: str, component_type: str
) -> dict[str, Any]:
    """對單一 Manifest component 判定 R：confirmed／refuted／unknown。"""
    declarations = [
        component
        for component in manifest.get("components", [])
        if component.get("manifest_name") == component_name
        and component.get("component_type") == component_type
    ]
    if not declarations:
        return _verdict("unknown", "component_not_in_manifest")

    exported_values = {
        (component.get("static_exported_interpretation") or {}).get("value")
        for component in declarations
    }
    if len(declarations) > 1 and len(exported_values) > 1:
        # 同名重複宣告且 exported 互相衝突：安裝後以哪一筆為準無法由 packet 判定。
        return _verdict(
            "unknown",
            "duplicate_declaration_conflict",
            declaration_count=len(declarations),
        )

    component = declarations[0]
    exported = (component.get("static_exported_interpretation") or {}).get("value")
    exported_basis = (component.get("static_exported_interpretation") or {}).get("basis")
    if exported is None:
        return _verdict("unknown", "exported_semantics_unresolved", exported_basis=exported_basis)
    if exported is False:
        return _verdict("refuted", "not_exported", exported_basis=exported_basis)

    permission = component.get("permission")
    if not permission:
        return _verdict("confirmed", "exported_without_permission", exported_basis=exported_basis)

    if permission in FRAMEWORK_BLOCKING_PERMISSIONS:
        return _verdict("refuted", "framework_signature_permission", permission=permission)

    declared = {
        row.get("name"): row.get("protection_level")
        for row in manifest.get("declared_permissions", [])
    }
    if permission not in declared:
        return _verdict(
            "unknown",
            "permission_not_declared_in_apk",
            permission=permission,
        )

    level = _base_protection_level(declared[permission])
    if level is None:
        # android:protectionLevel 省略時預設 normal；只有真的無法解析才 unknown。
        if declared[permission] is None:
            level = _BASE_NORMAL
        else:
            return _verdict(
                "unknown",
                "protection_level_unparsed",
                permission=permission,
                protection_level=declared[permission],
            )
    if level in (_BASE_SIGNATURE, _BASE_SIGNATURE_OR_SYSTEM, _BASE_INTERNAL):
        return _verdict(
            "refuted",
            "declared_signature_permission",
            permission=permission,
            protection_level=declared[permission],
        )
    if level == _BASE_NORMAL:
        return _verdict(
            "confirmed",
            "declared_normal_permission",
            permission=permission,
            protection_level=declared[permission],
        )
    # dangerous：spec 未規定使用者授權是否屬本威脅模型 caller 可取得的能力。
    return _verdict(
        "unknown",
        "dangerous_permission_semantics_unresolved",
        permission=permission,
        protection_level=declared[permission],
    )


class ManifestCache:
    def __init__(self, samples_csv: Path) -> None:
        with samples_csv.open(encoding="utf-8-sig", newline="") as handle:
            self._paths = {row["sha256"]: row["source_path"] for row in csv.DictReader(handle)}
        self._cache: dict[str, dict[str, Any]] = {}

    def get(self, sha256: str) -> dict[str, Any]:
        if sha256 not in self._cache:
            source = self._paths.get(sha256)
            if not source:
                raise KeyError(f"selected_samples.csv 找不到 {sha256}")
            self._cache[sha256] = extract_manifest_evidence(load_manifest_from_apk(Path(source)))
        return self._cache[sha256]


def load_latest_gold(gold_log: Path) -> dict[str, dict[str, Any]]:
    """每個 review unit 取 append-only log 中最後一筆 event。"""
    latest: dict[str, dict[str, Any]] = {}
    with gold_log.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                event = json.loads(line)
                latest[str(event["review_unit_id"])] = event
    return latest


def verify_against_gold(
    units: Sequence[Mapping[str, Any]],
    gold: Mapping[str, Mapping[str, Any]],
    manifests: ManifestCache,
) -> dict[str, Any]:
    confusion: Counter[tuple[str, str]] = Counter()
    reasons: dict[str, Counter[str]] = defaultdict(Counter)
    mismatches: list[dict[str, Any]] = []
    for unit in units:
        event = gold.get(str(unit["review_unit_id"]))
        if event is None:
            continue
        verdict = judge_reachability(
            manifests.get(str(unit["sha256"])),
            str(unit["component_name"]),
            str(unit["component_type"]),
        )
        gold_r = str(event.get("R_predicate_result"))
        rule_r = verdict["result"]
        confusion[(gold_r, rule_r)] += 1
        reasons[rule_r][verdict["reason_code"]] += 1
        if gold_r != rule_r:
            mismatches.append(
                {
                    "review_unit_id": unit["review_unit_id"],
                    "sha256": unit["sha256"],
                    "component": unit["component_name"],
                    "component_type": unit["component_type"],
                    "gold_R": gold_r,
                    "rule_R": rule_r,
                    "reason_code": verdict["reason_code"],
                    "basis": verdict["basis"],
                    "gold_label": event.get("gold_authz_label"),
                    "reviewed_at": event.get("reviewed_at"),
                }
            )
    return {"confusion": confusion, "reasons": reasons, "mismatches": mismatches}


def _print_report(report: Mapping[str, Any]) -> None:
    labels = ("confirmed", "refuted", "unknown")
    confusion = report["confusion"]
    print("\nGold R（列）× 規則 R（欄）")
    print(f"{'':>12}" + "".join(f"{label:>12}" for label in labels))
    for gold_r in labels:
        print(f"{gold_r:>12}" + "".join(f"{confusion[(gold_r, rule_r)]:>12}" for rule_r in labels))
    total = sum(confusion.values())
    agree = sum(confusion[(label, label)] for label in labels)
    print(f"\n一致 {agree} / {total}")
    unsafe = confusion[("confirmed", "refuted")] + confusion[("unknown", "refuted")]
    print(f"危險錯誤（Gold 非 refuted 卻被規則判 refuted，會被錯誤 early-stop）：{unsafe}")
    print("\n規則判定原因：")
    for rule_r in labels:
        for reason, count in report["reasons"][rule_r].most_common():
            print(f"  {rule_r:>10}  {reason:<45} {count}")
    if report["mismatches"]:
        print("\n不一致明細：")
        for row in report["mismatches"]:
            print(
                f"  {row['sha256'][:8]} {row['component_type']:<8} {row['component']}\n"
                f"    Gold={row['gold_R']} 規則={row['rule_R']} ({row['reason_code']}) "
                f"basis={row['basis']} label={row['gold_label']} at={row['reviewed_at']}"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    gold = load_latest_gold(args.gold_log)
    with args.units.open(encoding="utf-8") as handle:
        units = [json.loads(line) for line in handle if line.strip()]
    units = [unit for unit in units if str(unit["review_unit_id"]) in gold]
    LOGGER.info("Gold unit %d 筆，其中可由 candidate unit 對應 %d 筆。", len(gold), len(units))
    report = verify_against_gold(units, gold, ManifestCache(args.samples))
    _print_report(report)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
