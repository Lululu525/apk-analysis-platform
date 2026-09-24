"""規則基準線在 Gold 上的評估：規則能走多遠，剩下多少空間留給模型。

比較三個不需要訓練的方法（ADR-0002 執行順序第 3 項）：

- `R0`：舊規則 `exported && !protected`，也是既有洩漏基線的 label 公式。
- `r_gate`：可達性規則（`app/tools/r_gate.py`）。refuted 0、unknown 0.5、confirmed 1。
- `r_gate+sink`：同上再乘以 sink 類別的敏感度權重。

**sink 權重是先驗值，於 2026-09-25 在計算任何 Gold 數字之前凍結**，依據是
Android 對該類能力的風險定位（是否直接產生費用、是否為 dangerous 等級個資或
感測器），不是 Gold 的 label 分布。spec §10 與時程表禁止以 Golden label 選
feature、threshold 或超參數，這裡同樣適用。

本模組唯讀 Gold，不修改任何 label。
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .gold_consistency import load_identities, load_latest_events
from .r_gate import ManifestCache, judge_reachability

BASELINE_VERSION = "rule-baselines-v1"
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_OUTPUT = Path("dataset/authz_v2/experiments/rule_baselines.json")

# 先驗敏感度權重（2026-09-25 凍結，未參考 Gold 分布）。
# 1.0 直接產生費用；0.9/0.8 dangerous 等級個資；0.7 dangerous 等級感測器；
# 0.5 資料外送管道；0.4 檔案讀寫；0.2 反射／動態載入本身不一定構成敏感效果。
SINK_PRIOR_WEIGHTS: Mapping[str, float] = {
    "SENSITIVE_API_SMS_PHONE": 1.0,
    "SENSITIVE_API_DEVICE_ID": 0.9,
    "SENSITIVE_API_CONTACTS": 0.8,
    "SENSITIVE_API_GPS": 0.7,
    "SENSITIVE_API_MICROPHONE": 0.7,
    "SENSITIVE_API_CAMERA": 0.7,
    "SENSITIVE_API_NETWORK_CLIPBOARD": 0.5,
    "SENSITIVE_API_STORAGE": 0.4,
    "SENSITIVE_API_CODE_EXEC": 0.2,
}
UNKNOWN_SINK_WEIGHT = 0.3
# `r_gate+sink` 要填混淆矩陣需要一條線：取先驗的高敏感層，而不是挑讓數字好看的閾值。
HIGH_SENSITIVITY_THRESHOLD = 0.7
REACHABILITY_SCORE = {"confirmed": 1.0, "unknown": 0.5, "refuted": 0.0}

LOGGER = logging.getLogger(__name__)


def _r0_score(manifest: Mapping[str, Any], component_name: str, component_type: str) -> float:
    """`exported && !protected`：不處理重複宣告，取第一筆，與舊 pipeline 一致。"""
    for component in manifest.get("components", []):
        if (
            component.get("manifest_name") == component_name
            and component.get("component_type") == component_type
        ):
            exported = (component.get("static_exported_interpretation") or {}).get("value")
            return 1.0 if exported is True and not component.get("permission") else 0.0
    return 0.0


def score_units(
    units: Sequence[Mapping[str, Any]], manifests: ManifestCache
) -> list[dict[str, Any]]:
    scored: list[dict[str, Any]] = []
    for unit in units:
        manifest = manifests.get(str(unit["sha256"]))
        component_name = str(unit["component_name"])
        component_type = str(unit["component_type"])
        reachability = judge_reachability(manifest, component_name, component_type)["result"]
        gate = REACHABILITY_SCORE[reachability]
        weight = SINK_PRIOR_WEIGHTS.get(str(unit.get("sink_group_id")), UNKNOWN_SINK_WEIGHT)
        scored.append(
            {
                "review_unit_id": str(unit["review_unit_id"]),
                "sha256": str(unit["sha256"]),
                "label": unit["label"],
                "sink_group_id": unit.get("sink_group_id"),
                "reachability": reachability,
                "scores": {
                    "R0": _r0_score(manifest, component_name, component_type),
                    "r_gate": gate,
                    "r_gate+sink": gate * weight,
                },
                "predictions": {
                    "R0": _r0_score(manifest, component_name, component_type) > 0,
                    "r_gate": reachability != "refuted",
                    "r_gate+sink": reachability != "refuted"
                    and weight >= HIGH_SENSITIVITY_THRESHOLD,
                },
            }
        )
    return scored


def _classification(rows: Sequence[Mapping[str, Any]], method: str) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for row in rows:
        predicted = bool(row["predictions"][method])
        actual = row["label"] == "positive"
        if predicted and actual:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1

    def f1(precision: float, recall: float) -> float:
        return 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    negative_precision = tn / (tn + fn) if tn + fn else 0.0
    negative_recall = tn / (tn + fp) if tn + fp else 0.0
    specificity = negative_recall
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1(precision, recall),
        "macro_f1": (f1(precision, recall) + f1(negative_precision, negative_recall)) / 2,
        "balanced_accuracy": (recall + specificity) / 2,
    }


def _ranked(rows: Sequence[Mapping[str, Any]], method: str) -> list[Mapping[str, Any]]:
    # 分數大量並列，固定以 review_unit_id 作次要鍵，讓結果可重現。
    return sorted(rows, key=lambda row: (-row["scores"][method], row["review_unit_id"]))


def _ranking(rows: Sequence[Mapping[str, Any]], method: str, ks: Sequence[int]) -> dict[str, Any]:
    ranked = _ranked(rows, method)
    positives = sum(1 for row in rows if row["label"] == "positive")
    precision_at_k = {}
    for k in ks:
        top = ranked[:k]
        precision_at_k[f"P@{k}"] = (
            sum(1 for row in top if row["label"] == "positive") / len(top) if top else 0.0
        )
    needed = int(positives * 0.8 + 0.999) if positives else 0
    found = 0
    units_to_80 = None
    for index, row in enumerate(ranked, 1):
        if row["label"] == "positive":
            found += 1
            if found >= needed:
                units_to_80 = index
                break
    per_apk: list[float] = []
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["sha256"]].append(row)
    for apk_rows in grouped.values():
        if not any(row["label"] == "positive" for row in apk_rows):
            continue  # 沒有 positive 的 APK 不納入平均，否則只是稀釋成 0
        top = _ranked(apk_rows, method)[:3]
        per_apk.append(sum(1 for row in top if row["label"] == "positive") / len(top))
    return {
        **precision_at_k,
        "units_to_80pct_recall": units_to_80,
        "total_units": len(rows),
        "positives": positives,
        "per_apk_mean_P@3": sum(per_apk) / len(per_apk) if per_apk else 0.0,
        "per_apk_counted": len(per_apk),
        "distinct_scores": len({row["scores"][method] for row in rows}),
    }


def evaluate(rows: Sequence[Mapping[str, Any]], ks: Sequence[int] = (10, 50)) -> dict[str, Any]:
    methods = ("R0", "r_gate", "r_gate+sink")
    return {
        "baseline_version": BASELINE_VERSION,
        "sink_prior_weights": dict(SINK_PRIOR_WEIGHTS),
        "unknown_sink_weight": UNKNOWN_SINK_WEIGHT,
        "high_sensitivity_threshold": HIGH_SENSITIVITY_THRESHOLD,
        "evaluated_units": len(rows),
        "positives": sum(1 for row in rows if row["label"] == "positive"),
        "negatives": sum(1 for row in rows if row["label"] == "negative"),
        "methods": {
            method: {
                "classification": _classification(rows, method),
                "ranking": _ranking(rows, method, ks),
            }
            for method in methods
        },
    }


def _print_report(report: Mapping[str, Any]) -> None:
    print(
        f"\nGold 二分類 {report['evaluated_units']} 筆"
        f"（positive {report['positives']}、negative {report['negatives']}）\n"
    )
    header = f"{'方法':<14}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'P':>8}{'R':>8}{'F1':>8}{'MacroF1':>9}{'BalAcc':>8}"
    print(header)
    print("-" * len(header))
    for method, payload in report["methods"].items():
        c = payload["classification"]
        print(
            f"{method:<14}{c['tp']:>5}{c['fp']:>5}{c['fn']:>5}{c['tn']:>5}"
            f"{c['precision']:>8.3f}{c['recall']:>8.3f}{c['f1']:>8.3f}"
            f"{c['macro_f1']:>9.3f}{c['balanced_accuracy']:>8.3f}"
        )
    header2 = f"\n{'方法':<14}{'P@10':>8}{'P@50':>8}{'看到80%':>9}{'每APK P@3':>11}{'相異分數':>9}"
    print(header2)
    print("-" * (len(header2) - 1))
    for method, payload in report["methods"].items():
        r = payload["ranking"]
        print(
            f"{method:<14}{r['P@10']:>8.3f}{r['P@50']:>8.3f}"
            f"{str(r['units_to_80pct_recall']):>9}{r['per_apk_mean_P@3']:>11.3f}"
            f"{r['distinct_scores']:>9}"
        )
    print("\n「看到80%」= 依分數排序後，要看到第幾筆才能找到 80% 的 positive。")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true", help="只輸出報表，不寫 JSON。")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    events = load_latest_events(args.gold_log)
    identities = load_identities(args.units, set(events))
    units = [
        {**identities[unit_id], "label": events[unit_id]["gold_authz_label"]}
        for unit_id in events
        if unit_id in identities
        and events[unit_id]["gold_authz_label"] in ("positive", "negative")
    ]
    LOGGER.info(
        "Gold %d 筆，其中可對應 identity 且為二分類 %d 筆。", len(events), len(units)
    )
    rows = score_units(units, ManifestCache(args.samples))
    report = evaluate(rows)
    _print_report(report)
    if not args.dry_run:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        LOGGER.info("已寫出 %s。", args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
