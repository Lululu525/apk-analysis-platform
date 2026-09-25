"""量化程式碼層級的瓶頸：外部可達的候選裡，現有自動化特徵能分出多少？

ADR-0002 執行順序第 4 項。可達性規則把 Manifest 層級的 negative 判掉之後，
剩下的 negative 全部由 I 或 S 否定（兩者合併計算，不比較個別次數，理由見 ADR）。
本模組回答：這些 negative 靠現有特徵分得出來嗎？

三個角度，都只讀 Gold，不做任何 feature 或 threshold 的選擇：

1. **組成**：剩餘 negative 由哪個 predicate 否定、集中在哪些 APK。
2. **作弊上限**：直接用 Gold 的答案，對每個特徵組合取多數決。這是任何只用這些
   特徵的分類器在本資料上的上限，不是可達成的成績。格子數會一併輸出，格子接近
   樣本數時等同死記。
3. **跨 APK 交叉驗證**：leave-one-APK-out，同樣的多數決但只用其他 APK 的答案。
   這才是「換一個沒看過的 APK 還有沒有用」的估計。

注意本模組使用 Gold label 進行診斷與報告，不得用其結果挑選正式模型的 feature、
threshold 或超參數（spec §10）。
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .gold_consistency import load_identities, load_latest_events
from .r_gate import ManifestCache, judge_reachability

ANALYSIS_VERSION = "bottleneck-analysis-v1"
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_OUTPUT = Path("dataset/authz_v2/experiments/bottleneck_analysis.json")

FEATURE_SETS: Mapping[str, Callable[[Mapping[str, Any]], Any]] = {
    "sink": lambda unit: unit["sink_group_id"],
    "component_type": lambda unit: unit["component_type"],
    "sink+component": lambda unit: (unit["sink_group_id"], unit["component_type"]),
    "sink+component+method": lambda unit: (
        unit["sink_group_id"],
        unit["component_type"],
        unit["sink_class"],
        unit["sink_method"],
    ),
}

LOGGER = logging.getLogger(__name__)


def load_reachable_binary(
    gold_log: Path, units_path: Path, samples: Path
) -> list[dict[str, Any]]:
    events = load_latest_events(gold_log)
    identities = load_identities(units_path, set(events))
    manifests = ManifestCache(samples)
    rows: list[dict[str, Any]] = []
    for unit_id, event in events.items():
        identity = identities.get(unit_id)
        if identity is None or event["gold_authz_label"] not in ("positive", "negative"):
            continue
        reachability = judge_reachability(
            manifests.get(str(identity["sha256"])),
            str(identity["component_name"]),
            str(identity["component_type"]),
        )["result"]
        if reachability == "refuted":
            continue
        rows.append(
            {
                **identity,
                "positive": event["gold_authz_label"] == "positive",
                "refuted_predicates": [
                    name for name in "RISA" if event[f"{name}_predicate_result"] == "refuted"
                ],
            }
        )
    return rows


def _metrics(pairs: Sequence[tuple[bool, bool]]) -> dict[str, Any]:
    tp = sum(1 for pred, truth in pairs if pred and truth)
    fp = sum(1 for pred, truth in pairs if pred and not truth)
    fn = sum(1 for pred, truth in pairs if not pred and truth)
    tn = sum(1 for pred, truth in pairs if not pred and not truth)

    def f1(precision: float, recall: float) -> float:
        return 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    negative_precision = tn / (tn + fn) if tn + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "macro_f1": (f1(precision, recall) + f1(negative_precision, specificity)) / 2,
        "balanced_accuracy": (recall + specificity) / 2,
    }


def _majority(labels: Sequence[bool]) -> bool:
    return sum(labels) * 2 >= len(labels)


def oracle_ceiling(rows: Sequence[Mapping[str, Any]], key: Callable) -> dict[str, Any]:
    cells: dict[Any, list[bool]] = collections.defaultdict(list)
    for row in rows:
        cells[key(row)].append(row["positive"])
    pairs = [(_majority(cells[key(row)]), row["positive"]) for row in rows]
    return {**_metrics(pairs), "cells": len(cells)}


def leave_one_apk_out(rows: Sequence[Mapping[str, Any]], key: Callable) -> dict[str, Any]:
    pairs: list[tuple[bool, bool]] = []
    for held_out in sorted({row["sha256"] for row in rows}):
        train = [row for row in rows if row["sha256"] != held_out]
        cells: dict[Any, list[bool]] = collections.defaultdict(list)
        for row in train:
            cells[key(row)].append(row["positive"])
        prior = _majority([row["positive"] for row in train])
        for row in rows:
            if row["sha256"] != held_out:
                continue
            cell = cells.get(key(row))
            pairs.append((_majority(cell) if cell else prior, row["positive"]))
    return _metrics(pairs)


def analyse(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    negatives = [row for row in rows if not row["positive"]]
    by_apk = collections.Counter(row["sha256"][:8] for row in negatives)
    baseline = _metrics([(True, row["positive"]) for row in rows])
    return {
        "analysis_version": ANALYSIS_VERSION,
        "reachable_units": len(rows),
        "positives": len(rows) - len(negatives),
        "negatives": len(negatives),
        "apks": len({row["sha256"] for row in rows}),
        "negatives_refuted_by": {
            "+".join(predicates) or "none": count
            for predicates, count in collections.Counter(
                tuple(row["refuted_predicates"]) for row in negatives
            ).items()
        },
        "negatives_per_apk": dict(by_apk.most_common()),
        "apks_holding_half_the_negatives": _concentration(by_apk, len(negatives)),
        "predict_all_positive": baseline,
        "oracle_ceiling": {
            name: oracle_ceiling(rows, key) for name, key in FEATURE_SETS.items()
        },
        "leave_one_apk_out": {
            name: leave_one_apk_out(rows, key) for name, key in FEATURE_SETS.items()
        },
    }


def _concentration(by_apk: collections.Counter, total: int) -> int:
    """要幾個 APK 才涵蓋一半的 negative；數字小代表訊號是 APK 特有的。"""
    running = 0
    for index, (_, count) in enumerate(by_apk.most_common(), 1):
        running += count
        if running * 2 >= total:
            return index
    return len(by_apk)


def _print_report(report: Mapping[str, Any]) -> None:
    print(
        f"\n外部可達 {report['reachable_units']} 筆"
        f"（positive {report['positives']}、negative {report['negatives']}，"
        f"{report['apks']} 個 APK）"
    )
    print(f"\nnegative 由哪個 predicate 否定：{report['negatives_refuted_by']}")
    print(
        f"negative 集中度：{report['apks_holding_half_the_negatives']} 個 APK 就佔了一半；"
        f"各 APK 筆數 {report['negatives_per_apk']}"
    )
    baseline = report["predict_all_positive"]
    print(
        f"\n全判 positive 的基準線：macroF1 {baseline['macro_f1']:.3f}、"
        f"balAcc {baseline['balanced_accuracy']:.3f}（抓到 0 筆 negative）"
    )
    header = f"\n{'特徵組合':<24}{'格子':>5}{'作弊上限 macroF1':>18}{'跨APK macroF1':>16}{'跨APK 抓到的 neg':>18}"
    print(header)
    print("-" * 82)
    for name in FEATURE_SETS:
        ceiling = report["oracle_ceiling"][name]
        cv = report["leave_one_apk_out"][name]
        print(
            f"{name:<24}{ceiling['cells']:>5}{ceiling['macro_f1']:>18.3f}"
            f"{cv['macro_f1']:>16.3f}{cv['tn']:>18}"
        )
    print("\n作弊上限＝直接用 Gold 答案擬合，任何只用這些特徵的分類器都無法超過；")
    print("跨 APK＝leave-one-APK-out，估計換一個沒看過的 APK 還剩多少效果。")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    rows = load_reachable_binary(args.gold_log, args.units, args.samples)
    report = analyse(rows)
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
