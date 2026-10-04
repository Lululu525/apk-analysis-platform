"""M2／M3 對 Gold 的評估。協議見 `docs/authz_eval_protocol_v1.md`（執行前已凍結）。

執行順序第 5c-ii 項（ADR-0002）。**這是整個專題第一次把模型預測與 Gold 放在一起。**
在此之前的 6 次訓練執行全程未讀取 Gold。

本模組唯讀：不修改任何 label、不訓練、不調整任何設定。它只做三件事——
把預測與 Gold join、套用協議凍結的指標、把結果寫下來。

threshold 固定為 0.5（即 argmax，`predictions_<run>.jsonl` 內已算好），不做搜尋。
分類與排序指標直接沿用 `rule_baselines.py` 的實作，使數字可與既有的三條參考線並列，
不另寫第二份。
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence

from .gold_consistency import load_identities, load_latest_events
from .r_gate import ManifestCache, judge_reachability
from .rule_baselines import _classification, _ranking

EVAL_VERSION = "model-eval-gold-v1"

DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_EXPERIMENTS_DIR = Path("dataset/authz_v2/experiments")
DEFAULT_OUTPUT = DEFAULT_EXPERIMENTS_DIR / "model_eval_gold.json"

SEEDS = (20260823, 20260824, 20260825)
RUNS = tuple(f"{model}-seed{seed}" for model in ("m2", "m3") for seed in SEEDS)

# 協議 §3 的參考線，全部取自已 commit 的既有產物，不在此重算。
REFERENCE_LINES: Mapping[str, Mapping[str, Any]] = {
    "all_negative": {"macro_f1": 0.184, "source": "lf_noise_rate.json"},
    "lf_observed_label": {"macro_f1": 0.331, "source": "lf_noise_rate.json"},
    "reachability_rule_all_positive": {"macro_f1": 0.439, "source": "bottleneck_analysis.json"},
    "cross_apk_majority": {"macro_f1": 0.519, "source": "bottleneck_analysis.json"},
    "fitted_on_gold_ceiling": {"macro_f1": 0.695, "source": "bottleneck_analysis.json"},
}
LEAKAGE_SUSPICION_THRESHOLD = 0.695

LOGGER = logging.getLogger(__name__)


# --- 載入 ---------------------------------------------------------------------


def load_predictions(experiments_dir: Path, run_id: str) -> dict[str, dict[str, Any]]:
    """只取 `split = gold_eval` 的列。回傳 review_unit_id → 該列。"""
    path = experiments_dir / f"predictions_{run_id}.jsonl"
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if row["split"] == "gold_eval":
                rows[str(row["review_unit_id"])] = row
    if not rows:
        raise ValueError(f"{path} 沒有任何 gold_eval 的預測。")
    return rows


def build_population(
    *,
    gold_log: Path,
    units_path: Path,
    manifests: ManifestCache,
    predicted_unit_ids: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """協議 §1 的兩層母體。回傳 (rows, 筆數交代)。

    `rows` 的欄位刻意與 `rule_baselines.score_units` 的輸出同形（`label`、`sha256`、
    `scores`、`predictions`），才能直接套用那邊的指標實作。
    """
    events = load_latest_events(gold_log)
    identities = load_identities(units_path, set(events))
    rows: list[dict[str, Any]] = []
    accounting = {
        "gold_events": len(events),
        "with_identity": 0,
        "with_prediction": 0,
        "gold_binary": 0,
        "excluded_gold_unknown": 0,
        "excluded_no_prediction": 0,
        "excluded_no_identity": 0,
    }
    for unit_id, event in events.items():
        identity = identities.get(unit_id)
        if identity is None:
            accounting["excluded_no_identity"] += 1
            continue
        accounting["with_identity"] += 1
        if unit_id not in predicted_unit_ids:
            accounting["excluded_no_prediction"] += 1
            continue
        accounting["with_prediction"] += 1
        label = event["gold_authz_label"]
        if label not in ("positive", "negative"):
            accounting["excluded_gold_unknown"] += 1
            continue
        accounting["gold_binary"] += 1
        manifest = manifests.get(str(identity["sha256"]))
        reachability = judge_reachability(
            manifest, str(identity["component_name"]), str(identity["component_type"])
        )["result"]
        rows.append(
            {
                "review_unit_id": unit_id,
                "sha256": str(identity["sha256"]),
                "label": label,
                "sink_group_id": identity.get("sink_group_id"),
                "reachability": reachability,
            }
        )
    accounting["reachable"] = sum(1 for row in rows if row["reachability"] != "refuted")
    accounting["r_refuted"] = accounting["gold_binary"] - accounting["reachable"]
    return rows, accounting


def attach_run(
    rows: Sequence[Mapping[str, Any]], predictions: Mapping[str, Mapping[str, Any]], run_id: str
) -> list[dict[str, Any]]:
    """把一次執行的預測掛上母體。threshold 固定 0.5，直接採用已算好的硬預測。"""
    attached: list[dict[str, Any]] = []
    for row in rows:
        prediction = predictions[row["review_unit_id"]]
        attached.append(
            {
                **row,
                "scores": {run_id: float(prediction["prob_positive"])},
                "predictions": {run_id: prediction["predicted_label"] == "positive"},
            }
        )
    return attached


# --- 指標 ---------------------------------------------------------------------


def evaluate_run(rows: Sequence[Mapping[str, Any]], run_id: str) -> dict[str, Any]:
    return {
        "classification": _classification(rows, run_id),
        "ranking": _ranking(rows, run_id, (10, 50)),
    }


def aggregate(per_seed: Mapping[int, Mapping[str, Any]], metric: str) -> dict[str, Any]:
    """協議 §4：平均與極差並列。不取最佳 seed。"""
    values = [per_seed[seed]["classification"][metric] for seed in SEEDS]
    return {
        "per_seed": {str(seed): per_seed[seed]["classification"][metric] for seed in SEEDS},
        "mean": sum(values) / len(values),
        "min": min(values),
        "max": max(values),
        "spread": max(values) - min(values),
    }


def paired_differences(
    m2: Mapping[int, Mapping[str, Any]], m3: Mapping[int, Mapping[str, Any]], metric: str
) -> dict[str, Any]:
    """協議 §5：逐 seed 配對差。不做顯著性檢定（n = 3，配對不獨立）。"""
    differences = {
        str(seed): m3[seed]["classification"][metric] - m2[seed]["classification"][metric]
        for seed in SEEDS
    }
    values = list(differences.values())
    signs = {1 if value > 0 else (-1 if value < 0 else 0) for value in values}
    return {
        "metric": metric,
        "per_seed": differences,
        "mean_difference": sum(values) / len(values),
        "directions_agree": len(signs) == 1,
        "note": (
            "三個差值方向一致" if len(signs) == 1 else "三個差值方向不一致，差距在 seed 噪音之內"
        ),
    }


def leakage_check(per_seed: Mapping[int, Mapping[str, Any]]) -> dict[str, Any]:
    """協議 §3 判讀規則 1：macro F1 > 0.695 是洩漏的強烈跡象，不是好消息。"""
    exceeded = [
        str(seed)
        for seed in SEEDS
        if per_seed[seed]["classification"]["macro_f1"] > LEAKAGE_SUSPICION_THRESHOLD
    ]
    return {
        "threshold": LEAKAGE_SUSPICION_THRESHOLD,
        "seeds_exceeding": exceeded,
        "suspected": bool(exceeded),
    }


# --- 協議 §6 的錯誤分析 ------------------------------------------------------


def lf_error_analysis(
    rows: Sequence[Mapping[str, Any]],
    observed_labels: Mapping[str, str | None],
    predictions_by_run: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    """LF 的三個誤差格 × 6 次執行。協議 §6 要求「想修的」與「代價」並列。

    `missed_positives` 即 `authz_lf_spec_v1.md` §6.1 的那 65 筆（Gold positive、
    LF negative）。`gold_negatives` 是修正的代價那一側。
    """
    buckets: dict[str, list[str]] = {
        "lf_missed_positives": [],
        "lf_true_positives": [],
        "lf_false_positives": [],
        "lf_abstained": [],
        "gold_negatives": [],
    }
    for row in rows:
        unit_id = row["review_unit_id"]
        observed = observed_labels.get(unit_id, "missing")
        if row["label"] == "negative":
            buckets["gold_negatives"].append(unit_id)
        if observed is None:
            buckets["lf_abstained"].append(unit_id)
        elif row["label"] == "positive" and observed == "negative":
            buckets["lf_missed_positives"].append(unit_id)
        elif row["label"] == "positive" and observed == "positive":
            buckets["lf_true_positives"].append(unit_id)
        elif row["label"] == "negative" and observed == "positive":
            buckets["lf_false_positives"].append(unit_id)

    report: dict[str, Any] = {}
    for name, unit_ids in buckets.items():
        wants_positive = name != "gold_negatives"
        report[name] = {
            "units": len(unit_ids),
            # gold_negatives 要的是「預測 negative」（TN），其餘要的是「預測 positive」。
            "metric": "predicted_negative" if name == "gold_negatives" else "predicted_positive",
            "by_run": {
                run_id: sum(
                    1
                    for unit_id in unit_ids
                    if (predictions_by_run[run_id][unit_id]["predicted_label"] == "positive")
                    == wants_positive
                )
                for run_id in RUNS
            },
        }
    return report


def load_observed_labels(path: Path) -> dict[str, str | None]:
    """LF 在 Gold 評估集上的輸出。不存在時回傳空 dict，錯誤分析會據此略過。"""
    labels: dict[str, str | None] = {}
    if not path.exists():
        return labels
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                labels[str(row["review_unit_id"])] = row["observed_authz_label"]
    return labels


# --- 組裝 ---------------------------------------------------------------------


def evaluate(
    *,
    rows: Sequence[Mapping[str, Any]],
    predictions_by_run: Mapping[str, Mapping[str, Mapping[str, Any]]],
    accounting: Mapping[str, Any],
    observed_labels: Mapping[str, str | None],
) -> dict[str, Any]:
    layers: dict[str, Any] = {}
    for layer_name, subset in (
        ("pipeline_all_binary", list(rows)),
        ("reachable_subset", [row for row in rows if row["reachability"] != "refuted"]),
    ):
        by_run: dict[str, Any] = {}
        for run_id in RUNS:
            attached = attach_run(subset, predictions_by_run[run_id], run_id)
            by_run[run_id] = evaluate_run(attached, run_id)
        per_model = {
            model: {seed: by_run[f"{model}-seed{seed}"] for seed in SEEDS}
            for model in ("m2", "m3")
        }
        layers[layer_name] = {
            "evaluated_units": len(subset),
            "positives": sum(1 for row in subset if row["label"] == "positive"),
            "negatives": sum(1 for row in subset if row["label"] == "negative"),
            "runs": by_run,
            "aggregates": {
                model: {
                    metric: aggregate(per_model[model], metric)
                    for metric in ("macro_f1", "recall", "precision", "balanced_accuracy")
                }
                for model in ("m2", "m3")
            },
            "m3_minus_m2": {
                metric: paired_differences(per_model["m2"], per_model["m3"], metric)
                for metric in ("macro_f1", "recall", "precision", "balanced_accuracy")
            },
            "leakage_check": {
                model: leakage_check(per_model[model]) for model in ("m2", "m3")
            },
        }

    report: dict[str, Any] = {
        "eval_version": EVAL_VERSION,
        "protocol": "docs/authz_eval_protocol_v1.md",
        "threshold": 0.5,
        "threshold_searched": False,
        "best_seed_selected": False,
        "probability_ensemble": False,
        "significance_test": False,
        "population_accounting": dict(accounting),
        "reference_lines": {name: dict(value) for name, value in REFERENCE_LINES.items()},
        "layers": layers,
    }
    if observed_labels:
        report["lf_error_analysis_reachable_subset"] = lf_error_analysis(
            [row for row in rows if row["reachability"] != "refuted"],
            observed_labels,
            predictions_by_run,
        )
    return report


# --- 報表 ---------------------------------------------------------------------


LAYER_TITLES = {
    "pipeline_all_binary": "整條流程（Gold 全部二分類；會被 R 已否定的 unit 主導）",
    "reachable_subset": "外部可達子集（模型實際負責的那一層，主要層）",
}


def _print_report(report: Mapping[str, Any]) -> None:
    accounting = report["population_accounting"]
    print(
        f"\nGold event {accounting['gold_events']} 筆 → 有 identity "
        f"{accounting['with_identity']} → 有預測 {accounting['with_prediction']} → "
        f"二分類 {accounting['gold_binary']}（排除 unknown "
        f"{accounting['excluded_gold_unknown']}）→ 外部可達 {accounting['reachable']}"
        f"（R 否定 {accounting['r_refuted']}）"
    )
    for layer_name, layer in report["layers"].items():
        print(f"\n=== {LAYER_TITLES[layer_name]} ===")
        print(
            f"{layer['evaluated_units']} 筆"
            f"（positive {layer['positives']}、negative {layer['negatives']}）\n"
        )
        header = (
            f"{'執行':<18}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}"
            f"{'P':>8}{'R':>8}{'MacroF1':>9}{'BalAcc':>8}{'P@10':>7}{'看80%':>7}"
        )
        print(header)
        print("-" * len(header))
        for run_id, payload in layer["runs"].items():
            c, r = payload["classification"], payload["ranking"]
            print(
                f"{run_id:<18}{c['tp']:>5}{c['fp']:>5}{c['fn']:>5}{c['tn']:>5}"
                f"{c['precision']:>8.3f}{c['recall']:>8.3f}{c['macro_f1']:>9.3f}"
                f"{c['balanced_accuracy']:>8.3f}{r['P@10']:>7.2f}"
                f"{str(r['units_to_80pct_recall']):>7}"
            )
        print()
        for model in ("m2", "m3"):
            macro = layer["aggregates"][model]["macro_f1"]
            print(
                f"  {model.upper()} macro F1：平均 {macro['mean']:.3f}、"
                f"極差 {macro['min']:.3f}–{macro['max']:.3f}（{macro['spread']:.3f}）"
            )
        difference = layer["m3_minus_m2"]["macro_f1"]
        print(
            f"  M3 − M2 配對差："
            + "、".join(f"{seed} {value:+.3f}" for seed, value in difference["per_seed"].items())
            + f"；平均 {difference['mean_difference']:+.3f} → {difference['note']}"
        )
        for model in ("m2", "m3"):
            check = layer["leakage_check"][model]
            if check["suspected"]:
                print(
                    f"  ⚠ {model.upper()} 的 seed {check['seeds_exceeding']} macro F1 超過 "
                    f"{check['threshold']}（以 Gold 直接擬合的上限），依協議 §3 視為洩漏跡象。"
                )

    print("\n=== 參考線（外部可達子集，macro F1）===")
    for name, value in report["reference_lines"].items():
        print(f"  {name:<34}{value['macro_f1']:.3f}   {value['source']}")

    analysis = report.get("lf_error_analysis_reachable_subset")
    if analysis:
        print("\n=== 協議 §6 的錯誤分析（外部可達子集）===")
        header = f"{'LF 的格子':<22}{'筆數':>6}  {'要的':<19}" + "".join(
            f"{run_id.replace('-seed2026', '·'):>10}" for run_id in RUNS
        )
        print(header)
        print("-" * len(header))
        for name, payload in analysis.items():
            print(
                f"{name:<22}{payload['units']:>6}  {payload['metric']:<19}"
                + "".join(f"{payload['by_run'][run_id]:>10}" for run_id in RUNS)
            )
        print(
            "\n  lf_missed_positives 是 authz_lf_spec_v1.md §6.1 的那 65 筆（SLB 想修的）；"
            "\n  gold_negatives 是修正的代價那一側。依協議 §6 兩者必須並列判讀。"
        )


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--experiments-dir", type=Path, default=DEFAULT_EXPERIMENTS_DIR)
    parser.add_argument(
        "--gold-observed-labels",
        type=Path,
        default=Path("dataset/authz_v2/observed_labels_gold_eval.jsonl"),
        help="LF 在 Gold 評估集上的輸出，供協議 §6 的錯誤分析使用。",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true", help="只印報表，不寫 JSON。")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    predictions_by_run = {
        run_id: load_predictions(args.experiments_dir, run_id) for run_id in RUNS
    }
    predicted_unit_ids = set(predictions_by_run[RUNS[0]])
    for run_id, predictions in predictions_by_run.items():
        if set(predictions) != predicted_unit_ids:
            raise ValueError(f"{run_id} 的 gold_eval unit 集合與其他執行不一致。")

    rows, accounting = build_population(
        gold_log=args.gold_log,
        units_path=args.units,
        manifests=ManifestCache(args.samples),
        predicted_unit_ids=predicted_unit_ids,
    )
    observed_labels = load_observed_labels(args.gold_observed_labels)
    if not observed_labels:
        LOGGER.warning(
            "找不到 %s，略過協議 §6 的錯誤分析。", args.gold_observed_labels
        )
    report = evaluate(
        rows=rows,
        predictions_by_run=predictions_by_run,
        accounting=accounting,
        observed_labels=observed_labels,
    )
    _print_report(report)
    if args.dry_run:
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOGGER.info("已寫出 %s。", args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
