"""只看 I／S 的 labeling function，產生 `observed_authz_label`。

執行順序第 5b 項（ADR-0002），規格見 `docs/authz_lf_spec_v1.md`。

R 由 `r_gate.py` 的確定性規則在最前面處理，**`exported` 不參與本 LF**；A 沒有任何自動化
證據，本 LF 不判 A。因此 `exported` 既不在 feature 也不在訓練標籤。

判定順序依 `authz_annotation_guide.md` 的 I → S：

1. sink 不在外部可觸發的 entry method 裡   → negative（**weak negative**，見下）
2. sink 需要的平台 permission 未宣告       → negative（weak negative）
3. `caller_class` 對不上任何 Manifest component → abstain（S unknown）
4. 其餘                                    → positive（sink 就在 entry method 裡）

**規則 1 與 2 是 weak-negative 啟發式，不是 I 或 S 的 refutation。** 規則 1 的實質是
「沒有找到 entry 到 sink 的證據」：外部呼叫者確實觸發了 entry method（I 成立），
不明的是 entry 到不到得了 sink，而那條呼叫鏈我們沒有分析。把它記成 I refuted 正是
ADR-0002 2026-09-22 修訂警告過的歸因錯誤。弱監督本來就是用這種啟發式，但命名與報告
必須據實描述。凍結後對 Gold 的量測證實了代價：positive recall 只有 0.177（spec §6.1）。

abstain 的 `observed_authz_label` 寫 `null`、不進訓練（spec §5「做法一」）。
不改成 3 分類的理由見 spec §5：`unknown` 是我們的證據的性質，不是 App 的性質。

**噪音率必須先凍結再測。** `--noise-rate` 會拿同一個 LF 去跑 Gold 並比對，
依 spec §6 只能在本模組 commit 之後執行；不得反過來依 Gold 調整 LF
（`authz_label_spec.md` §10）。
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence

from .build_authz_features import SINK_PERMISSIONS, read_units
from .gold_consistency import load_identities, load_latest_events
from .r_gate import ManifestCache, judge_reachability

LF_VERSION = "authz-lf-v1"

DEFAULT_TRAINING_UNITS = Path("dataset/authz_v2/training_units.jsonl")
DEFAULT_CANDIDATE_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_OUTPUT = Path("dataset/authz_v2/observed_labels_training.jsonl")
DEFAULT_SUMMARY = Path("dataset/authz_v2/observed_labels_summary.json")
DEFAULT_NOISE_OUTPUT = Path("dataset/authz_v2/experiments/lf_noise_rate.json")
DEFAULT_GOLD_EVAL_OUTPUT = Path("dataset/authz_v2/observed_labels_gold_eval.jsonl")

# 外部呼叫者能使其執行的 entry method。刻意與
# `canonical_dataset_pilot.ENTRY_METHODS` 分歧——那組是為保守的 direct identity match
# 而設計，本 LF 問的是「外部觸發得到嗎」。理由與 196 筆影響見 spec §3.1。
ENTRY_METHODS: Mapping[str, frozenset[str]] = {
    "activity": frozenset({"onCreate", "onNewIntent", "onStart", "onResume"}),
    "service": frozenset({"onStartCommand", "onBind", "onStart", "onHandleIntent"}),
    "receiver": frozenset({"onReceive"}),
    "provider": frozenset(
        {"query", "insert", "update", "delete", "openFile", "call", "getType"}
    ),
}

UNLINKED = "unlinked_caller"

LOGGER = logging.getLogger(__name__)


def is_entry_method(unit: Mapping[str, Any]) -> bool:
    """外部呼叫者能不能使 sink 所在的 method 執行（I 的判準）。"""
    methods = ENTRY_METHODS.get(str(unit["component_type"]))
    if methods is None:
        raise ValueError(
            f"未知的 component_type {unit['component_type']!r}；"
            f"entry method 集合只涵蓋 {sorted(ENTRY_METHODS)}。"
        )
    return str(unit["caller_method"]) in methods


def sink_permission_undeclared(
    unit: Mapping[str, Any], manifest: Mapping[str, Any]
) -> bool:
    """呼叫需要 permission 的 sink 但 APK 從未宣告（S 的弱反證）。"""
    required = SINK_PERMISSIONS.get((str(unit["sink_class"]), str(unit["sink_method"])))
    if not required:
        return False
    return not (required & set(manifest.get("uses_permissions", [])))


def label(unit: Mapping[str, Any], manifest: Mapping[str, Any]) -> tuple[str | None, str]:
    """回傳 (observed_authz_label, reason_code)。abstain 時 label 為 None。

    reason code 刻意以 `weak_` 開頭，以免把啟發式讀成 predicate 的 refutation。
    """
    if not is_entry_method(unit):
        return "negative", "weak_negative_no_entry_to_sink_evidence"
    if sink_permission_undeclared(unit, manifest):
        return "negative", "weak_negative_sink_permission_undeclared"
    if str(unit["linkage_status"]) == UNLINKED:
        return None, "abstain_caller_class_not_component"
    return "positive", "weak_positive_sink_in_entry_method"


def label_all(
    units: Sequence[Mapping[str, Any]], manifests: ManifestCache
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for unit in units:
        manifest = manifests.get(str(unit["sha256"]))
        if not manifest:
            raise ValueError(f"讀不到 {unit['sha256']} 的 manifest，無法產生標籤。")
        observed, reason = label(unit, manifest)
        rows.append(
            {
                "review_unit_id": unit["review_unit_id"],
                "lf_version": LF_VERSION,
                "observed_authz_label": observed,
                "reason_code": reason,
            }
        )
    return rows


def label_gold_eval_units(
    gold_log: Path, candidate_units: Path, manifests: ManifestCache
) -> list[dict[str, Any]]:
    """把 `--noise-rate` 內部已經算過的 LF-on-Gold 輸出落成逐筆產物。

    `authz_eval_protocol_v1.md` §6 的錯誤分析需要知道每一筆 Gold unit 的 LF 標籤
    （哪些是 LF 漏判的 positive），而 `lf_noise_rate.json` 只有聚合的混淆矩陣。

    **這裡用的是同一個凍結的 `label()`，LF 沒有任何改動。** 本函式不讀取
    `gold_authz_label`，只用 Gold log 取得 unit 清單；輸出是 LF 的標籤，不是 Gold 的。
    """
    identities = load_identities(candidate_units, set(load_latest_events(gold_log)))
    return label_all(
        [identities[unit_id] for unit_id in sorted(identities)],
        manifests,
    )


def summarise(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    labels = collections.Counter(row["observed_authz_label"] for row in rows)
    binary = labels["positive"] + labels["negative"]
    return {
        "lf_version": LF_VERSION,
        "units": len(rows),
        "positive": labels["positive"],
        "negative": labels["negative"],
        "abstain": labels[None],
        "trainable_units": binary,
        "positive_share_of_binary": labels["positive"] / binary if binary else 0.0,
        "reason_codes": dict(
            sorted(collections.Counter(row["reason_code"] for row in rows).items())
        ),
    }


def _classification(pairs: Sequence[tuple[str, str]]) -> dict[str, Any]:
    tp = sum(1 for gold, obs in pairs if gold == "positive" and obs == "positive")
    fp = sum(1 for gold, obs in pairs if gold == "negative" and obs == "positive")
    fn = sum(1 for gold, obs in pairs if gold == "positive" and obs == "negative")
    tn = sum(1 for gold, obs in pairs if gold == "negative" and obs == "negative")

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
        "precision": precision,
        "recall": recall,
        "macro_f1": (f1(precision, recall) + f1(negative_precision, specificity)) / 2,
        "balanced_accuracy": (recall + specificity) / 2,
        "agreement_rate": (tp + tn) / len(pairs) if pairs else 0.0,
        "noise_rate": 1 - (tp + tn) / len(pairs) if pairs else 0.0,
    }


def noise_rate(
    gold_log: Path, candidate_units: Path, manifests: ManifestCache
) -> dict[str, Any]:
    """LF 與 Gold 的一致率與噪音率。**只能在 LF 凍結後執行**（spec §6）。

    僅報告，不得據此調整 LF。分兩層：

    - `all_binary`：Gold 全部二分類 unit，含 R 已被規則否定者。此層的數字會被 R 主導，
      不能與第九章的參考線比較。
    - `reachable_subset`：規則判為可達的 unit，即模型真正負責的那一層，與
      `bottleneck_analysis` 的 106 筆母體一致，因此可與 0.439／0.519／0.695 並列。
    """
    events = load_latest_events(gold_log)
    identities = load_identities(candidate_units, set(events))
    matrix: collections.Counter = collections.Counter()
    layers: dict[str, list[tuple[str, str]]] = {"all_binary": [], "reachable_subset": []}
    abstained = {"all_binary": 0, "reachable_subset": 0}
    for unit_id, identity in identities.items():
        gold = events[unit_id]["gold_authz_label"]
        manifest = manifests.get(str(identity["sha256"]))
        if not manifest:
            continue
        observed, _ = label(identity, manifest)
        matrix[(gold, observed or "abstain")] += 1
        if gold not in ("positive", "negative"):
            continue
        reachable = (
            judge_reachability(
                manifest, str(identity["component_name"]), str(identity["component_type"])
            )["result"]
            != "refuted"
        )
        for name in ("all_binary",) + (("reachable_subset",) if reachable else ()):
            if observed is None:
                abstained[name] += 1
            else:
                layers[name].append((gold, observed))
    report: dict[str, Any] = {
        "lf_version": LF_VERSION,
        "gold_units_seen": sum(matrix.values()),
        "matrix": {f"gold={key[0]}|lf={key[1]}": count for key, count in sorted(matrix.items())},
    }
    for name, pairs in layers.items():
        report[name] = {
            **_classification(pairs),
            "compared_units": len(pairs),
            "lf_abstained": abstained[name],
            "all_positive_macro_f1": _classification([(g, "positive") for g, _ in pairs])[
                "macro_f1"
            ],
            "all_negative_macro_f1": _classification([(g, "negative") for g, _ in pairs])[
                "macro_f1"
            ],
        }
    return report


def _print_summary(summary: Mapping[str, Any]) -> None:
    print(
        f"\n{summary['units']} 筆：positive {summary['positive']}、"
        f"negative {summary['negative']}、abstain {summary['abstain']}"
    )
    print(
        f"  可訓練 {summary['trainable_units']} 筆，"
        f"positive 佔二分類 {summary['positive_share_of_binary']:.1%}"
    )
    print("\n  reason code：")
    for reason, count in summary["reason_codes"].items():
        print(f"    {reason:<44} {count:>5}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-units", type=Path, default=DEFAULT_TRAINING_UNITS)
    parser.add_argument("--candidate-units", type=Path, default=DEFAULT_CANDIDATE_UNITS)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--noise-rate",
        action="store_true",
        help="對 Gold 量 LF 的噪音率。依 spec §6 只能在 LF 已 commit 凍結後執行。",
    )
    parser.add_argument("--noise-output", type=Path, default=DEFAULT_NOISE_OUTPUT)
    parser.add_argument(
        "--gold-eval-labels",
        action="store_true",
        help="以同一個凍結 LF 產出 Gold 評估集的逐筆標籤，供評估協議 §6 的錯誤分析使用。",
    )
    parser.add_argument(
        "--gold-eval-output", type=Path, default=DEFAULT_GOLD_EVAL_OUTPUT
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)

    units = read_units(args.training_units)
    manifests = ManifestCache(args.samples)
    rows = label_all(units, manifests)
    summary = summarise(rows)
    _print_summary(summary)

    if args.noise_rate:
        report = noise_rate(args.gold_log, args.candidate_units, manifests)
        for name, title in (
            ("all_binary", "Gold 全部二分類（含 R 已否定，會被 R 主導）"),
            ("reachable_subset", "外部可達子集（模型負責的那一層，可與第九章並列）"),
        ):
            layer = report[name]
            print(f"\n{title}：{layer['compared_units']} 筆（LF abstain {layer['lf_abstained']}）")
            print(
                f"  TP {layer['tp']}  FP {layer['fp']}  FN {layer['fn']}  TN {layer['tn']}"
                f"  | precision {layer['precision']:.3f}  recall {layer['recall']:.3f}"
            )
            print(
                f"  macro F1 {layer['macro_f1']:.3f}  噪音率 {layer['noise_rate']:.1%}"
                f"  | 對照：全判 positive {layer['all_positive_macro_f1']:.3f}、"
                f"全判 negative {layer['all_negative_macro_f1']:.3f}"
            )
        print()
        for key, count in report["matrix"].items():
            print(f"    {key:<34} {count:>5}")
        if not args.dry_run:
            args.noise_output.parent.mkdir(parents=True, exist_ok=True)
            args.noise_output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            LOGGER.info("已寫出 %s。", args.noise_output)

    if args.gold_eval_labels:
        gold_rows = label_gold_eval_units(args.gold_log, args.candidate_units, manifests)
        gold_summary = summarise(gold_rows)
        print(
            f"\nGold 評估集的 LF 標籤：{gold_summary['units']} 筆"
            f"（positive {gold_summary['positive']}、negative {gold_summary['negative']}、"
            f"abstain {gold_summary['abstain']}）"
        )
        if not args.dry_run:
            args.gold_eval_output.parent.mkdir(parents=True, exist_ok=True)
            with args.gold_eval_output.open("w", encoding="utf-8", newline="\n") as handle:
                for row in gold_rows:
                    handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            LOGGER.info("已寫出 %s。", args.gold_eval_output)

    if args.dry_run:
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    args.summary.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOGGER.info("已寫出 %s、%s。", args.output, args.summary)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
