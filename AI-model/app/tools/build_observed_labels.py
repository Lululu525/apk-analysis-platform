"""只看 I／S 的 labeling function，產生 `observed_authz_label`。

執行順序第 5b 項（ADR-0002），規格見 `docs/authz_lf_spec_v1.md`。

R 由 `r_gate.py` 的確定性規則在最前面處理，**`exported` 不參與本 LF**；A 沒有任何自動化
證據，本 LF 不判 A。因此 `exported` 既不在 feature 也不在訓練標籤。

判定順序依 `authz_annotation_guide.md` 的 I → S，negative 在第一個決定性否定即停止：

1. `caller_method` 不是外部可觸發的 entry method       → negative（I 不成立）
2. sink 需要的平台 permission 未宣告                   → negative（S 弱反證）
3. `caller_class` 對不上任何 Manifest component        → abstain（S unknown）
4. 其餘                                                → positive

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
from .r_gate import ManifestCache

LF_VERSION = "authz-lf-v1"

DEFAULT_TRAINING_UNITS = Path("dataset/authz_v2/training_units.jsonl")
DEFAULT_CANDIDATE_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_OUTPUT = Path("dataset/authz_v2/observed_labels_training.jsonl")
DEFAULT_SUMMARY = Path("dataset/authz_v2/observed_labels_summary.json")

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
    """回傳 (observed_authz_label, reason_code)。abstain 時 label 為 None。"""
    if not is_entry_method(unit):
        return "negative", "i_refuted_not_entry_method"
    if sink_permission_undeclared(unit, manifest):
        return "negative", "s_refuted_sink_permission_undeclared"
    if str(unit["linkage_status"]) == UNLINKED:
        return None, "s_unknown_caller_class_not_component"
    return "positive", "positive_i_trigger_and_s_linkage"


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


def noise_rate(
    gold_log: Path, candidate_units: Path, manifests: ManifestCache
) -> dict[str, Any]:
    """LF 與 Gold 的一致率。**只能在 LF 凍結後執行**（spec §6）。

    僅報告，不得據此調整 LF。只比對 Gold 為二分類、且 LF 未 abstain 的 unit。
    """
    events = load_latest_events(gold_log)
    identities = load_identities(candidate_units, set(events))
    matrix: collections.Counter = collections.Counter()
    for unit_id, identity in identities.items():
        gold = events[unit_id]["gold_authz_label"]
        manifest = manifests.get(str(identity["sha256"]))
        if not manifest:
            continue
        observed, _ = label(identity, manifest)
        matrix[(gold, observed or "abstain")] += 1
    compared = {
        key: count
        for key, count in matrix.items()
        if key[0] in ("positive", "negative") and key[1] != "abstain"
    }
    total = sum(compared.values())
    agree = sum(count for key, count in compared.items() if key[0] == key[1])
    return {
        "lf_version": LF_VERSION,
        "gold_units_seen": sum(matrix.values()),
        "compared_units": total,
        "agreements": agree,
        "agreement_rate": agree / total if total else 0.0,
        "noise_rate": 1 - agree / total if total else 0.0,
        "matrix": {f"gold={key[0]}|lf={key[1]}": count for key, count in sorted(matrix.items())},
    }


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
        print(
            f"\nLF vs Gold：比對 {report['compared_units']} 筆、"
            f"一致 {report['agreements']} 筆、"
            f"一致率 {report['agreement_rate']:.1%}、噪音率 {report['noise_rate']:.1%}"
        )
        for key, count in report["matrix"].items():
            print(f"    {key:<34} {count:>5}")
        summary["gold_noise_rate"] = report

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
