"""由 pilot-300 全量 unit 產生排除 Golden lineage 後的訓練池。

排除依據**不在本模組重新計算**：`golden_50_selection_metadata.json` 的
`candidate_registry[].excluded_from_future_training_by_golden_group` 是
membership 凍結時就決定好的結果（規則為「同 package 或明確 canonical lineage
的傳遞閉包；不以 certificate 單獨推定 lineage」）。這裡只讀取並套用，
避免出現與凍結決定不一致的第二套 lineage 規則。

輸出的 `training_units.jsonl` 才是 M2／M3 可用的訓練資料。
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = "training-pool-v1"
DEFAULT_INPUT = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_SELECTION_METADATA = Path("dataset/authz_v2/golden_50_selection_metadata.json")
DEFAULT_OUTPUT = Path("dataset/authz_v2/training_units.jsonl")
DEFAULT_SUMMARY = Path("dataset/authz_v2/training_pool_summary.json")

LOGGER = logging.getLogger(__name__)


def load_exclusion(metadata_path: Path) -> dict[str, set[str]]:
    """讀取凍結的 Golden membership 與 lineage 排除名單。"""
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    registry = metadata.get("candidate_registry")
    if not registry:
        raise ValueError(f"{metadata_path} 缺少 candidate_registry。")
    golden: set[str] = set()
    excluded: set[str] = set()
    for row in registry:
        sha256 = str(row.get("sha256") or "")
        if not sha256:
            raise ValueError("candidate_registry 有列缺少 sha256。")
        if row.get("golden_member"):
            golden.add(sha256)
        if row.get("excluded_from_future_training_by_golden_group"):
            excluded.add(sha256)
    registered = {str(row.get("sha256")) for row in registry}
    siblings = {str(sha) for sha in metadata.get("golden_group_sibling_sha256") or []}
    if not golden <= excluded:
        raise ValueError("凍結資料不一致：golden_member 未全數列入排除名單。")
    if not siblings <= excluded:
        raise ValueError("凍結資料不一致：sibling 未全數列入排除名單。")
    return {
        "golden": golden,
        "excluded": excluded,
        "siblings": siblings,
        "registered": registered,
    }


def read_units(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not row.get("review_unit_id") or not row.get("sha256"):
                raise ValueError(f"{path} line {line_number} 缺少 review_unit_id 或 sha256。")
            rows.append(row)
    return rows


def partition(
    rows: Iterable[Mapping[str, Any]], exclusion: Mapping[str, set[str]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    golden = exclusion["golden"]
    excluded = exclusion["excluded"]
    registered = exclusion["registered"]
    kept: list[dict[str, Any]] = []
    dropped_golden = 0
    dropped_sibling = 0
    kept_shas: set[str] = set()
    dropped_shas: set[str] = set()
    unregistered_shas: set[str] = set()
    for row in rows:
        sha256 = str(row["sha256"])
        if sha256 in excluded:
            dropped_shas.add(sha256)
            if sha256 in golden:
                dropped_golden += 1
            else:
                dropped_sibling += 1
            continue
        if sha256 not in registered:
            # 不在凍結的 candidate_registry 裡＝沒有 lineage 判定依據。
            # 靜默保留會讓訓練池含有無法稽核的資料，因此明確剔除並留痕。
            unregistered_shas.add(sha256)
            dropped_shas.add(sha256)
            continue
        kept.append(dict(row))
        kept_shas.add(sha256)
    stats = {
        "schema_version": SCHEMA_VERSION,
        "units_in": dropped_golden + dropped_sibling + len(kept),
        "units_dropped_golden": dropped_golden,
        "units_dropped_lineage_sibling": dropped_sibling,
        "units_kept": len(kept),
        "apks_kept": len(kept_shas),
        "apks_dropped": len(dropped_shas),
        "apks_dropped_unregistered": len(unregistered_shas),
        "unregistered_apks": sorted(unregistered_shas),
        "exclusion_source": "golden_50_selection_metadata.json"
        "#candidate_registry.excluded_from_future_training_by_golden_group",
        "lineage_rule": "同 package 或明確 canonical lineage 的傳遞閉包；"
        "不以 certificate 單獨推定 lineage。",
    }
    return kept, stats


def assert_no_gold_leak(rows: Iterable[Mapping[str, Any]], gold_log: Path) -> int:
    """訓練池不得含有任何已審查的 Gold review unit。"""
    gold_ids = set()
    with gold_log.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                gold_ids.add(str(json.loads(line)["review_unit_id"]))
    overlap = gold_ids & {str(row["review_unit_id"]) for row in rows}
    if overlap:
        raise ValueError(
            f"訓練池含有 {len(overlap)} 筆 Gold review unit，範例：{sorted(overlap)[:5]}"
        )
    return len(gold_ids)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--selection-metadata", type=Path, default=DEFAULT_SELECTION_METADATA)
    parser.add_argument("--gold-log", type=Path, default=Path("dataset/authz_v2/gold_review_log.jsonl"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--dry-run", action="store_true", help="只統計，不寫檔。")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)

    exclusion = load_exclusion(args.selection_metadata)
    LOGGER.info(
        "凍結排除名單：golden %d、sibling %d、合計排除 %d 個 APK。",
        len(exclusion["golden"]),
        len(exclusion["siblings"]),
        len(exclusion["excluded"]),
    )

    rows = read_units(args.input)
    kept, stats = partition(rows, exclusion)
    gold_total = assert_no_gold_leak(kept, args.gold_log)

    LOGGER.info(
        "Unit：讀入 %d、排除 golden %d、排除 lineage sibling %d、保留 %d。",
        stats["units_in"],
        stats["units_dropped_golden"],
        stats["units_dropped_lineage_sibling"],
        stats["units_kept"],
    )
    LOGGER.info("APK：保留 %d、排除 %d。", stats["apks_kept"], stats["apks_dropped"])
    if stats["apks_dropped_unregistered"]:
        LOGGER.warning(
            "剔除 %d 個不在 candidate_registry 的 APK（無 lineage 判定依據）：%s",
            stats["apks_dropped_unregistered"],
            stats["unregistered_apks"][:5],
        )
    LOGGER.info("Gold 隔離檢查通過：%d 筆 Gold unit 全部不在訓練池。", gold_total)

    if args.dry_run:
        LOGGER.info("dry-run：未寫出 %s。", args.output)
        return 0

    kept.sort(key=lambda row: (row["sha256"], row["review_unit_id"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in kept:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    args.summary.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOGGER.info("已寫出 %d 筆至 %s，統計至 %s。", len(kept), args.output, args.summary)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
