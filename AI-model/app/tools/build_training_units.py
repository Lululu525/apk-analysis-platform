"""從 pilot-300 證據產生與 Gold review unit 同座標系的訓練 unit。

本模組只做 identity 對齊與骨架輸出：它重用 `golden_review_packets._caller_unit`
計算 `review_unit_id`，不重新實作 id 演算法、不產生任何 label、也不挑選 feature。
`features` 一律輸出空 object，三層 label 一律 null，由後續步驟填入。

輸出是 pilot-300 的**全量** unit，仍包含 Golden 50，因此不可直接作為訓練資料。
排除 Golden lineage 是獨立的下游步驟，其產物才是 `training_units.jsonl`。

驗收方式是 `--verify-gold`：不排除 Golden 50 全量產生後，產出的 id 必須命中
`gold_review_log.jsonl` 的全部 review unit；命中不完全即代表 identity 漂移。
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .golden_review_packets import (
    NeutralInputUnavailableError,
    _caller_unit,
    extract_manifest_evidence,
    load_manifest_from_apk,
    load_projected_callers,
)

SCHEMA_VERSION = "training-unit-v1"
DEFAULT_PILOT_ROOT = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3"
)
DEFAULT_SAMPLES = DEFAULT_PILOT_ROOT / "selected_samples.csv"
DEFAULT_CALLERS = DEFAULT_PILOT_ROOT / "sensitive_api_callers.jsonl"
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
# 全量 pilot-300 unit，含 Golden 50。這不是訓練池：lineage 排除是獨立的
# 下游步驟，其產物才寫入 training_units.jsonl。
DEFAULT_OUTPUT = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class PilotEntry:
    """`_caller_unit` 只讀 sha256 與 package_name，這裡不冒充完整 MembershipEntry。"""

    sha256: str
    package_name: str
    source_path: str


def load_pilot_entries(samples_csv: Path) -> list[PilotEntry]:
    entries: list[PilotEntry] = []
    with samples_csv.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            sha256 = str(row.get("sha256") or "").strip()
            if not sha256:
                raise ValueError(f"selected_samples.csv 缺少 sha256：{row}")
            entries.append(
                PilotEntry(
                    sha256=sha256,
                    package_name=str(row.get("package_name") or "").strip(),
                    source_path=str(row.get("source_path") or "").strip(),
                )
            )
    return entries


def load_gold_unit_ids(gold_log: Path) -> dict[str, set[str]]:
    """依 row_kind 分組回傳 Gold review unit id。

    `concrete_path` unit 由 `_flow_unit()` 從 FlowDroid taint path 產生，而
    FlowDroid 只跑過 Golden 50、未跑 pilot-300，因此這類 unit 在此流程中
    結構上無法重建。驗收只能要求 `candidate` 全中，不能把兩者混在一起算。
    """
    by_kind: dict[str, set[str]] = {}
    with gold_log.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            unit_id = row.get("review_unit_id")
            if not unit_id:
                raise ValueError(f"gold review log line {line_number} 缺少 review_unit_id。")
            kind = str(row.get("row_kind") or "unknown")
            by_kind.setdefault(kind, set()).add(str(unit_id))
    return by_kind


def _manifest_for(entry: PilotEntry) -> dict[str, Any]:
    """走與 Golden packet 相同的 binary manifest 路徑。

    不提供 fallback：`manifest_name` 與 `resolved_code_owner` 一旦改由投影欄位
    推導就可能與 Gold 不同值，進而改變 candidate_id。讀不到就讓該 APK 失敗，
    寧可少一批 unit，也不要產生對不上 Gold 的 id。
    """
    apk_path = Path(entry.source_path)
    if not apk_path.is_file():
        raise NeutralInputUnavailableError(f"APK 不存在：{apk_path}")
    manifest = extract_manifest_evidence(load_manifest_from_apk(apk_path))
    manifest["extraction_status"] = "binary_manifest_verified"
    return manifest


def _training_row(*, entry: PilotEntry, unit: Mapping[str, Any]) -> dict[str, Any]:
    component = unit.get("component_identity") or {}
    effect = unit.get("sensitive_effect_candidate") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "review_unit_id": unit["review_unit_id"],
        "candidate_id": unit.get("candidate_id"),
        "row_kind": unit.get("row_kind"),
        "sha256": entry.sha256,
        "package_name": entry.package_name,
        "component_name": component.get("manifest_name"),
        "component_type": component.get("component_type"),
        "resolved_code_owner": component.get("resolved_code_owner"),
        "caller_class": effect.get("caller_class"),
        "caller_method": effect.get("caller_method"),
        "caller_descriptor": effect.get("caller_descriptor"),
        "call_offset": effect.get("call_offset"),
        "sink_class": effect.get("api_class"),
        "sink_method": effect.get("api_method"),
        "sink_group_id": effect.get("group_id"),
        "linkage_status": (unit.get("entry_evidence") or {}).get("linkage_status"),
        "coverage_limitations": unit.get("coverage_limitations") or [],
        "features": {},
        "observed_authz_label": None,
        "gold_authz_label": None,
        "revised_authz_label": None,
    }


def build_units(
    *,
    entries: Iterable[PilotEntry],
    callers_by_sha256: Mapping[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    stats: dict[str, Any] = {
        "apks_total": 0,
        "apks_manifest_ok": 0,
        "apks_manifest_failed": 0,
        "apks_without_callers": 0,
        "caller_rows_seen": 0,
        "caller_rows_unlinked": 0,
        "units_emitted": 0,
        "manifest_failures": [],
        "package_mismatches": [],
    }
    for entry in entries:
        stats["apks_total"] += 1
        callers = callers_by_sha256.get(entry.sha256) or []
        if not callers:
            stats["apks_without_callers"] += 1
            continue
        try:
            manifest = _manifest_for(entry)
        except Exception as exc:  # noqa: BLE001 - 單一 APK 失敗不得中止整批
            stats["apks_manifest_failed"] += 1
            stats["manifest_failures"].append(
                {"sha256": entry.sha256, "error": f"{type(exc).__name__}: {exc}"}
            )
            LOGGER.warning("manifest 讀取失敗，略過 %s：%s", entry.sha256[:12], exc)
            continue
        stats["apks_manifest_ok"] += 1
        if manifest.get("package_name") != entry.package_name:
            # 只記錄不中止：pilot CSV 的 package 來自 canonical metadata，
            # 與 binary manifest 不符時以 manifest 為準，但必須留痕。
            stats["package_mismatches"].append(
                {
                    "sha256": entry.sha256,
                    "csv": entry.package_name,
                    "manifest": manifest.get("package_name"),
                }
            )
        for caller in callers:
            stats["caller_rows_seen"] += 1
            unit = _caller_unit(entry=entry, manifest=manifest, caller=caller)
            if unit is None:
                stats["caller_rows_unlinked"] += 1
                continue
            rows.append(_training_row(entry=entry, unit=unit))
            stats["units_emitted"] += 1
    return rows, stats


def verify_against_gold(
    rows: Iterable[Mapping[str, Any]], gold_by_kind: Mapping[str, set[str]]
) -> dict[str, Any]:
    produced = {str(row["review_unit_id"]) for row in rows}
    candidates = gold_by_kind.get("candidate", set())
    missing = sorted(candidates - produced)
    out_of_scope = {
        kind: len(ids) for kind, ids in gold_by_kind.items() if kind != "candidate"
    }
    return {
        "candidate_total": len(candidates),
        "candidate_matched": len(candidates & produced),
        "candidate_missing": len(missing),
        "missing_sample": missing[:10],
        "out_of_scope_units": out_of_scope,
        "passed": not missing,
    }


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--callers", type=Path, default=DEFAULT_CALLERS)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--verify-gold",
        action="store_true",
        help="對 gold_review_log.jsonl 驗收 id 命中率；未全中時以非零狀態結束。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只統計與驗收，不寫出 training_units.jsonl。",
    )
    parser.add_argument("--limit", type=int, default=None, help="只處理前 N 個 APK（除錯用）。")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)

    entries = load_pilot_entries(args.samples)
    if args.limit is not None:
        entries = entries[: args.limit]
    callers_by_sha256 = load_projected_callers(
        args.callers, {entry.sha256 for entry in entries}
    )
    LOGGER.info(
        "載入 %d 個 APK，%d 個 APK 有 caller 證據。",
        len(entries),
        len(callers_by_sha256),
    )

    rows, stats = build_units(entries=entries, callers_by_sha256=callers_by_sha256)
    rows.sort(key=lambda row: (row["sha256"], row["review_unit_id"]))

    LOGGER.info("APK：總計 %d、manifest 成功 %d、失敗 %d、無 caller %d",
                stats["apks_total"], stats["apks_manifest_ok"],
                stats["apks_manifest_failed"], stats["apks_without_callers"])
    LOGGER.info("Caller row：讀入 %d、對不上 component %d、產生 unit %d",
                stats["caller_rows_seen"], stats["caller_rows_unlinked"],
                stats["units_emitted"])
    if stats["manifest_failures"]:
        LOGGER.warning("manifest 失敗 %d 筆，前 5 筆：%s",
                       len(stats["manifest_failures"]),
                       stats["manifest_failures"][:5])
    if stats["package_mismatches"]:
        LOGGER.warning("package 與 CSV 不符 %d 筆，前 5 筆：%s",
                       len(stats["package_mismatches"]),
                       stats["package_mismatches"][:5])

    exit_code = 0
    if args.verify_gold:
        report = verify_against_gold(rows, load_gold_unit_ids(args.gold_log))
        LOGGER.info(
            "Gold 驗收（candidate）：%d / %d 命中，缺 %d。",
            report["candidate_matched"],
            report["candidate_total"],
            report["candidate_missing"],
        )
        if report["out_of_scope_units"]:
            LOGGER.info(
                "不在本流程範圍的 Gold unit（FlowDroid 專屬，無法由 pilot 重建）：%s",
                report["out_of_scope_units"],
            )
        if report["passed"]:
            LOGGER.info("驗收通過：id 演算法與 Gold 一致。")
        else:
            LOGGER.error("驗收失敗，未命中範例：%s", report["missing_sample"])
            exit_code = 1

    if args.dry_run:
        LOGGER.info("dry-run：未寫出 %s。", args.output)
    else:
        write_jsonl(args.output, rows)
        LOGGER.info("已寫出 %d 筆至 %s。", len(rows), args.output)
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
