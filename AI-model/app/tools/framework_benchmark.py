"""建立固定的 6-APK MobSF/FlowDroid paired benchmark membership。

此 benchmark 只估計工具穩定性與人工覆核工作量，不是 50-APK Golden Set，
也不會產生 authorization label。輸入成員只能來自既有 pilot CSV。
"""
from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import itertools
import json
from pathlib import Path
from statistics import median
from typing import Any, Mapping, Sequence

from .flowdroid_poc import FLOWDROID_VERSION, prepare_output_dir, sha256_file
from .mobsf_poc import MOBSF_VERSION


SCHEMA_VERSION = "framework-paired-benchmark-v1"
SELECTION_SALT = "framework-paired-benchmark-v1"
EXPECTED_STRATA = (
    "fdroid_benign",
    "maldroid_benign",
    "maldroid_adware",
    "maldroid_banking",
    "maldroid_riskware",
    "maldroid_sms",
)
COMPLEXITY_FEATURES = (
    "actual_size_bytes",
    "component_total_count",
    "component_evidence_row_count",
    "sensitive_api_call_site_count",
    "sensitive_api_caller_count",
)
REQUIRED_FIELDS = {
    "stratum",
    "sample_id",
    "expected_sha256",
    "computed_sha256",
    "source_path",
    "source_dataset",
    "original_label",
    "binary_label",
    "validation_status",
    "parse_status",
    "sha256_match",
    "parsed_package_name",
    "exported_component_count",
    *COMPLEXITY_FEATURES,
}
MEMBERSHIP_FIELDS = (
    "benchmark_rank",
    "complexity_tier",
    "stratum",
    "sample_id",
    "expected_sha256",
    "computed_sha256",
    "sha256_match",
    "source_path",
    "source_dataset",
    "original_label",
    "binary_label",
    "dataset_label_role",
    "parsed_package_name",
    "actual_size_bytes",
    "component_total_count",
    "component_evidence_row_count",
    "exported_component_count",
    "sensitive_api_call_site_count",
    "sensitive_api_caller_count",
    "complexity_score",
    "tier_anchor_score",
    "selection_distance",
    "selection_reason",
)
EXECUTION_FIELDS = (
    "benchmark_rank",
    "sample_id",
    "expected_sha256",
    "complexity_tier",
    "tool",
    "tool_version",
    "status",
    "output_dir",
    "started_at_utc",
    "completed_at_utc",
    "duration_seconds",
    "finding_count",
    "error_type",
    "error_message",
)
MANUAL_REVIEW_FIELDS = (
    "benchmark_rank",
    "sample_id",
    "expected_sha256",
    "complexity_tier",
    "review_unit_count",
    "without_tools_minutes",
    "with_tools_minutes",
    "time_saved_minutes",
    "r_evidence_complete",
    "i_evidence_complete",
    "s_evidence_complete",
    "a_evidence_complete",
    "tool_false_positive_count",
    "remaining_manual_checks",
    "notes",
)


def normalize_csv_row(row: Mapping[str | None, str | None]) -> dict[str, str]:
    return {
        (key or "").strip(): (value or "").strip()
        for key, value in row.items()
        if key is not None
    }


def load_eligible_rows(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        normalized_fields = [(field or "").strip() for field in (reader.fieldnames or [])]
        missing = sorted(REQUIRED_FIELDS - set(normalized_fields))
        if missing:
            raise ValueError(f"pilot CSV 缺少必要欄位：{missing}")
        normalized = [normalize_csv_row(row) for row in reader]

    eligible = [
        row
        for row in normalized
        if row["validation_status"] == "valid"
        and row["parse_status"] == "success"
        and row["sha256_match"].lower() == "true"
        and row["expected_sha256"] == row["computed_sha256"]
    ]
    if not eligible:
        raise ValueError("pilot CSV 沒有 eligible rows。")

    duplicate_samples = _duplicates(row["sample_id"] for row in eligible)
    duplicate_hashes = _duplicates(row["expected_sha256"] for row in eligible)
    if duplicate_samples or duplicate_hashes:
        raise ValueError(
            f"eligible rows identity 不唯一：sample_id={duplicate_samples}, sha256={duplicate_hashes}"
        )
    return eligible, normalized_fields


def _duplicates(values: Sequence[str] | Any) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def _numeric(row: Mapping[str, str], field: str) -> float:
    try:
        value = float(row[field])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{row.get('sample_id', '<unknown>')} 的 {field} 不是數值。") from exc
    if value < 0:
        raise ValueError(f"{row.get('sample_id', '<unknown>')} 的 {field} 不得為負數。")
    return value


def _percentile_rank(sorted_values: list[float], value: float) -> float:
    if len(sorted_values) == 1:
        return 0.0
    left = bisect.bisect_left(sorted_values, value)
    right = bisect.bisect_right(sorted_values, value) - 1
    average_rank = (left + right) / 2
    return average_rank / (len(sorted_values) - 1)


def _tie_hash(sample_id: str) -> str:
    return hashlib.sha256(f"{SELECTION_SALT}\0{sample_id}".encode()).hexdigest()


def score_complexity(rows: Sequence[Mapping[str, str]]) -> list[dict[str, Any]]:
    distributions = {
        field: sorted(_numeric(row, field) for row in rows)
        for field in COMPLEXITY_FEATURES
    }
    scored: list[dict[str, Any]] = []
    for source_row in rows:
        row: dict[str, Any] = dict(source_row)
        ranks = [
            _percentile_rank(distributions[field], _numeric(source_row, field))
            for field in COMPLEXITY_FEATURES
        ]
        row["_complexity_score"] = sum(ranks) / len(ranks)
        row["_tie_hash"] = _tie_hash(source_row["sample_id"])
        scored.append(row)

    ordered = sorted(
        scored,
        key=lambda row: (row["_complexity_score"], row["_tie_hash"], row["sample_id"]),
    )
    size = len(ordered)
    low_end = size // 3
    medium_end = (2 * size) // 3
    for index, row in enumerate(ordered):
        row["_complexity_tier"] = (
            "low" if index < low_end else "medium" if index < medium_end else "high"
        )
    return ordered


def select_six(rows: Sequence[Mapping[str, str]]) -> tuple[list[dict[str, Any]], dict[str, float]]:
    scored = score_complexity(rows)
    strata_present = {str(row["stratum"]) for row in scored}
    missing_strata = sorted(set(EXPECTED_STRATA) - strata_present)
    if missing_strata:
        raise ValueError(f"eligible rows 缺少 benchmark strata：{missing_strata}")

    anchors = {
        tier: median(
            row["_complexity_score"]
            for row in scored
            if row["_complexity_tier"] == tier
        )
        for tier in ("low", "medium", "high")
    }
    candidate_lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for stratum in EXPECTED_STRATA:
        for tier in anchors:
            candidates = [
                row
                for row in scored
                if row["stratum"] == stratum and row["_complexity_tier"] == tier
            ]
            if not candidates:
                raise ValueError(f"stratum={stratum} 在 tier={tier} 沒有 candidate。")
            candidate_lookup[(stratum, tier)] = min(
                candidates,
                key=lambda row: (
                    abs(row["_complexity_score"] - anchors[tier]),
                    row["_tie_hash"],
                    row["sample_id"],
                ),
            )

    assignments: list[tuple[tuple[float, tuple[str, ...]], dict[str, str]]] = []
    stratum_indexes = range(len(EXPECTED_STRATA))
    for low_indexes in itertools.combinations(stratum_indexes, 2):
        remaining = [index for index in stratum_indexes if index not in low_indexes]
        for medium_indexes in itertools.combinations(remaining, 2):
            assignment = {
                stratum: (
                    "low"
                    if index in low_indexes
                    else "medium"
                    if index in medium_indexes
                    else "high"
                )
                for index, stratum in enumerate(EXPECTED_STRATA)
            }
            objective = sum(
                abs(
                    candidate_lookup[(stratum, tier)]["_complexity_score"]
                    - anchors[tier]
                )
                for stratum, tier in assignment.items()
            )
            tier_signature = tuple(assignment[stratum] for stratum in EXPECTED_STRATA)
            assignments.append(((objective, tier_signature), assignment))

    _, best_assignment = min(assignments, key=lambda item: item[0])
    selected = []
    for stratum, tier in best_assignment.items():
        row = dict(candidate_lookup[(stratum, tier)])
        row["_tier_anchor_score"] = anchors[tier]
        row["_selection_distance"] = abs(row["_complexity_score"] - anchors[tier])
        selected.append(row)
    tier_order = {"low": 0, "medium": 1, "high": 2}
    selected.sort(
        key=lambda row: (
            tier_order[row["_complexity_tier"]],
            row["_selection_distance"],
            row["_tie_hash"],
        )
    )
    return selected, anchors


def _write_csv(path: Path, fields: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def create_benchmark_membership(pilot_csv: Path, output_dir: Path) -> dict[str, Any]:
    pilot_csv = pilot_csv.resolve()
    if not pilot_csv.is_file():
        raise FileNotFoundError(f"pilot CSV 不存在：{pilot_csv}")
    eligible, input_fields = load_eligible_rows(pilot_csv)
    selected, anchors = select_six(eligible)

    membership_rows = []
    for benchmark_rank, row in enumerate(selected, start=1):
        source_path = Path(row["source_path"])
        if not source_path.is_file():
            raise FileNotFoundError(f"selected APK 不存在：{source_path}")
        computed_sha256 = sha256_file(source_path)
        if computed_sha256 != row["expected_sha256"]:
            raise ValueError(
                f"selected APK SHA-256 不符：{source_path}, "
                f"expected={row['expected_sha256']}, actual={computed_sha256}"
            )
        membership_rows.append(
            {
                "benchmark_rank": benchmark_rank,
                "complexity_tier": row["_complexity_tier"],
                "stratum": row["stratum"],
                "sample_id": row["sample_id"],
                "expected_sha256": row["expected_sha256"],
                "computed_sha256": computed_sha256,
                "sha256_match": True,
                "source_path": str(source_path),
                "source_dataset": row["source_dataset"],
                "original_label": row["original_label"],
                "binary_label": row["binary_label"],
                "dataset_label_role": "source_dataset_only_not_authz",
                "parsed_package_name": row["parsed_package_name"],
                **{field: row[field] for field in COMPLEXITY_FEATURES},
                "exported_component_count": row["exported_component_count"],
                "complexity_score": f"{row['_complexity_score']:.9f}",
                "tier_anchor_score": f"{row['_tier_anchor_score']:.9f}",
                "selection_distance": f"{row['_selection_distance']:.9f}",
                "selection_reason": (
                    "one_per_source_stratum;two_per_complexity_tier;"
                    "nearest_tier_median_under_global_minimum"
                ),
            }
        )

    output_dir = prepare_output_dir(output_dir)
    membership_path = output_dir / "benchmark_membership.csv"
    execution_path = output_dir / "execution_ledger.csv"
    manual_path = output_dir / "manual_review_ledger.csv"
    metadata_path = output_dir / "selection_metadata.json"
    _write_csv(membership_path, MEMBERSHIP_FIELDS, membership_rows)

    execution_rows = []
    for row in membership_rows:
        short_hash = row["expected_sha256"][:12]
        for tool, version in (
            ("flowdroid", FLOWDROID_VERSION),
            ("mobsf", MOBSF_VERSION),
        ):
            execution_rows.append(
                {
                    "benchmark_rank": row["benchmark_rank"],
                    "sample_id": row["sample_id"],
                    "expected_sha256": row["expected_sha256"],
                    "complexity_tier": row["complexity_tier"],
                    "tool": tool,
                    "tool_version": version,
                    "status": "pending",
                    "output_dir": f"runs/{row['benchmark_rank']:02d}_{short_hash}/{tool}",
                }
            )
    _write_csv(execution_path, EXECUTION_FIELDS, execution_rows)
    _write_csv(
        manual_path,
        MANUAL_REVIEW_FIELDS,
        [
            {
                "benchmark_rank": row["benchmark_rank"],
                "sample_id": row["sample_id"],
                "expected_sha256": row["expected_sha256"],
                "complexity_tier": row["complexity_tier"],
            }
            for row in membership_rows
        ],
    )

    manifest_material = "\n".join(
        f"{row['benchmark_rank']},{row['complexity_tier']},{row['stratum']},{row['sample_id']}"
        for row in membership_rows
    )
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "input": {
            "pilot_csv": str(pilot_csv),
            "pilot_csv_sha256": sha256_file(pilot_csv),
            "input_field_count": len(input_fields),
            "eligible_count": len(eligible),
        },
        "selection": {
            "selected_count": len(membership_rows),
            "expected_strata": list(EXPECTED_STRATA),
            "selected_stratum_counts": {
                stratum: sum(row["stratum"] == stratum for row in membership_rows)
                for stratum in EXPECTED_STRATA
            },
            "selected_tier_counts": {
                tier: sum(row["complexity_tier"] == tier for row in membership_rows)
                for tier in ("low", "medium", "high")
            },
            "complexity_features": list(COMPLEXITY_FEATURES),
            "complexity_method": "mean global percentile rank",
            "tier_method": "global thirds; select two per tier and one per source stratum",
            "tier_anchor_scores": anchors,
            "tie_breaker": f"sha256({SELECTION_SALT}\\0sample_id)",
            "selected_manifest_sha256": hashlib.sha256(
                manifest_material.encode("utf-8")
            ).hexdigest(),
        },
        "semantics": {
            "purpose": "tool_workload_and_manual_review_paired_benchmark",
            "is_golden_set": False,
            "produces_authz_labels": False,
            "source_dataset_labels_are_authz_labels": False,
        },
    }
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="建立固定 6-APK framework paired benchmark。")
    parser.add_argument("--pilot-csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metadata = create_benchmark_membership(args.pilot_csv, args.output_dir)
    print(json.dumps(metadata["selection"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
