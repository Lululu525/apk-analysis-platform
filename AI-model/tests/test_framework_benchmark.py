from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from app.tools import framework_benchmark as benchmark


def _fixture_rows(tmp_path: Path):
    rows = []
    for stratum_index, stratum in enumerate(benchmark.EXPECTED_STRATA):
        for level, base in enumerate((1, 50, 100)):
            content = f"{stratum}-{level}".encode()
            source_path = tmp_path / f"{stratum}-{level}.apk"
            source_path.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            value = base + stratum_index
            rows.append(
                {
                    "stratum": stratum,
                    "sample_id": f"sha256:{digest}",
                    "expected_sha256": digest,
                    "computed_sha256": digest,
                    "source_path": str(source_path),
                    "source_dataset": "fixture",
                    "original_label": "fixture",
                    "binary_label": "fixture",
                    "validation_status": "valid",
                    "parse_status": "success",
                    "sha256_match": "True",
                    "parsed_package_name": f"com.example.{stratum}.{level}",
                    "actual_size_bytes": str(value * 1000),
                    "component_total_count": str(value),
                    "component_evidence_row_count": str(value),
                    "exported_component_count": str(value),
                    "sensitive_api_call_site_count": str(value),
                    "sensitive_api_caller_count": str(value),
                }
            )
    return rows


def _write_padded_csv(path: Path, rows):
    fields = list(rows[0])
    padded_fields = [field if index == 0 else f" {field}  " for index, field in enumerate(fields)]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(padded_fields)
        for row in rows:
            writer.writerow(
                [row[field] if index == 0 else f" {row[field]} " for index, field in enumerate(fields)]
            )


def test_load_eligible_rows_normalizes_padded_pilot_csv(tmp_path):
    pilot_csv = tmp_path / "pilot.csv"
    rows = _fixture_rows(tmp_path)
    _write_padded_csv(pilot_csv, rows)

    eligible, fields = benchmark.load_eligible_rows(pilot_csv)

    assert len(eligible) == 18
    assert "stratum" in fields
    assert eligible[0]["stratum"] in benchmark.EXPECTED_STRATA


def test_select_six_is_deterministic_with_required_coverage(tmp_path):
    rows = _fixture_rows(tmp_path)

    first, _ = benchmark.select_six(rows)
    second, _ = benchmark.select_six(list(reversed(rows)))

    assert [row["sample_id"] for row in first] == [row["sample_id"] for row in second]
    assert {row["stratum"] for row in first} == set(benchmark.EXPECTED_STRATA)
    assert {
        tier: sum(row["_complexity_tier"] == tier for row in first)
        for tier in ("low", "medium", "high")
    } == {"low": 2, "medium": 2, "high": 2}


def test_create_membership_validates_sha_and_writes_three_ledgers(tmp_path):
    pilot_csv = tmp_path / "pilot.csv"
    _write_padded_csv(pilot_csv, _fixture_rows(tmp_path))
    output_dir = tmp_path / "output"

    metadata = benchmark.create_benchmark_membership(pilot_csv, output_dir)

    assert metadata["input"]["eligible_count"] == 18
    assert metadata["selection"]["selected_count"] == 6
    assert metadata["selection"]["selected_stratum_counts"] == {
        stratum: 1 for stratum in benchmark.EXPECTED_STRATA
    }
    assert metadata["selection"]["selected_tier_counts"] == {
        "low": 2,
        "medium": 2,
        "high": 2,
    }
    assert metadata["semantics"]["is_golden_set"] is False

    membership = list(csv.DictReader((output_dir / "benchmark_membership.csv").open(encoding="utf-8-sig")))
    execution = list(csv.DictReader((output_dir / "execution_ledger.csv").open(encoding="utf-8-sig")))
    manual = list(csv.DictReader((output_dir / "manual_review_ledger.csv").open(encoding="utf-8-sig")))
    assert len(membership) == 6
    assert len(execution) == 12
    assert len(manual) == 6
    assert {row["status"] for row in execution} == {"pending"}
    assert all(row["sha256_match"] == "True" for row in membership)
    assert json.loads((output_dir / "selection_metadata.json").read_text(encoding="utf-8")) == metadata
