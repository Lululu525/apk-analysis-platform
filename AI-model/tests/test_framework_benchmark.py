from __future__ import annotations

import csv
import hashlib
import json
import re
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
    assert metadata["semantics"]["reviewer_packet_is_verdict_blind"] is True
    assert metadata["reviewer_packet"]["staged_input_count"] == 6
    assert metadata["reviewer_packet"]["staged_sha256_verified"] is True

    membership = list(csv.DictReader((output_dir / "benchmark_membership.csv").open(encoding="utf-8-sig")))
    execution = list(csv.DictReader((output_dir / "execution_ledger.csv").open(encoding="utf-8-sig")))
    manual = list(csv.DictReader((output_dir / "manual_review_ledger.csv").open(encoding="utf-8-sig")))
    assert len(membership) == 6
    assert len(execution) == 12
    assert len(manual) == 6
    assert {row["status"] for row in execution} == {"pending"}
    assert all(row["sha256_match"] == "True" for row in membership)
    forbidden_fields = {
        "stratum",
        "source_path",
        "source_dataset",
        "original_label",
        "binary_label",
    }
    assert forbidden_fields.isdisjoint(manual[0])
    assert {row["sample_id"] for row in manual} == {row["sample_id"] for row in membership}
    for row in manual:
        assert re.fullmatch(r"review_inputs/\d{2}_[0-9a-f]{12}\.apk", row["review_apk_path"])
        review_apk = output_dir / row["review_apk_path"]
        assert review_apk.is_file()
        assert benchmark.sha256_file(review_apk) == row["expected_sha256"]
    assert json.loads((output_dir / "selection_metadata.json").read_text(encoding="utf-8")) == metadata


def test_create_membership_refuses_to_overwrite_mismatched_review_input(tmp_path):
    source_path = tmp_path / "source.apk"
    source_path.write_bytes(b"expected source")
    expected_sha256 = benchmark.sha256_file(source_path)
    staged_path = tmp_path / "review_inputs" / f"01_{expected_sha256[:12]}.apk"
    staged_path.parent.mkdir()
    staged_path.write_bytes(b"unexpected replacement")

    try:
        benchmark._stage_reviewer_input(source_path, staged_path, expected_sha256)
    except ValueError as exc:
        assert "拒絕覆寫" in str(exc)
    else:
        raise AssertionError("應拒絕覆寫 SHA-256 不符的 review input")
