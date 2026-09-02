from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from app.tools import canonical_dataset_pilot as pilot


CANONICAL_FIELDS = [
    "sample_id",
    "sha256",
    "source_dataset",
    "source_path",
    "relative_path",
    "original_label",
    "binary_label",
    "size_bytes",
    "package_name",
    "canonical_status",
]

FIXTURE_STRATA = tuple(
    pilot.StratumSpec(label, binary_label=label)
    for label in pilot.DEFAULT_LABELS
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _row(path: Path, data: bytes, label: str, package: str = "com.example"):
    digest = _sha256(data)
    return {
        "sample_id": f"sha256:{digest}",
        "sha256": digest,
        "source_dataset": "fixture",
        "source_path": str(path),
        "relative_path": path.name,
        "original_label": "Benign" if label == "benign" else "Adware",
        "binary_label": label,
        "size_bytes": str(len(data)),
        "package_name": package,
        "canonical_status": "included",
    }


def _write_csv(path: Path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CANONICAL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _features(package_name="com.example"):
    filter_rows = [{
        "sample_id": "replaced-by-caller",
        "package_name": package_name,
        "component_name": f"{package_name}.MainActivity",
        "component_type": "activity",
        "actions": ["android.intent.action.MAIN"],
        "categories": [],
        "data_types": [],
        "data_schemes": [],
        "permission": None,
        "exported": True,
        "protected": False,
    }]
    resolution_rows = [{
        "sample_id": "replaced-by-caller",
        "intent_component_name": "<UNKNOWN>",
        "filter_component_name": f"{package_name}.MainActivity",
        "match_action": True,
        "match_category": True,
        "match_type": True,
        "risk_hint": None,
    }]
    return {
        "filter_rows": filter_rows,
        "resolution_rows": resolution_rows,
        "app_summary": {
            "package_name": package_name,
            "components": {
                "activities": [f"{package_name}.MainActivity"],
                "services": [f"{package_name}.SyncService"],
                "providers": [],
                "receivers": [],
            },
            "exported_unprotected": [f"{package_name}.MainActivity"],
            "sensitive_api_callers": [{
                "group_id": "SENSITIVE_API_CODE_EXEC",
                "group_label": "命令執行 / 反射 / 動態載入 API",
                "api_class": "java/lang/Runtime",
                "api_method": "exec",
                "description": "執行系統命令",
                "caller_class": "Lcom/example/MainActivity;",
                "caller_method": "onCreate",
                "caller_descriptor": "()V",
                "call_offset": 4,
                "source": "androguard_xref",
            }],
            "sensitive_api_scan_status": "complete",
            "sensitive_api_scan_error_count": 0,
        },
    }


def test_balanced_selection_is_exact_and_independent_of_csv_order(tmp_path):
    rows = []
    for label in ("benign", "non_benign"):
        for index in range(4):
            data = f"{label}-{index}".encode()
            rows.append(_row(tmp_path / f"{label}-{index}.apk", data, label))
    for row_number, row in enumerate(rows, start=2):
        row["_canonical_row_number"] = str(row_number)

    first = pilot.select_balanced_samples(rows, 4, "fixed-seed")
    second = pilot.select_balanced_samples(list(reversed(rows)), 4, "fixed-seed")

    assert [row["sample_id"] for row in first] == [row["sample_id"] for row in second]
    assert {label: sum(row["binary_label"] == label for row in first) for label in pilot.DEFAULT_LABELS} == {
        "benign": 2,
        "non_benign": 2,
    }


def test_default_six_strata_selection_takes_exactly_one_from_each(tmp_path):
    rows = []
    for spec in pilot.DEFAULT_STRATA:
        for index in range(2):
            data = f"{spec.name}-{index}".encode()
            path = tmp_path / f"{spec.name}-{index}.apk"
            row = _row(
                path,
                data,
                spec.binary_label or ("benign" if spec.original_label == "Benign" else "non_benign"),
            )
            row["source_dataset"] = spec.source_dataset or "fixture"
            row["original_label"] = spec.original_label or row["original_label"]
            row["_canonical_row_number"] = str(len(rows) + 2)
            rows.append(row)

    selected = pilot.select_stratified_samples(rows, 6, "fixed-seed")

    assert len(selected) == 6
    assert {row["_stratum"] for row in selected} == {
        spec.name for spec in pilot.DEFAULT_STRATA
    }
    assert all(row["_stratum_reason"] for row in selected)


def test_run_pilot_validates_hash_continues_failures_and_keeps_inputs_unchanged(tmp_path):
    valid_a = tmp_path / "valid-a.apk"
    valid_b = tmp_path / "valid-b.apk"
    mismatch = tmp_path / "mismatch.apk"
    missing = tmp_path / "missing.apk"
    valid_a.write_bytes(b"valid-a")
    valid_b.write_bytes(b"valid-b")
    mismatch.write_bytes(b"different-content")

    rows = [
        _row(valid_a, b"valid-a", "benign"),
        _row(missing, b"expected-but-missing", "benign"),
        _row(valid_b, b"valid-b", "non_benign"),
        _row(mismatch, b"expected-content", "non_benign"),
    ]
    canonical_csv = tmp_path / "canonical_balanced_dataset.csv"
    _write_csv(canonical_csv, rows)
    before_csv = canonical_csv.read_bytes()
    before_a = valid_a.read_bytes()
    before_b = valid_b.read_bytes()
    parsed_paths = []

    def fake_builder(path, sample_id):
        parsed_paths.append(path)
        features = _features()
        for key in ("filter_rows", "resolution_rows"):
            features[key][0]["sample_id"] = sample_id
        return features

    output_dir = tmp_path / "pilot-output"
    summary = pilot.run_pilot(
        canonical_csv,
        output_dir,
        sample_size=4,
        seed="fixture",
        strata=FIXTURE_STRATA,
        progress_every=1,
        feature_builder=fake_builder,
    )

    assert set(parsed_paths) == {valid_a, valid_b}
    assert summary["validation"]["sha256_match_count"] == 2
    assert summary["validation"]["error_counts"] == {
        "sha256_mismatch": 1,
        "source_missing": 1,
    }
    assert summary["parsing"]["success_count"] == 2
    assert summary["evidence"]["component_total_count"] == 4
    assert summary["evidence"]["component_evidence_row_count"] == 2
    assert summary["evidence"]["manifest_resolution_path_count"] == 2
    assert summary["evidence"]["exported_component_count"] == 2
    assert summary["evidence"]["unique_exported_component_name_count"] == 2
    assert summary["evidence"]["sensitive_api_caller_count"] == 2
    assert summary["evidence"]["sensitive_api_direct_entry_caller_count"] == 2
    assert summary["input"]["canonical_csv_unchanged"] is True
    assert canonical_csv.read_bytes() == before_csv
    assert valid_a.read_bytes() == before_a
    assert valid_b.read_bytes() == before_b

    results = list(csv.DictReader(
        (output_dir / "sample_results.csv").open(encoding="utf-8-sig", newline="")
    ))
    assert len(results) == 4
    assert {row["parse_status"] for row in results} == {"success", "skipped"}
    assert len((output_dir / "component_evidence.jsonl").read_text(encoding="utf-8").splitlines()) == 2
    sensitive_evidence = [
        json.loads(line)
        for line in (output_dir / "sensitive_api_callers.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(sensitive_evidence) == 2
    assert all(
        item["evidence"]["linkage_status"] == "direct_entry_caller"
        for item in sensitive_evidence
    )
    path_evidence = [
        json.loads(line)
        for line in (output_dir / "manifest_path_evidence.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert {item["evidence_kind"] for item in path_evidence} == {
        "manifest_resolution_candidate"
    }


def test_parse_error_is_recorded_and_batch_continues(tmp_path):
    files = []
    rows = []
    for label in pilot.DEFAULT_LABELS:
        path = tmp_path / f"{label}.apk"
        data = label.encode()
        path.write_bytes(data)
        files.append(path)
        rows.append(_row(path, data, label))
    canonical_csv = tmp_path / "canonical.csv"
    _write_csv(canonical_csv, rows)

    calls = 0

    def flaky_builder(path, sample_id):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("broken manifest")
        return _features()

    summary = pilot.run_pilot(
        canonical_csv,
        tmp_path / "out",
        sample_size=2,
        strata=FIXTURE_STRATA,
        feature_builder=flaky_builder,
        progress_every=1,
    )

    assert calls == 2
    assert summary["parsing"]["attempted_count"] == 2
    assert summary["parsing"]["success_count"] == 1
    assert summary["validation"]["error_counts"] == {"parse_error": 1}


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("'cp950' codec can't decode byte 0xe2", "parse_encoding_error"),
        ("InvalidInstruction: invalid instruction for 0xdd", "parse_invalid_bytecode"),
        ("broken manifest", "parse_error"),
    ],
)
def test_parse_error_classification(message, expected):
    assert pilot._parse_error_code(ValueError(message)) == expected


def test_load_rejects_sample_id_sha256_disagreement(tmp_path):
    apk = tmp_path / "a.apk"
    row = _row(apk, b"a", "benign")
    row["sample_id"] = "sha256:" + "0" * 64
    canonical_csv = tmp_path / "bad.csv"
    _write_csv(canonical_csv, [row])

    with pytest.raises(ValueError, match="sample_id"):
        pilot.load_canonical_csv(canonical_csv)


def test_nonempty_output_directory_is_not_overwritten(tmp_path):
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    sentinel = output_dir / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError, match="拒絕覆寫"):
        pilot._prepare_output_dir(output_dir)
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_androguard_log_namespace_is_disabled(monkeypatch):
    disabled = []

    class FakeLogger:
        def disable(self, name):
            disabled.append(name)

    fake_loguru = type("FakeLoguru", (), {"logger": FakeLogger()})
    monkeypatch.setitem(__import__("sys").modules, "loguru", fake_loguru)

    pilot._silence_androguard_logs()

    assert disabled == ["androguard"]
