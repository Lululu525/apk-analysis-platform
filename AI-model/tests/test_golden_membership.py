from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np
import pytest

from app.tools import golden_membership as g


REPO_ROOT = Path(__file__).resolve().parents[1]


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def make_pilot(tmp_path, count=60):
    canonical = []; pilot = []
    for i in range(count):
        apk = tmp_path / f"{i}.apk"
        apk.write_bytes(f"fixture-{i}".encode())
        sha = hashlib.sha256(apk.read_bytes()).hexdigest()
        canonical.append({"sample_id": f"sha256:{sha}", "sha256": sha,
                          "source_path": str(apk), "package_name": f"p{i}",
                          "version_code": str(i), "version_name": f"1.{i}", "lineage_group": ""})
        row = {"parse_status": "success", "validation_status": "valid", "sha256_match": "True",
               "expected_sha256": sha, "computed_sha256": sha, "sample_id": f"sha256:{sha}",
               "source_path": str(apk), "canonical_row_number": str(i+2), "parsed_package_name": f"p{i}"}
        row.update({f: str((i+1)*(j+1) % 29) for j, f in enumerate(g.COUNT_FIELDS)})
        row.update({f: "0" for f in g.DIRECT_FIELDS})
        pilot.append(row)
    cp = tmp_path / "canonical.csv"; pp = tmp_path / "sample_results.csv"
    write_csv(cp, canonical);write_csv(pp, pilot)
    return pp, cp, pilot, canonical


def test_exact_feature_allowlist_and_ratio_semantics():
    row = {f: "3" for f in g.COUNT_FIELDS}
    row.update({g.DIRECT_FIELDS[0]: "2", g.DIRECT_FIELDS[1]: "1"})
    expected = [math.log1p(3)] * 8 + [2/3, 1/3]
    assert g.feature_vector(row) == expected
    row.update({k: "THIS MUST NOT BE PARSED" for k in [
        "observed_label", "revised_label", "malware_family", "source_dataset", "model_prediction",
        "mobsf_finding_id", "exported", "protected", "permission_<NONE>", "risk_hint"]})
    assert g.feature_vector(row) == expected
    row["sensitive_api_caller_count"] = "0"
    row.update({f: "0" for f in g.DIRECT_FIELDS})
    assert g.feature_vector(row)[-2:] == [0.0, 0.0]
    assert g.FEATURES == [
        "log1p(activity_count)", "log1p(service_count)", "log1p(provider_count)",
        "log1p(receiver_count)", "log1p(component_evidence_row_count)",
        "log1p(unique_exported_component_name_count)", "log1p(sensitive_api_call_site_count)",
        "log1p(sensitive_api_caller_count)", "direct_component_ratio", "direct_entry_ratio"]


@pytest.mark.parametrize("bad", ["nan", "inf", "-1", "0.5"])
def test_invalid_counts_fail_closed(bad):
    row = {f: "0" for f in (*g.COUNT_FIELDS, *g.DIRECT_FIELDS)}
    row[g.COUNT_FIELDS[0]] = bad
    with pytest.raises(ValueError):
        g.feature_vector(row)


def test_dedupe_failed_rows_and_transitive_lineage(tmp_path):
    pp, cp, pilot, canonical = make_pilot(tmp_path)
    # 同 package 的不同版本，以及跨 package 的明確 lineage 必須連成同 group。
    canonical[1]["package_name"] = canonical[0]["package_name"]
    pilot[1]["parsed_package_name"] = pilot[0]["parsed_package_name"]
    canonical[1]["lineage_group"] = canonical[2]["lineage_group"] = "known-family-lineage"
    pilot[-1]["parse_status"] = "failed"
    pilot[-1][g.COUNT_FIELDS[0]] = "invalid-but-excluded"
    write_csv(cp, canonical);write_csv(pp, pilot + [pilot[0]])
    rows, counts = g.load_candidates(pp, cp)
    assert counts["parse_success_count"] == 60
    assert counts["candidate_count"] == 59 and counts["dedupe_count"] == 1
    by_sha = {r["sha256"]: r for r in rows}
    related = [by_sha[r["expected_sha256"]] for r in pilot[:3]]
    assert len({r["lineage_group"] for r in related}) == 1
    assert related[0]["version_group"] != related[1]["version_group"]
    assert related[0]["package_group"] == related[1]["package_group"]
    conflicting = {**pilot[0], g.COUNT_FIELDS[0]: "999"}
    write_csv(pp, pilot + [conflicting])
    with pytest.raises(ValueError, match="衝突"):
        g.load_candidates(pp, cp)


def test_small_clusters_fill_to_fifty_and_keep_unique_packages():
    sizes = [1, 2, 2, 3] + [4] * 13
    labels = np.repeat(np.arange(17), sizes)
    x = np.arange(len(labels), dtype=float).reshape(-1, 1)
    centers = np.array([x[labels == c].mean(axis=0) for c in range(17)])
    rows = [{"package_name": f"p{i}", "tie_break": f"{i:03}"} for i in range(len(x))]
    selected = g.select_members(x, labels, centers, rows)
    assert len({p["index"] for p in selected}) == 50
    assert len({int(labels[p["index"]]) for p in selected}) == 17
    assert Counter(p["selection_role"] for p in selected) == {
        "representative": 17, "diverse": 16, "third": 14, "coverage_fill": 3}
    assert all(p["package_novel_at_selection"] for p in selected)


def test_repeat_and_permuted_input_same_selection_and_sensitivity(tmp_path):
    pp, cp, _, _ = make_pilot(tmp_path)
    rows, _ = g.load_candidates(pp, cp)
    first, metadata = g.build_selection(rows)
    again, second = g.build_selection(list(reversed(rows)))
    assert first == again
    assert metadata == second
    assert len({r["sha256"] for r in first}) == 50
    assert metadata["unique_selected_packages"] == 50
    assert set(metadata["sensitivity"]) == {"15", "17", "20"}
    assert metadata["sensitivity"]["17"]["overlap_with_k17"] == 50
    for k, summary in metadata["sensitivity"].items():
        assert summary["selected_count"] == 50
        assert summary["selected_cluster_count"] == int(k)
    assert len(metadata["candidate_registry"]) == 60
    assert not any("gold_label" in row or "observed_label" in row for row in first)


def test_freeze_hashes_no_overwrite_and_input_integrity(tmp_path):
    pp, cp, pilot, canonical = make_pilot(tmp_path, 300)
    for row in pilot[-3:]:
        row["parse_status"] = "failed"
    write_csv(pp, pilot)
    origin = {"canonical_csv": str(cp), "canonical_csv_sha256": g.sha256_file(cp)}
    pp.with_name("run_metadata.json").write_text(json.dumps(origin), encoding="utf-8")
    out = tmp_path / "frozen"
    metadata = g.freeze_membership(pp, out)
    csv_path = out / "golden_50_membership.csv"
    frozen = csv_path.read_bytes()
    actual = list(csv.DictReader(csv_path.open(encoding="utf-8-sig")))
    assert len(actual) == len({r["sha256"] for r in actual}) == 50
    assert metadata["source_sha256_verified_count"] == 297
    assert g.sha256_file(csv_path) == metadata["membership_csv_sha256"]
    assert g.fingerprint(sorted(r["sha256"] for r in actual)) == metadata["membership_sha256"]
    assert len({r["membership_freeze_timestamp"] for r in actual}) == 1
    assert metadata["produces_gold_labels"] is False
    with pytest.raises(FileExistsError):
        g.freeze_membership(pp, out)
    assert csv_path.read_bytes() == frozen
    # 已解析來源若被置換，拒絕凍結，不以另一 APK 補位。
    from pathlib import Path
    Path(canonical[0]["source_path"]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="source SHA-256"):
        g.freeze_membership(pp, tmp_path / "tampered")
    assert not (tmp_path / "tampered").exists()


def test_repository_annotation_template_carries_version_provenance_schema():
    annotation_path = REPO_ROOT / "dataset" / "authz_v2" / "golden_50_annotations.csv"
    with annotation_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames is not None
        assert "spec_version" in reader.fieldnames
        assert "guide_version" in reader.fieldnames
        rows = list(reader)

    assert len(rows) == 50
    assert all(row["row_kind"] == "apk_membership_placeholder" for row in rows)
    assert all(row["spec_version"] == "" and row["guide_version"] == "" for row in rows)
    review_log = REPO_ROOT / "dataset" / "authz_v2" / "gold_review_log.jsonl"
    review_log_bytes = review_log.read_bytes()
    if review_log_bytes:
        assert review_log_bytes.endswith(b"\n")
        events = [
            json.loads(line)
            for line in review_log_bytes.decode("utf-8").splitlines()
        ]
        event_ids = [event["review_event_id"] for event in events]
        assert len(event_ids) == len(set(event_ids))
        assert all(event["event_schema_version"] == "gold-review-event-v1" for event in events)
