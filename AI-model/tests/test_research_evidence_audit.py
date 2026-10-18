from __future__ import annotations

import csv
import hashlib
import json

import pytest

from app.tools import research_evidence_audit as audit


REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


FIELDS = [
    "claim_id", "population_id", "unit_count", "apk_count", "metric_name",
    "metric_value", "evaluation_design", "gold_role", "claim_scope",
    "artifact_path", "artifact_sha256", "json_pointer", "notes",
]


def write_claims(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def fixture(tmp_path):
    artifact = tmp_path / "linkage_eval.json"
    artifact.write_text(json.dumps({"layers": {"reachable": {"macro_f1": 0.785}}}), encoding="utf-8")
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    row = {
        "claim_id": "linkage-reachable-f1",
        "population_id": "reachable-gold-106",
        "unit_count": "106",
        "apk_count": "21",
        "metric_name": "linkage_macro_f1",
        "metric_value": "0.785",
        "evaluation_design": "descriptive",
        "gold_role": "tuning_or_rule_design",
        "claim_scope": "static_possible_path",
        "artifact_path": artifact.name,
        "artifact_sha256": sha,
        "json_pointer": "/layers/reachable/macro_f1",
        "notes": "linked 不代表資料流或 exploit",
    }
    return artifact, row


def test_verifies_source_hash_pointer_and_research_boundary(tmp_path):
    _, row = fixture(tmp_path)
    claims = tmp_path / "claims.csv"
    write_claims(claims, [row])
    report = audit.audit_claims(claims, tmp_path)
    assert report["summary"] == {
        "claim_count": 1,
        "verified_count": 1,
        "error_count": 0,
        "warning_count": 0,
        "population_count": 1,
    }
    assert report["claims"][0]["source_value"] == 0.785


def test_rejects_same_batch_fit_as_generalization(tmp_path):
    _, row = fixture(tmp_path)
    row.update({
        "claim_id": "coarse-cell-oracle",
        "metric_name": "macro_f1",
        "evaluation_design": "same_batch_fit",
        "gold_role": "tuning_or_rule_design",
        "claim_scope": "generalization",
    })
    claims = tmp_path / "claims.csv"
    write_claims(claims, [row])
    report = audit.audit_claims(claims, tmp_path)
    messages = {error["message"] for error in report["errors"]}
    assert "泛化主張必須使用 independent_holdout" in messages
    assert "泛化主張的 Gold 必須只用於未接觸的最終評估" in messages
    assert "同批擬合或訓練結果只能作描述或內部驗證" in messages


def test_rejects_mixed_population_denominators_and_tampering(tmp_path):
    artifact, first = fixture(tmp_path)
    second = {**first, "claim_id": "second", "unit_count": "67", "apk_count": "19"}
    claims = tmp_path / "claims.csv"
    write_claims(claims, [first, second])
    artifact.write_text("{}", encoding="utf-8")
    report = audit.audit_claims(claims, tmp_path)
    messages = [error["message"] for error in report["errors"]]
    assert "同一 population_id 的 unit_count/apk_count 不一致" in messages
    assert messages.count("artifact SHA-256 與宣告值不符") == 2


def test_blocks_path_traversal(tmp_path):
    _, row = fixture(tmp_path)
    row["artifact_path"] = "../outside.json"
    claims = tmp_path / "claims.csv"
    write_claims(claims, [row])
    report = audit.audit_claims(claims, tmp_path)
    assert any("不得離開" in error["message"] for error in report["errors"])


def test_missing_schema_fields_fail_closed(tmp_path):
    claims = tmp_path / "claims.csv"
    claims.write_text("claim_id,population_id\na,b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="缺少必要欄位"):
        audit.audit_claims(claims, tmp_path)


def test_20261019_manifest_preserves_reported_populations_and_boundaries():
    manifest = REPO_ROOT / "dataset" / "authz_v2" / "research_claims_20261019.csv"
    with manifest.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 9
    assert set(audit.REQUIRED_FIELDS) <= set(rows[0])
    assert {row["population_id"] for row in rows} == {
        "training-pool-v1-1685",
        "reachable-gold-106",
        "candidate-units-2121",
        "reachable-gold-excluding-design-apks-67",
    }
    assert not any(row["claim_scope"] == "generalization" for row in rows)
    same_batch = next(row for row in rows if row["evaluation_design"] == "same_batch_fit")
    assert same_batch["claim_scope"] == "descriptive"
    linkage = [row for row in rows if row["metric_name"].startswith("linkage_")]
    assert linkage and all(row["claim_scope"] == "static_possible_path" for row in linkage)
    assert all(len(row["artifact_sha256"]) == 64 for row in rows)
