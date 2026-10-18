from pathlib import Path
import sys


API_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(API_ROOT))

from apps.api.research_progress import load_research_progress  # noqa: E402


def test_progress_is_derived_from_audited_manifest():
    progress = load_research_progress()
    assert progress["schema_version"] == "research-progress-v1"
    assert progress["summary"] == {
        "claim_count": 9,
        "population_count": 4,
        "generalization_claim_count": 0,
        "static_path_claim_count": 3,
    }
    assert {row["unit_count"] for row in progress["populations"]} == {67, 106, 1685, 2121}


def test_progress_keeps_evaluation_boundaries_visible():
    claims = load_research_progress()["claims"]
    oracle = next(row for row in claims if row["evaluation_design"] == "same_batch_fit")
    assert oracle["boundary"] == "descriptive_ceiling"
    assert oracle["claim_scope"] == "descriptive"
    linkage = [row for row in claims if row["metric_name"].startswith("linkage_")]
    assert all(row["boundary"] == "static_path_only" for row in linkage)
    models = [row for row in claims if row["metric_name"] in {"m2_mean_macro_f1", "m3_mean_macro_f1"}]
    assert all(row["boundary"] == "held_out_internal" for row in models)
    assert all(row["claim_scope"] != "generalization" for row in claims)
