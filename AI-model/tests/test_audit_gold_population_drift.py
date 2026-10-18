from app.tools.audit_gold_population_drift import audit


def _current(binary=361, positive=58, negative=303, unknown=24):
    return {
        "binary_eval_unit_count": binary,
        "unknown_excluded_from_binary_eval": unknown,
        "label_counts": {"positive": positive, "negative": negative, "unknown": unknown},
        "authority": "review.jsonl",
        "authority_sha256": "a" * 64,
        "output_csv_sha256": "b" * 64,
    }


def _archived(raw=False):
    return {
        "source_title": "model_eval_gold.json",
        "source_drive_file_id": "id",
        "source_artifact_sha256": "c" * 64,
        "selected_json_pointer": "/population_accounting",
        "selected_fields_transcription": {"gold_binary": 348, "excluded_gold_unknown": 36},
        "pipeline_all_binary": {"positive": 83, "negative": 265},
        "raw_per_unit_predictions_in_shared_package": raw,
    }


def test_detects_population_drift_and_missing_predictions():
    result = audit(_current(), _archived())
    assert result["status"] == "not_reproducible"
    assert result["population_matches"] is False
    assert result["comparisons"]["positive"]["delta_current_minus_archived"] == -25


def test_matching_counts_still_require_raw_predictions():
    result = audit(_current(348, 83, 265, 36), _archived(raw=False))
    assert result["population_matches"] is True
    assert result["status"] == "not_reproducible"


def test_matching_counts_and_raw_predictions_are_compatible():
    result = audit(_current(348, 83, 265, 36), _archived(raw=True))
    assert result["status"] == "compatible"
