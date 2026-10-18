import csv

import pytest

from app.tools.evaluate_gold_predictions import evaluate


def _write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _gold_rows():
    return [
        {"review_unit_id": "u1", "apk_sha256": "a", "gold_authz_label": "positive"},
        {"review_unit_id": "u2", "apk_sha256": "a", "gold_authz_label": "negative"},
        {"review_unit_id": "u3", "apk_sha256": "b", "gold_authz_label": "unknown"},
    ]


def test_unknown_is_excluded_and_metrics_are_exact(tmp_path):
    gold = tmp_path / "gold.csv"
    pred = tmp_path / "pred.csv"
    _write_csv(gold, _gold_rows())
    _write_csv(
        pred,
        [
            {"review_unit_id": "u1", "predicted_label": "1", "score": "0.9"},
            {"review_unit_id": "u2", "predicted_label": "0", "score": "0.1"},
        ],
    )
    result = evaluate(gold, pred)
    run = result["runs"][0]
    assert run["coverage"]["evaluated_units"] == 2
    assert run["coverage"]["human_unknown_excluded"] == 1
    assert run["metrics"]["macro_f1"] == 1.0
    assert run["metrics"]["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}


def test_missing_binary_gold_is_rejected_by_default(tmp_path):
    gold = tmp_path / "gold.csv"
    pred = tmp_path / "pred.csv"
    _write_csv(gold, _gold_rows())
    _write_csv(pred, [{"review_unit_id": "u1", "predicted_label": "1"}])
    with pytest.raises(ValueError, match="misses 1"):
        evaluate(gold, pred)


def test_partial_scope_requires_explicit_opt_in(tmp_path):
    gold = tmp_path / "gold.csv"
    pred = tmp_path / "pred.csv"
    _write_csv(gold, _gold_rows())
    _write_csv(pred, [{"review_unit_id": "u1", "predicted_label": "1"}])
    result = evaluate(gold, pred, allow_partial=True)
    assert result["allow_partial"] is True
    assert result["runs"][0]["coverage"]["coverage_rate"] == 0.5


def test_unknown_prediction_identity_is_rejected(tmp_path):
    gold = tmp_path / "gold.csv"
    pred = tmp_path / "pred.csv"
    _write_csv(gold, _gold_rows())
    _write_csv(pred, [{"review_unit_id": "not-gold", "predicted_label": "1"}])
    with pytest.raises(ValueError, match="unknown review_unit_id"):
        evaluate(gold, pred, allow_partial=True)
