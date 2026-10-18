"""Evaluate frozen model predictions against materialized Golden-50 labels.

This is an evaluation-only join. It never fits a model, selects a threshold, or
turns human ``unknown`` into a negative label.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("predictions"), list):
        return payload["predictions"]
    raise ValueError("prediction JSON must be a list or contain a predictions list")


def _binary(value: Any, field: str) -> int:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "positive"}:
        return 1
    if normalized in {"0", "false", "negative"}:
        return 0
    raise ValueError(f"{field} must be binary, got {value!r}")


def evaluate(
    gold_csv: Path,
    predictions_path: Path,
    *,
    allow_partial: bool = False,
) -> dict[str, Any]:
    gold_rows = read_rows(gold_csv)
    gold_all = {str(row["review_unit_id"]): row for row in gold_rows}
    gold_binary = {
        unit_id: row
        for unit_id, row in gold_all.items()
        if str(row["gold_authz_label"]) in {"positive", "negative"}
    }
    unknown_count = len(gold_all) - len(gold_binary)

    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in read_rows(predictions_path):
        unit_id = str(row.get("review_unit_id") or "")
        if not unit_id:
            raise ValueError("every prediction requires review_unit_id")
        run = (str(row.get("model_id") or "default"), str(row.get("seed") or "default"))
        if unit_id in grouped[run]:
            raise ValueError(f"duplicate prediction for run={run}, review_unit_id={unit_id}")
        grouped[run][unit_id] = row
    if not grouped:
        raise ValueError("prediction file is empty")

    results = []
    for (model_id, seed), predictions in sorted(grouped.items()):
        extra_ids = sorted(set(predictions) - set(gold_all))
        covered_ids = sorted(set(predictions) & set(gold_binary))
        missing_ids = sorted(set(gold_binary) - set(predictions))
        if extra_ids:
            raise ValueError(f"predictions contain {len(extra_ids)} unknown review_unit_id values")
        if missing_ids and not allow_partial:
            raise ValueError(
                f"run {model_id}/{seed} misses {len(missing_ids)} binary Gold units; "
                "use --allow-partial only for an explicitly scoped analysis"
            )
        if not covered_ids:
            raise ValueError(f"run {model_id}/{seed} covers no binary Gold units")

        y_true = [_binary(gold_binary[unit]["gold_authz_label"], "gold_authz_label") for unit in covered_ids]
        y_pred = [_binary(predictions[unit]["predicted_label"], "predicted_label") for unit in covered_ids]
        matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = (int(value) for value in matrix.ravel())
        scores: list[float] | None = None
        if all(str(predictions[unit].get("score", "")).strip() for unit in covered_ids):
            scores = [float(predictions[unit]["score"]) for unit in covered_ids]

        has_both_gold_classes = len(set(y_true)) == 2
        metrics: dict[str, Any] = {
            "accuracy": accuracy_score(y_true, y_pred),
            "balanced_accuracy": balanced_accuracy_score(y_true, y_pred)
            if has_both_gold_classes
            else None,
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0),
            "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
            "mcc": matthews_corrcoef(y_true, y_pred) if has_both_gold_classes else None,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        }
        if scores is not None and has_both_gold_classes:
            metrics["roc_auc"] = roc_auc_score(y_true, scores)

        results.append(
            {
                "model_id": model_id,
                "seed": seed,
                "coverage": {
                    "evaluated_units": len(covered_ids),
                    "total_binary_gold_units": len(gold_binary),
                    "coverage_rate": len(covered_ids) / len(gold_binary),
                    "covered_apks": len({gold_binary[unit]["apk_sha256"] for unit in covered_ids}),
                    "missing_binary_gold_units": len(missing_ids),
                    "human_unknown_excluded": unknown_count,
                },
                "class_counts": {
                    "negative": y_true.count(0),
                    "positive": y_true.count(1),
                },
                "both_gold_classes_present": has_both_gold_classes,
                "metrics": metrics,
            }
        )

    return {
        "schema_version": "gold-prediction-evaluation-v1",
        "evaluation_design": "independent_holdout",
        "gold_role": "untouched_evaluation_only",
        "threshold_selection_on_gold_permitted": False,
        "gold_csv": str(gold_csv),
        "gold_csv_sha256": sha256_file(gold_csv),
        "predictions": str(predictions_path),
        "predictions_sha256": sha256_file(predictions_path),
        "allow_partial": allow_partial,
        "runs": results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument(
        "--gold",
        type=Path,
        default=Path("dataset/authz_v2/golden_50_labels_materialized.csv"),
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args(argv)
    payload = evaluate(args.gold, args.predictions, allow_partial=args.allow_partial)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
