"""Compare an archived evaluation population with the current Gold materialization."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence


def audit(current_summary: dict[str, Any], archived: dict[str, Any]) -> dict[str, Any]:
    old = archived["selected_fields_transcription"]
    old_classes = archived["pipeline_all_binary"]
    current_labels = current_summary["label_counts"]
    comparisons = {
        "binary_units": {
            "archived": int(old["gold_binary"]),
            "current": int(current_summary["binary_eval_unit_count"]),
        },
        "positive": {
            "archived": int(old_classes["positive"]),
            "current": int(current_labels.get("positive", 0)),
        },
        "negative": {
            "archived": int(old_classes["negative"]),
            "current": int(current_labels.get("negative", 0)),
        },
        "unknown": {
            "archived": int(old["excluded_gold_unknown"]),
            "current": int(current_summary["unknown_excluded_from_binary_eval"]),
        },
    }
    for values in comparisons.values():
        values["delta_current_minus_archived"] = values["current"] - values["archived"]
        values["matches"] = values["current"] == values["archived"]
    matches = all(values["matches"] for values in comparisons.values())
    raw_predictions_available = bool(archived.get("raw_per_unit_predictions_in_shared_package"))
    reproducible = matches and raw_predictions_available
    return {
        "schema_version": "gold-population-drift-audit-v1",
        "status": "compatible" if reproducible else "not_reproducible",
        "population_matches": matches,
        "raw_per_unit_predictions_available": raw_predictions_available,
        "comparisons": comparisons,
        "archived_source": {
            "title": archived["source_title"],
            "drive_file_id": archived["source_drive_file_id"],
            "artifact_sha256": archived["source_artifact_sha256"],
            "json_pointer": archived["selected_json_pointer"],
        },
        "current_source": {
            "authority": current_summary["authority"],
            "authority_sha256": current_summary["authority_sha256"],
            "materialized_csv_sha256": current_summary["output_csv_sha256"],
        },
        "required_before_re_evaluation": [
            "Freeze and name the intended Gold review-log revision.",
            "Export per-unit predictions with review_unit_id, model_id, seed, predicted_label, and score.",
            "Run evaluate_gold_predictions.py against the matching materialized Gold revision.",
            "Do not compare metrics across mismatched Gold populations as if they were the same test set.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--current-summary",
        type=Path,
        default=Path("dataset/authz_v2/golden_50_labels_summary.json"),
    )
    parser.add_argument(
        "--archived-eval",
        type=Path,
        default=Path("dataset/authz_v2/archived_model_eval_population_20261018.json"),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("dataset/authz_v2/gold_population_drift_audit_20261019.json"),
    )
    args = parser.parse_args(argv)
    current = json.loads(args.current_summary.read_text(encoding="utf-8"))
    archived = json.loads(args.archived_eval.read_text(encoding="utf-8"))
    result = audit(current, archived)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
