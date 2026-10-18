"""Materialize the latest human-confirmed Golden-50 labels from the audit log.

The append-only review log remains the authority. This command only creates a
derived evaluation view; it must never be used as a training-data builder.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

LABELS = {"positive", "negative", "unknown"}
OUTPUT_FIELDS = [
    "review_unit_id",
    "membership_id",
    "apk_sha256",
    "row_kind",
    "gold_authz_label",
    "binary_eval_eligible",
    "reviewer_confidence",
    "R_predicate_result",
    "I_predicate_result",
    "S_predicate_result",
    "A_predicate_result",
    "primary_gold_unknown_reason",
    "gold_unknown_reason_codes",
    "review_event_id",
    "supersedes_review_event_id",
    "reviewed_at",
    "reviewer_id",
    "spec_version",
    "guide_version",
    "evidence_packet_reference",
    "evidence_packet_sha256",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_events(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at line {line_number}: {exc}") from exc
            events.append(event)
    return events


def select_latest_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_event_id: dict[str, dict[str, Any]] = {}
    unit_order: list[str] = []
    seen_units: set[str] = set()
    superseded_ids: set[str] = set()

    for event in events:
        event_id = str(event.get("review_event_id") or "")
        unit_id = str(event.get("review_unit_id") or "")
        label = str(event.get("gold_authz_label") or "")
        if not event_id or not unit_id:
            raise ValueError("every event requires review_event_id and review_unit_id")
        if event_id in by_event_id:
            raise ValueError(f"duplicate review_event_id: {event_id}")
        if label not in LABELS:
            raise ValueError(f"invalid gold_authz_label for {event_id}: {label}")
        by_event_id[event_id] = event
        if unit_id not in seen_units:
            seen_units.add(unit_id)
            unit_order.append(unit_id)
        supersedes = event.get("supersedes_review_event_id")
        if supersedes:
            superseded_ids.add(str(supersedes))

    for event in events:
        supersedes = event.get("supersedes_review_event_id")
        if not supersedes:
            continue
        previous = by_event_id.get(str(supersedes))
        if previous is None:
            raise ValueError(f"superseded event does not exist: {supersedes}")
        if previous["review_unit_id"] != event["review_unit_id"]:
            raise ValueError(f"supersession crosses review units: {supersedes}")

    leaves_by_unit: dict[str, list[dict[str, Any]]] = {}
    for event_id, event in by_event_id.items():
        if event_id not in superseded_ids:
            leaves_by_unit.setdefault(str(event["review_unit_id"]), []).append(event)
    for unit_id, leaves in leaves_by_unit.items():
        if len(leaves) != 1:
            raise ValueError(f"review unit must have exactly one latest event: {unit_id}")
    if set(leaves_by_unit) != seen_units:
        raise ValueError("one or more review units have no latest event")
    return [leaves_by_unit[unit_id][0] for unit_id in unit_order]


def materialized_row(event: dict[str, Any]) -> dict[str, Any]:
    label = str(event["gold_authz_label"])
    reason_codes = event.get("gold_unknown_reason_codes") or []
    return {
        "review_unit_id": event["review_unit_id"],
        "membership_id": event["membership_id"],
        "apk_sha256": event["sha256"],
        "row_kind": event["row_kind"],
        "gold_authz_label": label,
        "binary_eval_eligible": str(label in {"positive", "negative"}).lower(),
        "reviewer_confidence": event["reviewer_confidence"],
        "R_predicate_result": event["R_predicate_result"],
        "I_predicate_result": event["I_predicate_result"],
        "S_predicate_result": event["S_predicate_result"],
        "A_predicate_result": event["A_predicate_result"],
        "primary_gold_unknown_reason": event.get("primary_gold_unknown_reason") or "",
        "gold_unknown_reason_codes": "|".join(str(code) for code in reason_codes),
        "review_event_id": event["review_event_id"],
        "supersedes_review_event_id": event.get("supersedes_review_event_id") or "",
        "reviewed_at": event["reviewed_at"],
        "reviewer_id": event["reviewer_id"],
        "spec_version": event["spec_version"],
        "guide_version": event["guide_version"],
        "evidence_packet_reference": event["evidence_packet_reference"],
        "evidence_packet_sha256": event["evidence_packet_sha256"],
    }


def materialize(review_log: Path, output_csv: Path, summary_json: Path) -> dict[str, Any]:
    events = read_events(review_log)
    latest = select_latest_events(events)
    rows = [materialized_row(event) for event in latest]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    labels = Counter(row["gold_authz_label"] for row in rows)
    confidence = Counter(row["reviewer_confidence"] for row in rows)
    summary = {
        "schema_version": "gold-label-materialization-v1",
        "authority": str(review_log),
        "authority_sha256": sha256_file(review_log),
        "event_count": len(events),
        "latest_review_unit_count": len(rows),
        "superseded_event_count": len(events) - len(rows),
        "apk_count": len({row["apk_sha256"] for row in rows}),
        "label_counts": dict(sorted(labels.items())),
        "binary_eval_unit_count": labels["positive"] + labels["negative"],
        "unknown_excluded_from_binary_eval": labels["unknown"],
        "confidence_counts": dict(sorted(confidence.items())),
        "output_csv": str(output_csv),
        "output_csv_sha256": sha256_file(output_csv),
        "gold_role": "untouched_evaluation_only",
        "training_use_permitted": False,
    }
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--review-log",
        type=Path,
        default=Path("dataset/authz_v2/gold_review_log.jsonl"),
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("dataset/authz_v2/golden_50_labels_materialized.csv"),
    )
    parser.add_argument(
        "--summary-json",
        type=Path,
        default=Path("dataset/authz_v2/golden_50_labels_summary.json"),
    )
    args = parser.parse_args(argv)
    summary = materialize(args.review_log, args.output_csv, args.summary_json)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
