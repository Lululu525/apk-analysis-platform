import csv
import json

import pytest

from app.tools.materialize_gold_labels import materialize, select_latest_events


def _event(event_id, unit_id, label, supersedes=None):
    return {
        "review_event_id": event_id,
        "review_unit_id": unit_id,
        "membership_id": f"membership:{unit_id}",
        "sha256": unit_id * 64,
        "row_kind": "candidate",
        "gold_authz_label": label,
        "reviewer_confidence": "high",
        "R_predicate_result": "confirmed",
        "I_predicate_result": "confirmed",
        "S_predicate_result": "confirmed",
        "A_predicate_result": "confirmed",
        "gold_unknown_reason_codes": [],
        "reviewed_at": "2026-10-19T00:00:00+08:00",
        "reviewer_id": "reviewer",
        "spec_version": "spec-v1",
        "guide_version": "guide-v1",
        "evidence_packet_reference": "packet.json",
        "evidence_packet_sha256": "a" * 64,
        "supersedes_review_event_id": supersedes,
    }


def test_revision_replaces_prior_event():
    latest = select_latest_events(
        [_event("e1", "a", "negative"), _event("e2", "a", "unknown", "e1")]
    )
    assert [event["review_event_id"] for event in latest] == ["e2"]


def test_cross_unit_supersession_is_rejected():
    with pytest.raises(ValueError, match="crosses review units"):
        select_latest_events(
            [_event("e1", "a", "negative"), _event("e2", "b", "positive", "e1")]
        )


def test_materialization_marks_unknown_outside_binary_eval(tmp_path):
    log = tmp_path / "review.jsonl"
    events = [_event("e1", "a", "positive"), _event("e2", "b", "unknown")]
    log.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    output = tmp_path / "labels.csv"
    summary_path = tmp_path / "summary.json"

    summary = materialize(log, output, summary_path)
    with output.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert [row["binary_eval_eligible"] for row in rows] == ["true", "false"]
    assert summary["binary_eval_unit_count"] == 1
    assert summary["unknown_excluded_from_binary_eval"] == 1
    assert summary["training_use_permitted"] is False
