import csv
import hashlib
import json
from pathlib import Path

import pytest

from app.tools import golden_review_session as session


def _write_units(root: Path, count: int) -> tuple[Path, Path, list[dict[str, str]]]:
    packet_root = root / "packets-root"
    packet_root.mkdir()
    fields = [
        "membership_id",
        "apk_sha256",
        "package_name",
        "review_unit_id",
        "row_kind",
        "candidate_id",
        "path_id",
        "component_type",
        "manifest_component_name",
        "entry_method",
        "caller_method",
        "sensitive_sink",
        "evidence_packet_reference",
        "evidence_packet_sha256",
        "materialization_version",
        "spec_version",
        "guide_version",
    ]
    rows = []
    for index in range(count):
        packet_reference = f"packets/{index:02d}/packet.json"
        packet = packet_root / packet_reference
        packet.parent.mkdir(parents=True)
        packet.write_text(json.dumps({"index": index}), encoding="utf-8")
        rows.append(
            {
                "membership_id": "golden-50-v1:" + "a" * 64,
                "apk_sha256": "a" * 64,
                "package_name": "example",
                "review_unit_id": f"review-unit-v1:{index:064x}",
                "row_kind": "candidate",
                "candidate_id": f"candidate-v1:{index:064x}",
                "path_id": "",
                "component_type": "activity",
                "manifest_component_name": "o.灬",
                "entry_method": "onCreate",
                "caller_method": "run",
                "sensitive_sink": f"Sink:{index}",
                "evidence_packet_reference": packet_reference,
                "evidence_packet_sha256": session.sha256_file(packet),
                "materialization_version": "golden-50-review-packets-v1",
                "spec_version": "authz-label-spec-v0.2-meeting-approved",
                "guide_version": "authz-annotation-guide-v0.2-meeting-approved",
            }
        )
    units = root / "review_units.csv"
    with units.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return units, packet_root, rows


def _proposal(row: dict[str, str], *, label: str = "negative") -> dict:
    if label == "positive":
        results = {field: "confirmed" for field in session.PREDICATE_FIELDS}
        statuses = {field: "confirmed_present" for field in session.EVIDENCE_STATUS_FIELDS}
        reasons = {"primary_gold_unknown_reason": None, "gold_unknown_reason_codes": []}
    elif label == "negative":
        results = {
            "R_predicate_result": "refuted",
            "I_predicate_result": "unknown",
            "S_predicate_result": "unknown",
            "A_predicate_result": "unknown",
        }
        statuses = {
            "R_evidence_status": "confirmed_absent",
            "I_evidence_status": "not_reviewed_after_decisive_blocker",
            "S_evidence_status": "not_reviewed_after_decisive_blocker",
            "A_evidence_status": "not_reviewed_after_decisive_blocker",
        }
        reasons = {"primary_gold_unknown_reason": None, "gold_unknown_reason_codes": []}
    else:
        results = {field: "unknown" for field in session.PREDICATE_FIELDS}
        statuses = {field: "not_analyzed" for field in session.EVIDENCE_STATUS_FIELDS}
        reasons = {
            "primary_gold_unknown_reason": "gold_unknown_insufficient_evidence",
            "gold_unknown_reason_codes": ["gold_unknown_insufficient_evidence"],
        }
    return {
        "review_unit_id": row["review_unit_id"],
        **results,
        **statuses,
        **reasons,
        "reviewer_notes": "Manifest, source, and applicable limitations were checked; this rationale applies only to this review unit.",
        "evidence_references": [row["evidence_packet_reference"]],
        "unit_specific_evidence_references": [
            row["evidence_packet_reference"] + "#review-unit"
        ],
        "evidence_checklist": {
            "duplicate_manifest_declarations_checked": True,
            "activity_alias_checked": True,
            "source_review_status": "read",
            "source_references": ["sources/java/example/MainActivity.java#L1"],
            "platform_semantics_status": "verified_primary_source",
            "platform_semantics_references": ["https://developer.android.com/guide"],
        },
    }


def _write_proposals(path: Path, proposals: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in proposals),
        encoding="utf-8",
    )


def _append(
    tmp_path: Path,
    units: Path,
    packet_root: Path,
    review_log: Path,
    proposals: Path,
    *,
    label: str = "negative",
    expected_sha: str | None = None,
) -> list[dict]:
    return session.append_approved_group(
        review_log=review_log,
        review_units_csv=units,
        packet_root=packet_root,
        proposals_jsonl=proposals,
        human_label=label,
        human_confidence="high",
        reviewer_id="human-reviewer",
        assistant_id="claude-cli:test-session",
        expected_log_sha256=expected_sha or hashlib.sha256(review_log.read_bytes()).hexdigest(),
        experiment_dir=tmp_path / "docs",
    )


def test_append_uses_only_human_label_confidence_and_records_provenance(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 2)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    proposals = tmp_path / "proposals.jsonl"
    first = _proposal(rows[0])
    second = _proposal(rows[1])
    for item in (first, second):
        item.update(
            {
                "safe_group_id": "same-component-code",
                "shared_evidence_fingerprint": "f" * 64,
                "grouping_basis": "Same component and the same decisive reachability blocker.",
            }
        )
    _write_proposals(proposals, [first, second])

    appended = _append(tmp_path, units, packet_root, review_log, proposals)

    assert len(appended) == 2
    assert len({event["review_event_id"] for event in appended}) == 2
    assert [event["review_unit_id"] for event in appended] == [
        rows[0]["review_unit_id"],
        rows[1]["review_unit_id"],
    ]
    assert all(event["gold_authz_label"] == "negative" for event in appended)
    assert all(event["reviewer_confidence"] == "high" for event in appended)
    assert all(
        event["human_confirmed_fields"]
        == ["gold_authz_label", "reviewer_confidence"]
        for event in appended
    )
    assert all(event["assistant_id"] == "claude-cli:test-session" for event in appended)
    assert all(event["review_workflow_version"] == session.WORKFLOW_VERSION for event in appended)
    assert all(event["reviewer_notes"].isascii() for event in appended)
    assert "o.灬" == rows[0]["manifest_component_name"]
    assert review_log.read_bytes().endswith(b"\n")


def test_label_mismatch_rejects_without_changing_log(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 1)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    proposals = tmp_path / "proposals.jsonl"
    _write_proposals(proposals, [_proposal(rows[0], label="negative")])
    before = review_log.read_bytes()

    with pytest.raises(session.ReviewProtocolError, match="決策表不一致"):
        _append(
            tmp_path,
            units,
            packet_root,
            review_log,
            proposals,
            label="positive",
        )

    assert review_log.read_bytes() == before


def test_missing_mandatory_evidence_check_rejects(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 1)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    proposal = _proposal(rows[0])
    proposal["evidence_checklist"]["duplicate_manifest_declarations_checked"] = False
    proposals = tmp_path / "proposals.jsonl"
    _write_proposals(proposals, [proposal])

    with pytest.raises(session.ReviewProtocolError, match="duplicate Manifest"):
        _append(tmp_path, units, packet_root, review_log, proposals)

    assert review_log.read_bytes() == b""


def test_expected_sha_rejects_concurrent_change(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 1)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    proposal = tmp_path / "proposals.jsonl"
    _write_proposals(proposal, [_proposal(rows[0])])

    with pytest.raises(session.ReviewProtocolError, match="已變更"):
        _append(
            tmp_path,
            units,
            packet_root,
            review_log,
            proposal,
            expected_sha="0" * 64,
        )


def test_session_cap_rejects_crossing_twenty(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 21)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    for row in rows[:19]:
        proposal = tmp_path / "one.jsonl"
        _write_proposals(proposal, [_proposal(row)])
        _append(tmp_path, units, packet_root, review_log, proposal)
    group = [_proposal(rows[19]), _proposal(rows[20])]
    for item in group:
        item.update(
            {
                "safe_group_id": "over-boundary",
                "shared_evidence_fingerprint": "f" * 64,
                "grouping_basis": "same component",
            }
        )
    proposals = tmp_path / "two.jsonl"
    _write_proposals(proposals, group)
    before = review_log.read_bytes()

    with pytest.raises(session.ReviewProtocolError, match="只剩 1 筆"):
        _append(tmp_path, units, packet_root, review_log, proposals)

    assert review_log.read_bytes() == before


def test_close_session_requires_boundary_and_creates_complete_record(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 21)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    for row in rows[:19]:
        proposal = tmp_path / "one.jsonl"
        _write_proposals(proposal, [_proposal(row)])
        _append(tmp_path, units, packet_root, review_log, proposal)
    with pytest.raises(session.ReviewProtocolError, match="19/20"):
        session.close_session(
            review_log=review_log,
            review_units_csv=units,
            experiment_dir=tmp_path / "docs",
        )

    proposal = tmp_path / "twentieth.jsonl"
    _write_proposals(proposal, [_proposal(rows[19])])
    _append(tmp_path, units, packet_root, review_log, proposal)
    record = session.close_session(
        review_log=review_log,
        review_units_csv=units,
        experiment_dir=tmp_path / "docs",
    )

    assert record.name == "golden_review_experiment_log_1_20.md"
    text = record.read_text(encoding="utf-8")
    assert "第 1-20 筆" in text
    assert "人工輸入欄位" in text
    assert "`o.灬`" in text
    assert "SESSION" not in text
    assert "Claude CLI 必須在此停止" in text
    with pytest.raises(session.ReviewProtocolError, match="拒絕覆寫"):
        session.close_session(
            review_log=review_log,
            review_units_csv=units,
            experiment_dir=tmp_path / "docs",
        )


def test_jsonl_rejects_chinese_agent_prose_and_preserves_unicode_identity(tmp_path):
    units, packet_root, rows = _write_units(tmp_path, 1)
    review_log = tmp_path / "review.jsonl"
    review_log.write_bytes(b"")
    proposal = _proposal(rows[0])
    proposal["reviewer_notes"] = "這是 Claude 撰寫的中文 JSONL 敘述。"
    proposals = tmp_path / "proposals.jsonl"
    _write_proposals(proposals, [proposal])

    with pytest.raises(session.ReviewProtocolError, match="英文 ASCII"):
        _append(tmp_path, units, packet_root, review_log, proposals)
    assert review_log.read_bytes() == b""

    proposal["reviewer_notes"] = "English rationale for an obfuscated Unicode component."
    proposal["unit_specific_evidence_references"] = ["sources/smali/o/灬.smali"]
    _write_proposals(proposals, [proposal])
    _append(tmp_path, units, packet_root, review_log, proposals)

    raw = review_log.read_bytes()
    assert "o/灬.smali".encode("utf-8") in raw
    assert b"o/\\u706c.smali" not in raw
    parsed = json.loads(raw.decode("utf-8"))
    assert parsed["unit_specific_evidence_references"] == ["sources/smali/o/灬.smali"]
