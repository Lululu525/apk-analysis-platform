"""Golden review 的 AI-assisted / human-confirmed session guard。

Claude CLI 負責讀取盲化 evidence、提出 R/I/S/A 與可稽核理由；指定人工
reviewer 只輸入最終 label 與 confidence。本模組是 gold review log 的唯一
允許寫入入口，負責驗證決策表、packet identity、單一 writer、pure-suffix
append，以及每 20 個新 unique review units 的 session 邊界。已審查 unit 的
修訂走獨立的 `append-revision`（supersession event），不混入日常 append。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


EVENT_SCHEMA_VERSION = "gold-review-event-v1"
WORKFLOW_VERSION = "golden-review-session-protocol-v1.1"
REVIEW_GUIDE_VERSION = "authz-annotation-guide-v0.3-ai-assisted-review"
SESSION_SIZE = 20
TAIPEI_TIMEZONE = timezone(timedelta(hours=8), name="Asia/Taipei")

DEFAULT_REVIEW_UNITS = Path(
    "output/framework_poc/golden_50_v1/reviewer_packets_v1/review_units.csv"
)
DEFAULT_PACKET_ROOT = Path(
    "output/framework_poc/golden_50_v1/reviewer_packets_v1"
)
DEFAULT_REVIEW_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_EXPERIMENT_DIR = Path("docs")

PREDICATE_FIELDS = tuple(f"{name}_predicate_result" for name in "RISA")
EVIDENCE_STATUS_FIELDS = tuple(f"{name}_evidence_status" for name in "RISA")
PREDICATE_VALUES = {"confirmed", "refuted", "unknown"}
EVIDENCE_STATUS_VALUES = {
    "confirmed_present",
    "confirmed_absent",
    "observed_unresolved",
    "not_observed",
    "not_analyzed",
    "analysis_failed",
    "not_applicable",
    "not_reviewed_after_decisive_blocker",
    "not_analyzed_due_to_upstream_unknown",
}
LABEL_VALUES = {"positive", "negative", "unknown"}
CONFIDENCE_VALUES = {"low", "medium", "high"}
SOURCE_REVIEW_VALUES = {"read", "unavailable"}
PLATFORM_SEMANTICS_VALUES = {"verified_primary_source", "not_needed"}


class ReviewProtocolError(ValueError):
    """輸入或目前狀態違反 Golden review session protocol。"""


def _require_ascii_prose(value: Any, field: str) -> str:
    """JSONL 的 agent-authored prose 固定使用英文 ASCII。"""
    if not isinstance(value, str) or not value.strip():
        raise ReviewProtocolError(f"{field} 必須是非空英文文字。")
    if not value.isascii():
        raise ReviewProtocolError(
            f"{field} 必須使用英文 ASCII；component/code/path 的非 ASCII identity "
            "應放在專用 evidence/identity 欄位。"
        )
    return value


def taipei_now() -> str:
    return datetime.now(TAIPEI_TIMEZONE).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.stat().st_size == 0:
        return []
    records: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    if "\ufffd" in text:
        raise ReviewProtocolError(f"{path} 含 Unicode replacement character U+FFFD。")
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ReviewProtocolError(f"{path}:{line_number} 含空白 JSONL 列。")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReviewProtocolError(
                f"{path}:{line_number} 不是合法 JSON：{exc.msg}"
            ) from exc
        if not isinstance(value, dict):
            raise ReviewProtocolError(f"{path}:{line_number} 必須是 JSON object。")
        records.append(value)
    return records


def _load_review_units(path: Path) -> tuple[list[dict[str, str]], dict[str, dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    by_id: dict[str, dict[str, str]] = {}
    for row in rows:
        if any("\ufffd" in str(value) for value in row.values()):
            raise ReviewProtocolError("review_units.csv 含 Unicode replacement character U+FFFD。")
        unit_id = (row.get("review_unit_id") or "").strip()
        if not unit_id:
            raise ReviewProtocolError("review_units.csv 含空白 review_unit_id。")
        if unit_id in by_id:
            raise ReviewProtocolError(f"review_units.csv 含重複 ID：{unit_id}")
        by_id[unit_id] = row
    return rows, by_id


def _ordered_unique_unit_ids(events: Sequence[Mapping[str, Any]]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    event_ids: set[str] = set()
    for index, event in enumerate(events, 1):
        event_id = str(event.get("review_event_id") or "")
        unit_id = str(event.get("review_unit_id") or "")
        if not event_id or event_id in event_ids:
            raise ReviewProtocolError(f"review log 第 {index} 列的 event ID 空白或重複。")
        if not unit_id:
            raise ReviewProtocolError(f"review log 第 {index} 列缺 review_unit_id。")
        event_ids.add(event_id)
        if unit_id not in seen:
            seen.add(unit_id)
            ordered.append(unit_id)
    return ordered


def session_window(unique_count: int, total_units: int) -> dict[str, int | bool]:
    if unique_count < 0 or total_units < unique_count:
        raise ReviewProtocolError("unique_count/total_units 無效。")
    if unique_count == total_units:
        completed_in_window = unique_count % SESSION_SIZE or (
            SESSION_SIZE if unique_count else 0
        )
        start = unique_count - completed_in_window + 1 if unique_count else 1
        return {
            "start": start,
            "end": unique_count,
            "completed": completed_in_window,
            "remaining": 0,
            "dataset_complete": True,
            "boundary_reached": True,
        }

    completed_in_window = unique_count % SESSION_SIZE
    start = unique_count - completed_in_window + 1
    end = min(start + SESSION_SIZE - 1, total_units)
    return {
        "start": start,
        "end": end,
        "completed": completed_in_window,
        "remaining": end - unique_count,
        "dataset_complete": False,
        "boundary_reached": completed_in_window == 0 and unique_count > 0,
    }


def derive_label(proposal: Mapping[str, Any]) -> str:
    results = [str(proposal.get(field) or "") for field in PREDICATE_FIELDS]
    if any(value not in PREDICATE_VALUES for value in results):
        raise ReviewProtocolError("R/I/S/A predicate result 僅可為 confirmed/refuted/unknown。")
    if all(value == "confirmed" for value in results):
        return "positive"
    if "refuted" in results:
        return "negative"
    return "unknown"


def _require_string_list(value: Any, field: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ReviewProtocolError(f"{field} 必須是非空字串組成的陣列。")
    if nonempty and not value:
        raise ReviewProtocolError(f"{field} 不得為空。")
    return value


def _safe_packet_path(packet_root: Path, reference: str) -> Path:
    root = packet_root.resolve()
    candidate = (root / reference).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ReviewProtocolError(f"packet reference 超出 reviewer packet root：{reference}") from exc
    return candidate


def validate_proposal(
    proposal: Mapping[str, Any],
    unit: Mapping[str, str],
    *,
    packet_root: Path,
) -> str:
    unit_id = str(proposal.get("review_unit_id") or "")
    if unit_id != unit.get("review_unit_id"):
        raise ReviewProtocolError(f"proposal/unit identity 不一致：{unit_id}")

    for field in PREDICATE_FIELDS:
        if proposal.get(field) not in PREDICATE_VALUES:
            raise ReviewProtocolError(f"{unit_id} 的 {field} 無效。")
    for field in EVIDENCE_STATUS_FIELDS:
        if proposal.get(field) not in EVIDENCE_STATUS_VALUES:
            raise ReviewProtocolError(f"{unit_id} 的 {field} 無效。")

    evidence_references = _require_string_list(
        proposal.get("evidence_references"), "evidence_references", nonempty=True
    )
    _require_string_list(
        proposal.get("unit_specific_evidence_references"),
        "unit_specific_evidence_references",
        nonempty=True,
    )
    _require_ascii_prose(proposal.get("reviewer_notes"), "reviewer_notes")

    checklist = proposal.get("evidence_checklist")
    if not isinstance(checklist, dict):
        raise ReviewProtocolError(f"{unit_id} 缺 evidence_checklist。")
    if checklist.get("duplicate_manifest_declarations_checked") is not True:
        raise ReviewProtocolError(f"{unit_id} 尚未檢查 duplicate Manifest declaration。")
    if checklist.get("activity_alias_checked") is not True:
        raise ReviewProtocolError(f"{unit_id} 尚未檢查 activity-alias。")
    source_status = checklist.get("source_review_status")
    if source_status not in SOURCE_REVIEW_VALUES:
        raise ReviewProtocolError(f"{unit_id} 的 source_review_status 無效。")
    source_refs = _require_string_list(
        checklist.get("source_references"), "source_references"
    )
    if source_status == "read" and not source_refs:
        raise ReviewProtocolError(f"{unit_id} 宣稱已讀 source，但沒有 source reference。")
    platform_status = checklist.get("platform_semantics_status")
    if platform_status not in PLATFORM_SEMANTICS_VALUES:
        raise ReviewProtocolError(f"{unit_id} 的 platform_semantics_status 無效。")
    platform_refs = _require_string_list(
        checklist.get("platform_semantics_references"),
        "platform_semantics_references",
    )
    if platform_status == "verified_primary_source" and not platform_refs:
        raise ReviewProtocolError(f"{unit_id} 宣稱已查平台語意，但沒有一手來源。")

    packet_reference = str(unit.get("evidence_packet_reference") or "")
    packet_path = _safe_packet_path(packet_root, packet_reference)
    if not packet_path.is_file():
        raise ReviewProtocolError(f"找不到 evidence packet：{packet_path}")
    actual_packet_sha = sha256_file(packet_path)
    expected_packet_sha = str(unit.get("evidence_packet_sha256") or "")
    if actual_packet_sha != expected_packet_sha:
        raise ReviewProtocolError(
            f"{unit_id} packet SHA-256 不符：expected={expected_packet_sha}, "
            f"actual={actual_packet_sha}"
        )
    if packet_reference not in evidence_references:
        raise ReviewProtocolError(f"{unit_id} 的 evidence_references 未引用自己的 packet。")
    if "\ufffd" in packet_path.read_text(encoding="utf-8"):
        raise ReviewProtocolError(f"{unit_id} 的 packet 含 Unicode replacement character U+FFFD。")

    label = derive_label(proposal)
    reason_codes = _require_string_list(
        proposal.get("gold_unknown_reason_codes"), "gold_unknown_reason_codes"
    )
    primary_reason = proposal.get("primary_gold_unknown_reason")
    if label == "unknown":
        if not reason_codes or not isinstance(primary_reason, str) or not primary_reason:
            raise ReviewProtocolError(f"{unit_id} 的 unknown 必須有 primary/reason codes。")
        if primary_reason not in reason_codes:
            raise ReviewProtocolError(f"{unit_id} 的 primary unknown reason 不在 reason codes。")
    elif reason_codes or primary_reason is not None:
        raise ReviewProtocolError(f"{unit_id} 非 unknown，不得填 unknown reason。")
    for reason in reason_codes:
        _require_ascii_prose(reason, "gold_unknown_reason_codes")
    if primary_reason is not None:
        _require_ascii_prose(primary_reason, "primary_gold_unknown_reason")
    if proposal.get("grouping_basis") is not None:
        _require_ascii_prose(proposal.get("grouping_basis"), "grouping_basis")
    return label


def _validate_group(proposals: Sequence[Mapping[str, Any]], units: Mapping[str, Mapping[str, str]]) -> None:
    if not proposals:
        raise ReviewProtocolError("proposal group 不得為空。")
    ids = [str(proposal.get("review_unit_id") or "") for proposal in proposals]
    if len(set(ids)) != len(ids):
        raise ReviewProtocolError("同一 proposal group 含重複 review_unit_id。")
    if len(proposals) == 1:
        return
    group_ids = {str(proposal.get("safe_group_id") or "") for proposal in proposals}
    fingerprints = {
        str(proposal.get("shared_evidence_fingerprint") or "") for proposal in proposals
    }
    components = {
        (
            units[unit_id].get("apk_sha256"),
            units[unit_id].get("component_type"),
            units[unit_id].get("manifest_component_name"),
        )
        for unit_id in ids
    }
    if "" in group_ids or len(group_ids) != 1:
        raise ReviewProtocolError("多筆核准必須有相同且非空的 safe_group_id。")
    if "" in fingerprints or len(fingerprints) != 1:
        raise ReviewProtocolError("多筆核准必須有相同的 shared_evidence_fingerprint。")
    if len(components) != 1:
        raise ReviewProtocolError("safe_grouping 只允許同 APK、component type 與 component identity。")
    if any(not proposal.get("grouping_basis") for proposal in proposals):
        raise ReviewProtocolError("safe_grouping 每筆都必須說明 grouping_basis。")
    for proposal in proposals:
        _require_ascii_prose(proposal.get("grouping_basis"), "grouping_basis")


def _build_event(
    proposal: Mapping[str, Any],
    unit: Mapping[str, str],
    *,
    reviewer_id: str,
    human_label: str,
    human_confidence: str,
    assistant_id: str,
    proposal_sha256: str,
    reviewed_at: str,
    supersedes_review_event_id: str | None = None,
    change_reason: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "review_event_id": str(uuid.uuid4()),
        "membership_id": unit["membership_id"],
        "sha256": unit["apk_sha256"],
        "review_unit_id": unit["review_unit_id"],
        "row_kind": unit["row_kind"],
        "evidence_packet_reference": unit["evidence_packet_reference"],
        "evidence_packet_sha256": unit["evidence_packet_sha256"],
        "materialization_version": unit["materialization_version"],
        "spec_version": unit["spec_version"],
        "guide_version": REVIEW_GUIDE_VERSION,
        "packet_guide_version": unit["guide_version"],
        "review_workflow_version": WORKFLOW_VERSION,
        "assistant_id": assistant_id,
        "assistant_proposal_sha256": proposal_sha256,
        "human_confirmed_fields": ["gold_authz_label", "reviewer_confidence"],
        "assistant_proposed_fields": [
            *PREDICATE_FIELDS,
            *EVIDENCE_STATUS_FIELDS,
            "primary_gold_unknown_reason",
            "gold_unknown_reason_codes",
            "reviewer_notes",
        ],
        "reviewer_id": reviewer_id,
        **{field: proposal[field] for field in PREDICATE_FIELDS},
        **{field: proposal[field] for field in EVIDENCE_STATUS_FIELDS},
        "gold_authz_label": human_label,
        "primary_gold_unknown_reason": proposal.get("primary_gold_unknown_reason"),
        "gold_unknown_reason_codes": proposal.get("gold_unknown_reason_codes", []),
        "reviewer_confidence": human_confidence,
        "reviewer_notes": str(proposal["reviewer_notes"]),
        "reviewed_at": reviewed_at,
        "evidence_checklist": proposal["evidence_checklist"],
        "evidence_references": proposal["evidence_references"],
        "unit_specific_evidence_references": proposal[
            "unit_specific_evidence_references"
        ],
        "safe_group_id": proposal.get("safe_group_id"),
        "grouping_basis": proposal.get("grouping_basis"),
        "shared_evidence_fingerprint": proposal.get("shared_evidence_fingerprint"),
        "supersedes_review_event_id": supersedes_review_event_id,
        "change_reason": change_reason,
        "new_evidence_packet_sha256": None,
    }
    return event


def _read_log_for_append(review_log: Path, expected_log_sha256: str) -> bytes:
    """核對人工核准時看到的 log SHA，回傳 append 前的原始 bytes。"""
    old_bytes = review_log.read_bytes() if review_log.is_file() else b""
    actual_log_sha = sha256_bytes(old_bytes)
    if actual_log_sha != expected_log_sha256.lower():
        raise ReviewProtocolError(
            "review log 在人工核准後已變更，拒絕 append："
            f"expected={expected_log_sha256.lower()}, actual={actual_log_sha}"
        )
    if old_bytes and not old_bytes.endswith(b"\n"):
        raise ReviewProtocolError("review log 缺結尾換行，拒絕產生黏行。")
    return old_bytes


def _locked_pure_suffix_append(
    review_log: Path, old_bytes: bytes, events: Sequence[Mapping[str, Any]], created_at: str
) -> None:
    """以 exclusive lock 寫入，並驗證結果恰為舊 bytes 加上新 events。"""
    payload = b"".join(
        (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        for event in events
    )
    lock_path = review_log.with_name(review_log.name + ".lock")
    review_log.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = None
    try:
        try:
            lock_handle = lock_path.open("x", encoding="utf-8")
        except FileExistsError as exc:
            raise ReviewProtocolError(
                f"偵測到另一個 writer 或未清理 lock：{lock_path}"
            ) from exc
        lock_handle.write(
            json.dumps(
                {
                    "workflow_version": WORKFLOW_VERSION,
                    "pid": os.getpid(),
                    "created_at": created_at,
                    "expected_log_sha256": sha256_bytes(old_bytes),
                },
                ensure_ascii=False,
            )
        )
        lock_handle.flush()
        os.fsync(lock_handle.fileno())

        if review_log.is_file() and review_log.read_bytes() != old_bytes:
            raise ReviewProtocolError("取得 lock 後 review log 已變更，拒絕 append。")
        with review_log.open("ab") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        actual_after = review_log.read_bytes()
        if actual_after != old_bytes + payload:
            raise ReviewProtocolError("append 後不是舊 bytes 的 pure suffix；立即停止。")
    finally:
        if lock_handle is not None:
            lock_handle.close()
            lock_path.unlink(missing_ok=True)


def experiment_log_path(directory: Path, start: int, end: int) -> Path:
    return directory / f"golden_review_experiment_log_{start}_{end}.md"


def append_approved_group(
    *,
    review_log: Path,
    review_units_csv: Path,
    packet_root: Path,
    proposals_jsonl: Path,
    human_label: str,
    human_confidence: str,
    reviewer_id: str,
    assistant_id: str,
    expected_log_sha256: str,
    experiment_dir: Path = DEFAULT_EXPERIMENT_DIR,
) -> list[dict[str, Any]]:
    """驗證並以 pure suffix 一次 append 一個人工核准 group。"""
    if human_label not in LABEL_VALUES:
        raise ReviewProtocolError("人工 label 僅可為 positive/negative/unknown。")
    if human_confidence not in CONFIDENCE_VALUES:
        raise ReviewProtocolError("人工 confidence 僅可為 low/medium/high。")
    _require_ascii_prose(reviewer_id, "reviewer_id")
    _require_ascii_prose(assistant_id, "assistant_id")

    old_bytes = _read_log_for_append(review_log, expected_log_sha256)

    events = _read_jsonl(review_log)
    ordered_reviewed = _ordered_unique_unit_ids(events)
    rows, units = _load_review_units(review_units_csv)
    unknown_logged_units = set(ordered_reviewed) - set(units)
    if unknown_logged_units:
        raise ReviewProtocolError(
            "review log 含不在 reviewer packet collection 的 unit："
            + ", ".join(sorted(unknown_logged_units))
        )

    unique_count = len(ordered_reviewed)
    total_units = len(rows)
    if unique_count and unique_count % SESSION_SIZE == 0 and unique_count < total_units:
        previous_start = unique_count - SESSION_SIZE + 1
        previous_log = experiment_log_path(experiment_dir, previous_start, unique_count)
        if not previous_log.is_file():
            raise ReviewProtocolError(
                f"前一個 session 尚未產生實驗紀錄：{previous_log}；必須先 close-session。"
            )

    proposals = _read_jsonl(proposals_jsonl)
    proposal_bytes = proposals_jsonl.read_bytes()
    proposal_sha = sha256_bytes(proposal_bytes)
    proposal_ids = [str(proposal.get("review_unit_id") or "") for proposal in proposals]
    already_reviewed = set(proposal_ids) & set(ordered_reviewed)
    if already_reviewed:
        raise ReviewProtocolError(
            "日常 session append 不接受已審查 unit；修訂須使用獨立 supersession 流程："
            + ", ".join(sorted(already_reviewed))
        )
    missing_units = set(proposal_ids) - set(units)
    if missing_units:
        raise ReviewProtocolError("proposal 含未知 unit：" + ", ".join(sorted(missing_units)))
    _validate_group(proposals, units)

    window = session_window(unique_count, total_units)
    if len(proposals) > int(window["remaining"]):
        raise ReviewProtocolError(
            f"本 session 只剩 {window['remaining']} 筆；拒絕跨越第 {window['end']} 筆。"
        )

    derived_labels = [
        validate_proposal(proposal, units[unit_id], packet_root=packet_root)
        for proposal, unit_id in zip(proposals, proposal_ids)
    ]
    if any(label != human_label for label in derived_labels):
        raise ReviewProtocolError(
            "人工 label 與 Claude 提出的 R/I/S/A 決策表不一致；"
            "必須回到 evidence/proposal 修正，不得改寫人工輸入。"
        )

    reviewed_at = taipei_now()
    new_events = [
        _build_event(
            proposal,
            units[unit_id],
            reviewer_id=reviewer_id,
            human_label=human_label,
            human_confidence=human_confidence,
            assistant_id=assistant_id,
            proposal_sha256=proposal_sha,
            reviewed_at=reviewed_at,
        )
        for proposal, unit_id in zip(proposals, proposal_ids)
    ]
    _locked_pure_suffix_append(review_log, old_bytes, new_events, reviewed_at)
    return new_events


def append_revision(
    *,
    review_log: Path,
    review_units_csv: Path,
    packet_root: Path,
    proposals_jsonl: Path,
    human_label: str,
    human_confidence: str,
    reviewer_id: str,
    assistant_id: str,
    expected_log_sha256: str,
) -> list[dict[str, Any]]:
    """為已審查 unit append supersession event（authz_label_spec §7.2）。

    與日常 append 分開：只接受已審查 unit，不佔 20 筆 session 名額；每筆
    proposal 必須指定它取代的 event（且必須是該 unit 目前最新的 event），
    並以英文寫明 change_reason。舊 event 原樣保留。
    """
    if human_label not in LABEL_VALUES:
        raise ReviewProtocolError("人工 label 僅可為 positive/negative/unknown。")
    if human_confidence not in CONFIDENCE_VALUES:
        raise ReviewProtocolError("人工 confidence 僅可為 low/medium/high。")
    _require_ascii_prose(reviewer_id, "reviewer_id")
    _require_ascii_prose(assistant_id, "assistant_id")

    old_bytes = _read_log_for_append(review_log, expected_log_sha256)

    events = _read_jsonl(review_log)
    _ordered_unique_unit_ids(events)
    latest_event_id: dict[str, str] = {}
    for event in events:
        latest_event_id[str(event["review_unit_id"])] = str(event["review_event_id"])
    _, units = _load_review_units(review_units_csv)

    proposals = _read_jsonl(proposals_jsonl)
    proposal_sha = sha256_bytes(proposals_jsonl.read_bytes())
    proposal_ids = [str(proposal.get("review_unit_id") or "") for proposal in proposals]
    missing_units = set(proposal_ids) - set(units)
    if missing_units:
        raise ReviewProtocolError("proposal 含未知 unit：" + ", ".join(sorted(missing_units)))
    not_reviewed = set(proposal_ids) - set(latest_event_id)
    if not_reviewed:
        raise ReviewProtocolError(
            "修訂只接受已審查 unit；新 unit 請走日常 append："
            + ", ".join(sorted(not_reviewed))
        )
    for proposal, unit_id in zip(proposals, proposal_ids):
        supersedes = proposal.get("supersedes_review_event_id")
        if not isinstance(supersedes, str) or not supersedes:
            raise ReviewProtocolError(f"{unit_id} 缺 supersedes_review_event_id。")
        if supersedes != latest_event_id[unit_id]:
            raise ReviewProtocolError(
                f"{unit_id} 只能取代目前最新的 event："
                f"latest={latest_event_id[unit_id]}, given={supersedes}"
            )
        _require_ascii_prose(proposal.get("change_reason"), "change_reason")
    _validate_group(proposals, units)

    derived_labels = [
        validate_proposal(proposal, units[unit_id], packet_root=packet_root)
        for proposal, unit_id in zip(proposals, proposal_ids)
    ]
    if any(label != human_label for label in derived_labels):
        raise ReviewProtocolError(
            "人工 label 與 Claude 提出的 R/I/S/A 決策表不一致；"
            "必須回到 evidence/proposal 修正，不得改寫人工輸入。"
        )

    reviewed_at = taipei_now()
    new_events = [
        _build_event(
            proposal,
            units[unit_id],
            reviewer_id=reviewer_id,
            human_label=human_label,
            human_confidence=human_confidence,
            assistant_id=assistant_id,
            proposal_sha256=proposal_sha,
            reviewed_at=reviewed_at,
            supersedes_review_event_id=str(proposal["supersedes_review_event_id"]),
            change_reason=str(proposal["change_reason"]),
        )
        for proposal, unit_id in zip(proposals, proposal_ids)
    ]
    _locked_pure_suffix_append(review_log, old_bytes, new_events, reviewed_at)
    return new_events


def close_session(
    *,
    review_log: Path,
    review_units_csv: Path,
    experiment_dir: Path,
) -> Path:
    """在第 20 筆邊界產生不可覆寫的完整實驗紀錄。"""
    events = _read_jsonl(review_log)
    ordered_ids = _ordered_unique_unit_ids(events)
    rows, units = _load_review_units(review_units_csv)
    unique_count = len(ordered_ids)
    total_units = len(rows)
    if unique_count == 0:
        raise ReviewProtocolError("尚無 review unit，不能關閉 session。")
    is_final_partial = unique_count == total_units
    if unique_count % SESSION_SIZE != 0 and not is_final_partial:
        raise ReviewProtocolError(
            f"目前只有 {unique_count % SESSION_SIZE}/20 筆；尚未到 session 終止點。"
        )

    completed_in_window = unique_count % SESSION_SIZE or SESSION_SIZE
    start = unique_count - completed_in_window + 1
    end = unique_count
    path = experiment_log_path(experiment_dir, start, end)
    if path.exists():
        raise ReviewProtocolError(f"實驗紀錄已存在，拒絕覆寫：{path}")

    latest_by_unit: dict[str, Mapping[str, Any]] = {}
    for event in events:
        latest_by_unit[str(event["review_unit_id"])] = event
    selected_ids = ordered_ids[start - 1 : end]
    selected = [latest_by_unit[unit_id] for unit_id in selected_ids]
    counts = Counter(str(event.get("gold_authz_label")) for event in selected)
    log_sha = sha256_file(review_log)

    lines = [
        f"# Golden-50 人工審查實驗紀錄（第 {start}-{end} 筆）",
        "",
        f"- Workflow：`{WORKFLOW_VERSION}`",
        f"- 記錄範圍：`dataset/authz_v2/gold_review_log.jsonl` 第 {start}-{end} 個 unique review unit",
        f"- 本 session 新增 unique units：{len(selected)}",
        f"- Review log SHA-256：`{log_sha}`",
        f"- Review log events／unique units：{len(events)}／{unique_count}",
        "- 人工輸入欄位：`gold_authz_label`、`reviewer_confidence`",
        "- Claude 責任：R/I/S/A、evidence status、reason codes、notes、evidence references 與 mandatory checklist",
        "",
        "## Session 完整紀錄",
        "",
    ]
    for ordinal, event in enumerate(selected, start):
        unit_id = str(event["review_unit_id"])
        unit = units[unit_id]
        lines.extend(
            [
                f"### 第 {ordinal} 筆 — `{unit_id}`",
                "",
                f"- APK／component：`{unit.get('apk_sha256')}`／`{unit.get('manifest_component_name')}`",
                f"- Caller／sink：`{unit.get('caller_method')}`／`{unit.get('sensitive_sink')}`",
                f"- R/I/S/A：`{event.get('R_predicate_result')}`／`{event.get('I_predicate_result')}`／`{event.get('S_predicate_result')}`／`{event.get('A_predicate_result')}`",
                f"- 人工 label／confidence：`{event.get('gold_authz_label')}`／`{event.get('reviewer_confidence')}`",
                f"- Reviewer／assistant：`{event.get('reviewer_id')}`／`{event.get('assistant_id', 'legacy-unspecified')}`",
                f"- Evidence packet：`{event.get('evidence_packet_reference')}` (`{event.get('evidence_packet_sha256')}`)",
                f"- 說明：{event.get('reviewer_notes')}",
                "",
            ]
        )
    lines.extend(
        [
            "## 本 session 統計",
            "",
            "| gold_authz_label | 筆數 |",
            "| --- | ---: |",
            f"| positive | {counts.get('positive', 0)} |",
            f"| negative | {counts.get('negative', 0)} |",
            f"| unknown | {counts.get('unknown', 0)} |",
            f"| **合計** | **{len(selected)}** |",
            "",
            "## 終止與交接",
            "",
            "- 本 session 已完成紀錄，Claude CLI 必須在此停止，不得分析或 append 下一筆。",
        ]
    )
    if unique_count < total_units:
        lines.extend(
            [
                f"- 下一個新 session 從第 {unique_count + 1} 筆開始，下一個切換點為第 {min(unique_count + SESSION_SIZE, total_units)} 筆。",
                "- 新 session 開始前必須重新執行 `status`，取得最新 review log SHA-256 並確認沒有平行 writer。",
            ]
        )
    else:
        lines.append("- 全部 reviewer packet units 已完成；不得建立新的 review session。")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


def status_payload(review_log: Path, review_units_csv: Path) -> dict[str, Any]:
    events = _read_jsonl(review_log)
    ordered = _ordered_unique_unit_ids(events)
    rows, units = _load_review_units(review_units_csv)
    unknown_logged_units = set(ordered) - set(units)
    if unknown_logged_units:
        raise ReviewProtocolError("review log 與 review_units.csv identity 不一致。")
    return {
        "workflow_version": WORKFLOW_VERSION,
        "review_log_sha256": sha256_file(review_log)
        if review_log.is_file()
        else sha256_bytes(b""),
        "event_count": len(events),
        "unique_review_unit_count": len(ordered),
        "total_review_unit_count": len(rows),
        "session": session_window(len(ordered), len(rows)),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--review-log", type=Path, default=DEFAULT_REVIEW_LOG)
        subparser.add_argument(
            "--review-units", type=Path, default=DEFAULT_REVIEW_UNITS
        )

    status = subparsers.add_parser("status")
    common(status)

    append = subparsers.add_parser("append-approved-group")
    common(append)
    append.add_argument("--packet-root", type=Path, default=DEFAULT_PACKET_ROOT)
    append.add_argument("--proposals", type=Path, required=True)
    append.add_argument("--label", choices=sorted(LABEL_VALUES), required=True)
    append.add_argument(
        "--confidence", choices=sorted(CONFIDENCE_VALUES), required=True
    )
    append.add_argument("--reviewer-id", required=True)
    append.add_argument("--assistant-id", required=True)
    append.add_argument("--expected-log-sha256", required=True)
    append.add_argument("--experiment-dir", type=Path, default=DEFAULT_EXPERIMENT_DIR)

    revision = subparsers.add_parser("append-revision")
    common(revision)
    revision.add_argument("--packet-root", type=Path, default=DEFAULT_PACKET_ROOT)
    revision.add_argument("--proposals", type=Path, required=True)
    revision.add_argument("--label", choices=sorted(LABEL_VALUES), required=True)
    revision.add_argument(
        "--confidence", choices=sorted(CONFIDENCE_VALUES), required=True
    )
    revision.add_argument("--reviewer-id", required=True)
    revision.add_argument("--assistant-id", required=True)
    revision.add_argument("--expected-log-sha256", required=True)

    close = subparsers.add_parser("close-session")
    common(close)
    close.add_argument("--experiment-dir", type=Path, default=DEFAULT_EXPERIMENT_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "status":
            print(json.dumps(status_payload(args.review_log, args.review_units), ensure_ascii=False, indent=2))
            return 0
        if args.command == "append-approved-group":
            events = append_approved_group(
                review_log=args.review_log,
                review_units_csv=args.review_units,
                packet_root=args.packet_root,
                proposals_jsonl=args.proposals,
                human_label=args.label,
                human_confidence=args.confidence,
                reviewer_id=args.reviewer_id,
                assistant_id=args.assistant_id,
                expected_log_sha256=args.expected_log_sha256,
                experiment_dir=args.experiment_dir,
            )
            payload = status_payload(args.review_log, args.review_units)
            payload["appended_event_count"] = len(events)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            if payload["session"]["boundary_reached"]:
                print("SESSION_LIMIT_REACHED: 執行 close-session，完成紀錄後立即終止本 Claude CLI session。")
            return 0
        if args.command == "append-revision":
            events = append_revision(
                review_log=args.review_log,
                review_units_csv=args.review_units,
                packet_root=args.packet_root,
                proposals_jsonl=args.proposals,
                human_label=args.label,
                human_confidence=args.confidence,
                reviewer_id=args.reviewer_id,
                assistant_id=args.assistant_id,
                expected_log_sha256=args.expected_log_sha256,
            )
            payload = status_payload(args.review_log, args.review_units)
            payload["appended_revision_events"] = [
                {
                    "review_unit_id": event["review_unit_id"],
                    "review_event_id": event["review_event_id"],
                    "supersedes_review_event_id": event["supersedes_review_event_id"],
                }
                for event in events
            ]
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0
        if args.command == "close-session":
            path = close_session(
                review_log=args.review_log,
                review_units_csv=args.review_units,
                experiment_dir=args.experiment_dir,
            )
            print(f"SESSION_TERMINATED: {path}")
            print("不得在本 Claude CLI session 繼續審查；請另開新 session。")
            return 0
    except (OSError, ReviewProtocolError) as exc:
        parser = _parser()
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
