from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.tools import golden_batch as batch


def _entry(tmp_path: Path, rank: int, payload: bytes | None = None) -> batch.MembershipEntry:
    payload = payload or f"apk-{rank}".encode()
    sha256 = hashlib.sha256(payload).hexdigest()
    source = tmp_path / f"source-{rank}.apk"
    source.write_bytes(payload)
    return batch.MembershipEntry(
        membership_id=f"test-v1:{sha256}",
        sha256=sha256,
        source_path=str(source),
        package_name=f"example.package{rank}",
        selection_rank=rank,
        membership_version="test-v1",
    )


def _configs() -> dict[str, dict]:
    return {
        "mobsf": {
            "tool": "mobsf",
            "fingerprint": "mobsf-config",
            "available": True,
            "api_key": "secret-not-persisted",
        },
        "flowdroid": {
            "tool": "flowdroid",
            "fingerprint": "flowdroid-config",
            "available": True,
        },
    }


def _audit(count: int) -> dict:
    return {
        "membership_version": "test-v1",
        "membership_count": count,
        "membership_sha256": "membership-fingerprint",
        "membership_csv_sha256": "csv-fingerprint",
    }


def _write_fake_artifacts(tool: str, attempt_dir: Path, status: str) -> None:
    (attempt_dir / "run_metadata.json").write_text("{}\n", encoding="utf-8")
    (attempt_dir / "attempts.csv").write_text("status\n" + status + "\n", encoding="utf-8")
    if tool == "flowdroid":
        (attempt_dir / "stdout.log").write_text("stdout", encoding="utf-8")
        (attempt_dir / "stderr.log").write_text("stderr", encoding="utf-8")
    elif status == "success":
        raw = attempt_dir / "raw"
        raw.mkdir()
        (raw / "report.json").write_text("{}\n", encoding="utf-8")
        (attempt_dir / "candidate_summary.v2.json").write_text(
            json.dumps({"schema_version": "mobsf-candidate-summary-v2"}),
            encoding="utf-8",
        )


def test_real_golden_membership_identity_is_frozen():
    entries, audit = batch.load_frozen_membership(
        Path("dataset/authz_v2/golden_50_membership.csv"),
        Path("dataset/authz_v2/golden_50_selection_metadata.json"),
    )

    assert len(entries) == 50
    assert len({entry.membership_id for entry in entries}) == 50
    assert len({entry.sha256 for entry in entries}) == 50
    assert len({entry.package_name for entry in entries}) == 50
    assert audit["membership_sha256"] == batch.EXPECTED_MEMBERSHIP_SHA256
    assert audit["membership_csv_sha256"] == batch.EXPECTED_MEMBERSHIP_CSV_SHA256


def test_review_input_mismatch_is_not_overwritten(tmp_path):
    entry = _entry(tmp_path, 1)
    review_dir = tmp_path / "batch" / "review_inputs"
    review_dir.mkdir(parents=True)
    target = review_dir / f"{entry.sha256}.apk"
    target.write_bytes(b"wrong-existing-copy")

    with pytest.raises(ValueError, match="拒絕覆寫"):
        batch.prepare_review_input(entry, tmp_path / "batch")

    assert target.read_bytes() == b"wrong-existing-copy"


def test_deterministic_traversal_and_single_failure_continues(tmp_path):
    entries = [_entry(tmp_path, 2), _entry(tmp_path, 1)]
    calls = []

    def runner(tool, entry, apk, attempt_dir, config):
        del apk, config
        calls.append((entry.selection_rank, tool))
        status = "analysis_failed" if entry.selection_rank == 1 else "success"
        _write_fake_artifacts(tool, attempt_dir, status)
        return {"status": status, "error_type": "FixtureFailure" if status != "success" else ""}

    rows = batch.run_batch(
        entries=entries,
        membership_audit=_audit(2),
        output_dir=tmp_path / "batch",
        configs=_configs(),
        tools=["mobsf"],
        runner=runner,
    )

    assert calls == [(1, "mobsf"), (2, "mobsf")]
    mobsf_rows = [row for row in rows if row["tool"] == "mobsf"]
    assert [row["status"] for row in mobsf_rows] == ["analysis_failed", "success"]
    assert (tmp_path / "batch" / "execution_ledger.csv").is_file()
    assert (tmp_path / "batch" / "batch_events.jsonl").is_file()
    persisted = "\n".join(
        path.read_text(encoding="utf-8-sig")
        for path in (tmp_path / "batch").rglob("*")
        if path.is_file()
    )
    assert "secret-not-persisted" not in persisted


def test_resume_skips_verified_identity_config_and_artifacts(tmp_path):
    entry = _entry(tmp_path, 1)
    calls = []

    def runner(tool, entry, apk, attempt_dir, config):
        del entry, apk, config
        calls.append(attempt_dir)
        _write_fake_artifacts(tool, attempt_dir, "success")
        return {"status": "success"}

    kwargs = {
        "entries": [entry],
        "membership_audit": _audit(1),
        "output_dir": tmp_path / "batch",
        "configs": _configs(),
        "tools": ["mobsf"],
        "runner": runner,
    }
    batch.run_batch(**kwargs)
    rows = batch.run_batch(**kwargs)

    assert len(calls) == 1
    assert [row for row in rows if row["tool"] == "mobsf"][0]["resume_reason"] == (
        "identity_config_artifacts_verified"
    )


def test_changed_artifact_creates_new_attempt_without_overwriting_old(tmp_path):
    entry = _entry(tmp_path, 1)
    calls = []

    def runner(tool, entry, apk, attempt_dir, config):
        del entry, apk, config
        calls.append(attempt_dir)
        _write_fake_artifacts(tool, attempt_dir, "success")
        return {"status": "success"}

    kwargs = {
        "entries": [entry],
        "membership_audit": _audit(1),
        "output_dir": tmp_path / "batch",
        "configs": _configs(),
        "tools": ["mobsf"],
        "runner": runner,
    }
    batch.run_batch(**kwargs)
    first = calls[0]
    (first / "run_metadata.json").write_text("changed", encoding="utf-8")
    batch.run_batch(**kwargs)

    assert len(calls) == 2
    assert calls[0].name == "attempt_001"
    assert calls[1].name == "attempt_002"
    assert (calls[0] / "attempt_metadata.json").is_file()


def test_transient_mobsf_failure_retries_only_once(tmp_path):
    entry = _entry(tmp_path, 1)
    calls = []

    def runner(tool, entry, apk, attempt_dir, config):
        del entry, apk, config
        calls.append(attempt_dir)
        _write_fake_artifacts(tool, attempt_dir, "analysis_failed")
        return {
            "status": "analysis_failed",
            "error_type": "ConnectionRefusedError",
            "error_message": "connection refused",
        }

    rows = batch.run_batch(
        entries=[entry],
        membership_audit=_audit(1),
        output_dir=tmp_path / "batch",
        configs=_configs(),
        tools=["mobsf"],
        max_transient_retries=1,
        systemic_failure_threshold=3,
        runner=runner,
    )

    assert [path.name for path in calls] == ["attempt_001", "attempt_002"]
    row = [row for row in rows if row["tool"] == "mobsf"][0]
    assert row["attempt_number"] == 2


def test_same_systemic_failure_pauses_tool_after_two_apks(tmp_path):
    entries = [_entry(tmp_path, rank) for rank in range(1, 4)]
    calls = []

    def runner(tool, entry, apk, attempt_dir, config):
        del apk, config
        calls.append(entry.selection_rank)
        _write_fake_artifacts(tool, attempt_dir, "launch_failed")
        return {
            "status": "launch_failed",
            "error_type": "PermissionError",
            "error_message": "cannot launch tool",
        }

    rows = batch.run_batch(
        entries=entries,
        membership_audit=_audit(3),
        output_dir=tmp_path / "batch",
        configs=_configs(),
        tools=["flowdroid"],
        systemic_failure_threshold=2,
        runner=runner,
    )

    assert calls == [1, 2]
    statuses = [row["status"] for row in rows if row["tool"] == "flowdroid"]
    assert statuses == ["launch_failed", "launch_failed", "blocked_systemic"]
