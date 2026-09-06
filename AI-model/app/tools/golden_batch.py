"""對已凍結的 Golden-50 membership 執行可續跑、可稽核的靜態工具批次。

本模組只協調 MobSF 與 FlowDroid 候選證據，不建立人工 review event、
Gold label、weak label、label revision 或模型訓練資料。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import time
import urllib.error
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import flowdroid_poc, mobsf_poc


SCHEMA_VERSION = "golden-batch-v1"
ATTEMPT_SCHEMA_VERSION = "golden-batch-attempt-v1"
EVENT_SCHEMA_VERSION = "golden-batch-event-v1"
MEMBERSHIP_VERSION = "golden-50-v1"
EXPECTED_MEMBERSHIP_COUNT = 50
EXPECTED_MEMBERSHIP_SHA256 = (
    "7382f4d5e0434c8b7b37fa81269f88e32fe5d2fadc119301b56d512f9768f6e4"
)
EXPECTED_MEMBERSHIP_CSV_SHA256 = (
    "0d50029142e5ac8ee567fd72a732782723eb1d57588026b0860ea00fb9694ada"
)
TAIPEI_TIMEZONE = timezone(timedelta(hours=8), name="Asia/Taipei")
TOOLS = ("mobsf", "flowdroid")
FROZEN_HUMAN_FILES = (
    Path("dataset/authz_v2/golden_50_membership.csv"),
    Path("dataset/authz_v2/golden_50_selection_metadata.json"),
    Path("dataset/authz_v2/golden_50_annotations.csv"),
    Path("dataset/authz_v2/gold_review_log.jsonl"),
)
TERMINAL_ATTEMPT_STATUSES = {
    "success",
    "partial",
    "incomplete",
    "no_result_artifact",
    "invalid_result_artifact",
    "timeout",
    "memory_termination",
    "analysis_failed",
    "launch_failed",
}
LEDGER_FIELDS = (
    "membership_id",
    "apk_sha256",
    "tool",
    "status",
    "attempt_id",
    "attempt_number",
    "started_at",
    "completed_at",
    "duration_seconds",
    "config_fingerprint",
    "exit_code",
    "error_type",
    "error_message",
    "raw_artifact_references",
    "candidate_summary_reference",
    "candidate_summary_version",
    "stdout_reference",
    "stderr_reference",
    "resume_reason",
)


@dataclass(frozen=True)
class MembershipEntry:
    membership_id: str
    sha256: str
    source_path: str
    package_name: str
    selection_rank: int
    membership_version: str


def taipei_now() -> str:
    return datetime.now(TAIPEI_TIMEZONE).isoformat()


def canonical_fingerprint(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return flowdroid_poc.sha256_file(path)


def load_frozen_membership(
    membership_csv: Path,
    selection_metadata: Path,
    *,
    expected_count: int = EXPECTED_MEMBERSHIP_COUNT,
    expected_membership_sha256: str = EXPECTED_MEMBERSHIP_SHA256,
    expected_csv_sha256: str = EXPECTED_MEMBERSHIP_CSV_SHA256,
    expected_version: str = MEMBERSHIP_VERSION,
) -> tuple[list[MembershipEntry], dict[str, Any]]:
    """讀取唯一 authority，並同時核對 CSV bytes 與 canonical SHA 清單。"""
    membership_csv = membership_csv.resolve()
    selection_metadata = selection_metadata.resolve()
    csv_sha256 = sha256_file(membership_csv)
    if csv_sha256 != expected_csv_sha256:
        raise ValueError(
            "Golden membership CSV bytes SHA-256 不符："
            f"expected={expected_csv_sha256}, actual={csv_sha256}"
        )
    metadata = json.loads(selection_metadata.read_text(encoding="utf-8"))
    if metadata.get("membership_csv_sha256") != csv_sha256:
        raise ValueError("selection metadata 的 membership_csv_sha256 與 CSV 不符。")
    if metadata.get("membership_sha256") != expected_membership_sha256:
        raise ValueError("selection metadata 的 membership_sha256 與凍結值不符。")
    if metadata.get("config", {}).get("membership_version") != expected_version:
        raise ValueError("selection metadata 的 membership version 不符。")

    with membership_csv.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != expected_count:
        raise ValueError(f"Golden membership 必須恰好 {expected_count} 筆。")

    entries: list[MembershipEntry] = []
    for row in rows:
        sha256 = (row.get("sha256") or "").strip()
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError(f"membership 含無效 SHA-256：{sha256!r}")
        try:
            rank = int(row["selection_rank"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("membership selection_rank 無效。") from exc
        entries.append(
            MembershipEntry(
                membership_id=(row.get("membership_id") or "").strip(),
                sha256=sha256,
                source_path=(row.get("source_path") or "").strip(),
                package_name=(row.get("package_name") or "").strip(),
                selection_rank=rank,
                membership_version=(row.get("membership_version") or "").strip(),
            )
        )

    if len({entry.membership_id for entry in entries}) != expected_count:
        raise ValueError("Golden membership IDs 不唯一。")
    if len({entry.sha256 for entry in entries}) != expected_count:
        raise ValueError("Golden membership APK SHA-256 不唯一。")
    if len({entry.package_name for entry in entries}) != expected_count:
        raise ValueError("Golden membership package 不唯一。")
    if {entry.selection_rank for entry in entries} != set(range(1, expected_count + 1)):
        raise ValueError("Golden membership selection_rank 必須完整且唯一。")
    if any(entry.membership_version != expected_version for entry in entries):
        raise ValueError("membership row version 與凍結版本不符。")
    membership_sha256 = canonical_fingerprint(sorted(entry.sha256 for entry in entries))
    if membership_sha256 != expected_membership_sha256:
        raise ValueError(
            "Golden membership canonical fingerprint 不符："
            f"expected={expected_membership_sha256}, actual={membership_sha256}"
        )

    entries.sort(key=lambda entry: entry.selection_rank)
    audit = {
        "membership_version": expected_version,
        "membership_count": len(entries),
        "unique_membership_id_count": len({entry.membership_id for entry in entries}),
        "unique_apk_sha256_count": len({entry.sha256 for entry in entries}),
        "unique_package_count": len({entry.package_name for entry in entries}),
        "membership_sha256": membership_sha256,
        "membership_csv_sha256": csv_sha256,
        "membership_freeze_timestamp": metadata.get("membership_freeze_timestamp"),
        "authority_reference": str(membership_csv),
        "selection_metadata_reference": str(selection_metadata),
    }
    return entries, audit


def prepare_review_input(entry: MembershipEntry, output_dir: Path) -> tuple[Path, bool]:
    """建立中性 SHA 檔名副本；既有副本不符時絕不覆寫。"""
    source = Path(entry.source_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"membership source APK 不存在：{source}")
    actual_source_sha256 = sha256_file(source)
    if actual_source_sha256 != entry.sha256:
        raise ValueError(
            "membership source APK SHA-256 不符："
            f"expected={entry.sha256}, actual={actual_source_sha256}"
        )
    review_dir = output_dir / "review_inputs"
    review_dir.mkdir(parents=True, exist_ok=True)
    target = review_dir / f"{entry.sha256}.apk"
    if target.exists():
        actual_target_sha256 = sha256_file(target)
        if actual_target_sha256 != entry.sha256:
            raise ValueError(
                "既有中性 APK 副本 SHA-256 不符，拒絕覆寫："
                f"expected={entry.sha256}, actual={actual_target_sha256}, path={target}"
            )
        return target.resolve(), True
    shutil.copyfile(source, target)
    copied_sha256 = sha256_file(target)
    if copied_sha256 != entry.sha256:
        raise ValueError(
            "中性 APK 副本複製後 SHA-256 不符；已停止該項目且未覆寫："
            f"expected={entry.sha256}, actual={copied_sha256}, path={target}"
        )
    return target.resolve(), False


def _append_event(path: Path, event: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "timestamp": taipei_now(),
        **event,
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def _write_json_current(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _write_json_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _write_ledger(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in LEDGER_FIELDS})
    temporary.replace(path)


def _expected_artifact_paths(tool: str) -> tuple[str, ...]:
    if tool == "mobsf":
        return (
            "run_metadata.json",
            "attempts.csv",
            "raw/upload_response.json",
            "raw/scan_response.json",
            "raw/report.json",
            "candidate_summary.json",
            "candidate_summary.v2.json",
        )
    return (
        "run_metadata.json",
        "attempts.csv",
        "stdout.log",
        "stderr.log",
        "raw/flowdroid.xml",
    )


def _artifact_records(tool: str, attempt_dir: Path, output_dir: Path) -> list[dict[str, Any]]:
    records = []
    for relative in _expected_artifact_paths(tool):
        artifact = attempt_dir / relative
        exists = artifact.is_file()
        records.append(
            {
                "reference": artifact.relative_to(output_dir).as_posix(),
                "exists": exists,
                "sha256": sha256_file(artifact) if exists else None,
                "size_bytes": artifact.stat().st_size if exists else None,
            }
        )
    return records


def _validate_completed_attempt(
    attempt: Mapping[str, Any], output_dir: Path, entry: MembershipEntry, config_fingerprint: str
) -> tuple[bool, str]:
    if attempt.get("apk_sha256") != entry.sha256:
        return False, "attempt_identity_mismatch"
    if attempt.get("membership_id") != entry.membership_id:
        return False, "attempt_membership_mismatch"
    if attempt.get("config_fingerprint") != config_fingerprint:
        return False, "config_changed"
    if attempt.get("status") not in TERMINAL_ATTEMPT_STATUSES:
        return False, "attempt_not_terminal"
    for artifact in attempt.get("artifacts", []):
        path = output_dir / artifact["reference"]
        exists = path.is_file()
        if exists != bool(artifact.get("exists")):
            return False, "artifact_existence_changed"
        if exists and sha256_file(path) != artifact.get("sha256"):
            return False, "artifact_hash_mismatch"
    return True, "identity_config_artifacts_verified"


def _attempts_for(output_dir: Path, entry: MembershipEntry, tool: str) -> list[dict[str, Any]]:
    tool_dir = output_dir / "runs" / entry.sha256 / tool
    attempts = []
    if not tool_dir.is_dir():
        return attempts
    for child in sorted(tool_dir.glob("attempt_*")):
        metadata_path = child / "attempt_metadata.json"
        if not metadata_path.is_file():
            continue
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        payload["_attempt_dir"] = child
        attempts.append(payload)
    return sorted(attempts, key=lambda value: int(value.get("attempt_number", 0)))


def _next_attempt_number(output_dir: Path, entry: MembershipEntry, tool: str) -> int:
    tool_dir = output_dir / "runs" / entry.sha256 / tool
    numbers = []
    if tool_dir.is_dir():
        for child in tool_dir.glob("attempt_*" ):
            try:
                numbers.append(int(child.name.removeprefix("attempt_")))
            except ValueError:
                continue
    return max(numbers, default=0) + 1


def _is_transient(tool: str, attempt: Mapping[str, Any]) -> bool:
    if tool != "mobsf":
        return False
    error_type = str(attempt.get("error_type") or "")
    message = str(attempt.get("error_message") or "").lower()
    return error_type in {
        "URLError",
        "TimeoutError",
        "ConnectionError",
        "ConnectionResetError",
        "ConnectionRefusedError",
    } or any(token in message for token in ("timed out", "connection reset", "connection refused"))


def _systemic_signature(tool: str, attempt: Mapping[str, Any]) -> str | None:
    status = attempt.get("status")
    error_type = str(attempt.get("error_type") or "")
    if status == "launch_failed" or error_type in {
        "FileNotFoundError",
        "PermissionError",
        "MissingCredential",
        "FlowDroidJarMismatch",
        "InvalidToolConfiguration",
    }:
        return f"{tool}:{status}:{error_type}"
    if _is_transient(tool, attempt):
        return f"{tool}:connectivity:{error_type}"
    return None


def _candidate_summary(attempt_dir: Path) -> tuple[str, str]:
    for name in ("candidate_summary.v2.json", "candidate_summary.json"):
        path = attempt_dir / name
        if not path.is_file():
            continue
        try:
            version = json.loads(path.read_text(encoding="utf-8")).get("schema_version", "")
        except (OSError, json.JSONDecodeError):
            version = ""
        return name, str(version)
    return "", ""


def _ledger_row(attempt: Mapping[str, Any]) -> dict[str, Any]:
    existing_artifacts = [
        artifact["reference"] for artifact in attempt.get("artifacts", []) if artifact.get("exists")
    ]
    return {
        "membership_id": attempt.get("membership_id", ""),
        "apk_sha256": attempt.get("apk_sha256", ""),
        "tool": attempt.get("tool", ""),
        "status": attempt.get("status", ""),
        "attempt_id": attempt.get("attempt_id", ""),
        "attempt_number": attempt.get("attempt_number", ""),
        "started_at": attempt.get("started_at", ""),
        "completed_at": attempt.get("completed_at", ""),
        "duration_seconds": attempt.get("duration_seconds", ""),
        "config_fingerprint": attempt.get("config_fingerprint", ""),
        "exit_code": attempt.get("exit_code", ""),
        "error_type": attempt.get("error_type", ""),
        "error_message": attempt.get("error_message", ""),
        "raw_artifact_references": ";".join(existing_artifacts),
        "candidate_summary_reference": attempt.get("candidate_summary_reference", ""),
        "candidate_summary_version": attempt.get("candidate_summary_version", ""),
        "stdout_reference": attempt.get("stdout_reference", ""),
        "stderr_reference": attempt.get("stderr_reference", ""),
        "resume_reason": attempt.get("resume_reason", ""),
    }


def _blocked_row(
    entry: MembershipEntry,
    tool: str,
    config_fingerprint: str,
    *,
    status: str,
    error_type: str,
    error_message: str,
) -> dict[str, Any]:
    return {
        "membership_id": entry.membership_id,
        "apk_sha256": entry.sha256,
        "tool": tool,
        "status": status,
        "config_fingerprint": config_fingerprint,
        "error_type": error_type,
        "error_message": error_message,
    }


def _default_tool_runner(
    tool: str,
    entry: MembershipEntry,
    apk: Path,
    attempt_dir: Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    del entry
    if tool == "mobsf":
        metadata = mobsf_poc.run_mobsf(
            apk=apk,
            output_dir=attempt_dir,
            api_key=str(config["api_key"]),
            base_url=str(config["base_url"]),
            request_timeout_seconds=int(config["request_timeout_seconds"]),
        )
        result = dict(metadata["result"])
        report = attempt_dir / "raw" / "report.json"
        if result.get("status") == "success" and report.is_file():
            try:
                mobsf_poc.rebuild_candidate_summary(
                    apk=apk, report_path=report, output_dir=attempt_dir
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                result.update(
                    {
                        "status": "partial",
                        "error_type": "SummaryRebuildError",
                        "error_message": str(exc),
                    }
                )
        return result
    metadata = flowdroid_poc.run_flowdroid(
        jar=Path(config["jar_path"]),
        apk=apk,
        platforms_dir=Path(config["android_platforms_path"]),
        sources_sinks=Path(config["sources_sinks_path"]),
        output_dir=attempt_dir,
        java=str(config["java"]),
        callback_timeout_seconds=int(config["callback_timeout_seconds"]),
        dataflow_timeout_seconds=int(config["dataflow_timeout_seconds"]),
        result_timeout_seconds=int(config["result_timeout_seconds"]),
        process_timeout_seconds=int(config["process_timeout_seconds"]),
        max_threads=int(config["max_threads"]),
        java_max_heap=str(config["java_max_heap"]),
    )
    return dict(metadata["result"])


def _record_attempt(
    *,
    output_dir: Path,
    entry: MembershipEntry,
    tool: str,
    config: Mapping[str, Any],
    review_input: Path,
    resume_reason: str,
    runner: Callable[[str, MembershipEntry, Path, Path, Mapping[str, Any]], Mapping[str, Any]],
    events_path: Path,
) -> dict[str, Any]:
    attempt_number = _next_attempt_number(output_dir, entry, tool)
    attempt_id = f"{entry.sha256}:{tool}:attempt_{attempt_number:03d}"
    attempt_dir = output_dir / "runs" / entry.sha256 / tool / f"attempt_{attempt_number:03d}"
    attempt_dir.mkdir(parents=True, exist_ok=False)
    started_at = taipei_now()
    start = time.perf_counter()
    _append_event(
        events_path,
        {
            "event": "attempt_started",
            "membership_id": entry.membership_id,
            "apk_sha256": entry.sha256,
            "tool": tool,
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "config_fingerprint": config["fingerprint"],
            "resume_reason": resume_reason,
        },
    )
    try:
        result = dict(runner(tool, entry, review_input, attempt_dir, config))
    except Exception as exc:  # 邊界層必須記錄單筆 failure，讓其他 APK 可繼續。
        result = {
            "status": "launch_failed" if isinstance(exc, OSError) else "analysis_failed",
            "exit_code": "",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }
    completed_at = taipei_now()
    duration = time.perf_counter() - start
    status = str(result.get("status") or "analysis_failed")
    if status not in TERMINAL_ATTEMPT_STATUSES:
        status = "analysis_failed"
        result["error_type"] = "InvalidRunnerStatus"
        result["error_message"] = "runner 回傳未定義狀態。"
    artifacts = _artifact_records(tool, attempt_dir, output_dir)
    summary_name, summary_version = _candidate_summary(attempt_dir)
    summary_reference = (
        (attempt_dir / summary_name).relative_to(output_dir).as_posix() if summary_name else ""
    )
    attempt = {
        "schema_version": ATTEMPT_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "attempt_number": attempt_number,
        "membership_id": entry.membership_id,
        "apk_sha256": entry.sha256,
        "tool": tool,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": float(result.get("duration_seconds") or duration),
        "config_fingerprint": config["fingerprint"],
        "status": status,
        "exit_code": result.get("exit_code", ""),
        "error_type": result.get("error_type", ""),
        "error_message": result.get("error_message", ""),
        "resume_reason": resume_reason,
        "review_input_reference": review_input.relative_to(output_dir).as_posix(),
        "review_input_sha256": entry.sha256,
        "artifacts": artifacts,
        "candidate_summary_reference": summary_reference,
        "candidate_summary_version": summary_version,
        "stdout_reference": (
            (attempt_dir / "stdout.log").relative_to(output_dir).as_posix()
            if (attempt_dir / "stdout.log").is_file()
            else ""
        ),
        "stderr_reference": (
            (attempt_dir / "stderr.log").relative_to(output_dir).as_posix()
            if (attempt_dir / "stderr.log").is_file()
            else ""
        ),
    }
    _write_json_exclusive(attempt_dir / "attempt_metadata.json", attempt)
    _append_event(
        events_path,
        {
            "event": "attempt_completed",
            "membership_id": entry.membership_id,
            "apk_sha256": entry.sha256,
            "tool": tool,
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "config_fingerprint": config["fingerprint"],
            "status": status,
            "error_type": attempt["error_type"],
            "error_message": attempt["error_message"],
        },
    )
    return attempt


def _resource_snapshot(output_dir: Path) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "logical_cpu_count": os.cpu_count(),
        "platform": platform.platform(),
        "sequential_heavy_workers": 1,
    }
    try:
        import psutil

        memory = psutil.virtual_memory()
        snapshot["physical_memory_total_bytes"] = memory.total
        snapshot["physical_memory_available_bytes"] = memory.available
    except (ImportError, OSError):
        snapshot["physical_memory_total_bytes"] = None
        snapshot["physical_memory_available_bytes"] = None
    usage = shutil.disk_usage(output_dir.resolve().anchor or output_dir)
    snapshot["output_volume_free_bytes"] = usage.free
    return snapshot


def _java_version(java: str) -> str:
    completed = subprocess.run(
        [java, "-version"], capture_output=True, text=True, shell=False, check=False, timeout=30
    )
    return (completed.stderr or completed.stdout).strip()


def _mobsf_container_snapshot(container: str, image: str) -> dict[str, Any]:
    """只擷取非 credential Docker provenance；完整 inspect payload 不落盤。"""
    container_result = subprocess.run(
        ["docker", "inspect", container],
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    if container_result.returncode != 0:
        raise OSError(container_result.stderr.strip() or "無法查詢 MobSF container。")
    image_result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    if image_result.returncode != 0:
        raise OSError(image_result.stderr.strip() or "無法查詢 MobSF image。")
    container_payload = json.loads(container_result.stdout)[0]
    image_payload = json.loads(image_result.stdout)[0]
    repo_digests = image_payload.get("RepoDigests") or []
    digest = ""
    if repo_digests and "@" in repo_digests[0]:
        digest = str(repo_digests[0]).split("@", 1)[1]
    health = (container_payload.get("State", {}).get("Health") or {}).get("Status")
    return {
        "container_name": container,
        "container_image_reference": container_payload.get("Config", {}).get("Image"),
        "container_image_id": container_payload.get("Image"),
        "container_running": bool(container_payload.get("State", {}).get("Running")),
        "container_health": health,
        "image_id": image_payload.get("Id"),
        "repo_digest": digest,
        "published_ports": container_payload.get("NetworkSettings", {}).get("Ports"),
        "credential_fields_persisted": False,
    }


def _frozen_human_file_snapshot() -> dict[str, dict[str, Any]]:
    snapshot = {}
    for path in FROZEN_HUMAN_FILES:
        resolved = path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"受保護的 Golden 人工檔案不存在：{resolved}")
        snapshot[path.as_posix()] = {
            "sha256": sha256_file(resolved),
            "size_bytes": resolved.stat().st_size,
        }
    return snapshot


def build_tool_configs(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    """建立去除 credential 的實際設定 payload 與 fingerprint。"""
    configs: dict[str, dict[str, Any]] = {}
    mobsf_container: dict[str, Any] | None = None
    mobsf_unavailable_reason = ""
    try:
        mobsf_container = _mobsf_container_snapshot(args.mobsf_container, mobsf_poc.MOBSF_IMAGE)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        mobsf_unavailable_reason = str(exc)
    mobsf_payload = {
        "tool": "mobsf",
        "version": mobsf_poc.MOBSF_VERSION,
        "image": mobsf_poc.MOBSF_IMAGE,
        "image_digest": mobsf_poc.MOBSF_IMAGE_DIGEST,
        "base_url": mobsf_poc.validate_base_url(args.mobsf_base_url),
        "request_timeout_seconds": args.mobsf_request_timeout,
        "force_rescan": True,
        "summary_schema": "mobsf-candidate-summary-v2",
        "api_key_persisted": False,
        "container": mobsf_container,
    }
    if mobsf_container and mobsf_container.get("repo_digest") != mobsf_poc.MOBSF_IMAGE_DIGEST:
        mobsf_unavailable_reason = "MobSF image RepoDigest 與固定版本不符。"
    elif mobsf_container and not mobsf_container.get("container_running"):
        mobsf_unavailable_reason = "MobSF container 未執行。"
    elif mobsf_container and mobsf_container.get("container_health") not in (None, "healthy"):
        mobsf_unavailable_reason = f"MobSF container health={mobsf_container.get('container_health')}"
    api_key = os.environ.get(args.mobsf_api_key_env, "")
    if not api_key:
        mobsf_unavailable_reason = f"缺少環境變數 {args.mobsf_api_key_env}"
    configs["mobsf"] = {
        **mobsf_payload,
        "fingerprint": canonical_fingerprint(mobsf_payload),
        "available": not mobsf_unavailable_reason,
        "unavailable_reason": mobsf_unavailable_reason,
        "api_key": api_key,
    }

    jar = args.flowdroid_jar.resolve()
    sources_sinks = args.sources_sinks.resolve()
    platforms = args.platforms_dir.resolve()
    flow_payload: dict[str, Any] = {
        "tool": "flowdroid",
        "version": flowdroid_poc.FLOWDROID_VERSION,
        "jar_path": str(jar),
        "jar_sha256": sha256_file(jar) if jar.is_file() else None,
        "android_platforms_path": str(platforms),
        "android_jar_sha256": sha256_file(platforms) if platforms.is_file() else None,
        "sources_sinks_path": str(sources_sinks),
        "sources_sinks_sha256": sha256_file(sources_sinks) if sources_sinks.is_file() else None,
        "java": args.java,
        "java_version": _java_version(args.java),
        "java_max_heap": args.java_max_heap,
        "callback_timeout_seconds": args.callback_timeout,
        "dataflow_timeout_seconds": args.dataflow_timeout,
        "result_timeout_seconds": args.result_timeout,
        "process_timeout_seconds": args.process_timeout,
        "max_threads": args.max_threads,
        "shell": False,
    }
    unavailable_reason = ""
    if not jar.is_file():
        unavailable_reason = f"FlowDroid JAR 不存在：{jar}"
    elif flow_payload["jar_sha256"] != flowdroid_poc.FLOWDROID_JAR_SHA256:
        unavailable_reason = "FlowDroid JAR SHA-256 與固定版本不符。"
    elif not sources_sinks.is_file():
        unavailable_reason = f"sources/sinks 不存在：{sources_sinks}"
    else:
        try:
            flowdroid_poc.require_platforms_path(platforms)
            flowdroid_poc.build_command(
                java=args.java,
                jar=jar,
                apk=Path("placeholder.apk"),
                platforms_dir=platforms,
                sources_sinks=sources_sinks,
                result_xml=Path("placeholder.xml"),
                callback_timeout_seconds=args.callback_timeout,
                dataflow_timeout_seconds=args.dataflow_timeout,
                result_timeout_seconds=args.result_timeout,
                max_threads=args.max_threads,
                java_max_heap=args.java_max_heap,
            )
        except (OSError, ValueError) as exc:
            unavailable_reason = str(exc)
    configs["flowdroid"] = {
        **flow_payload,
        "fingerprint": canonical_fingerprint(flow_payload),
        "available": not unavailable_reason,
        "unavailable_reason": unavailable_reason,
    }
    return configs


def _sanitized_config(config: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in config.items() if key != "api_key"}


def _load_or_initialize_batch_metadata(
    output_dir: Path,
    membership_audit: Mapping[str, Any],
    configs: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    path = output_dir / "batch_metadata.json"
    current_human_files = _frozen_human_file_snapshot()
    if path.is_file():
        metadata = json.loads(path.read_text(encoding="utf-8"))
        existing = metadata.get("membership", {})
        for key in ("membership_version", "membership_sha256", "membership_csv_sha256"):
            if existing.get(key) != membership_audit.get(key):
                raise ValueError(f"既有 batch metadata 的 {key} 與目前凍結 membership 不符。")
        if metadata.get("frozen_human_files") != current_human_files:
            raise ValueError("Golden membership／annotation／human review log 已在批次期間變更。")
    else:
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "created_at": taipei_now(),
            "membership": dict(membership_audit),
            "resource_snapshot_at_creation": _resource_snapshot(output_dir),
            "frozen_human_files": current_human_files,
            "configurations": {},
            "semantics": {
                "output_role": "coordinator_candidate_evidence",
                "reviewer_packet_blinded": False,
                "produces_ground_truth": False,
                "absence_is_negative_label": False,
                "static_analysis_only": True,
            },
        }
    for tool, config in configs.items():
        metadata["configurations"][config["fingerprint"]] = _sanitized_config(config)
        metadata["configurations"][config["fingerprint"]]["tool"] = tool
    metadata["updated_at"] = taipei_now()
    _write_json_current(path, metadata)
    return metadata


def run_batch(
    *,
    entries: Sequence[MembershipEntry],
    membership_audit: Mapping[str, Any],
    output_dir: Path,
    configs: Mapping[str, Mapping[str, Any]],
    tools: Sequence[str] = TOOLS,
    max_work_items: int | None = None,
    max_transient_retries: int = 1,
    systemic_failure_threshold: int = 2,
    runner: Callable[[str, MembershipEntry, Path, Path, Mapping[str, Any]], Mapping[str, Any]] = _default_tool_runner,
) -> list[dict[str, Any]]:
    """依 selection rank 與固定 tool order 串行執行；每筆 failure 後繼續。"""
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    events_path = output_dir / "batch_events.jsonl"
    ledger_path = output_dir / "execution_ledger.csv"
    selected_tools = tuple(tool for tool in TOOLS if tool in tools)
    if set(selected_tools) != set(tools):
        raise ValueError(f"不支援的 tool：{set(tools) - set(TOOLS)}")
    batch_metadata = _load_or_initialize_batch_metadata(output_dir, membership_audit, configs)
    invocation_id = f"batch-{datetime.now(TAIPEI_TIMEZONE).strftime('%Y%m%dT%H%M%S%f%z')}"
    _append_event(
        events_path,
        {
            "event": "batch_started",
            "invocation_id": invocation_id,
            "tools": list(selected_tools),
            "config_fingerprints": {tool: configs[tool]["fingerprint"] for tool in selected_tools},
            "max_work_items": max_work_items,
            "sequential_heavy_workers": 1,
        },
    )

    ledger: dict[tuple[str, str], dict[str, Any]] = {
        (entry.sha256, tool): {
            "membership_id": entry.membership_id,
            "apk_sha256": entry.sha256,
            "tool": tool,
            "status": "pending",
            "config_fingerprint": configs[tool]["fingerprint"],
        }
        for entry in entries
        for tool in TOOLS
    }
    processed_attempts = 0
    processed_work_items = 0
    paused_tools: dict[str, tuple[str, str]] = {}
    systemic_counts: dict[tuple[str, str], int] = {}

    for entry in sorted(entries, key=lambda item: item.selection_rank):
        if max_work_items is not None and processed_work_items >= max_work_items:
            break
        review_input: Path | None = None
        input_error: Exception | None = None
        try:
            review_input, reused = prepare_review_input(entry, output_dir)
            _append_event(
                events_path,
                {
                    "event": "review_input_verified",
                    "membership_id": entry.membership_id,
                    "apk_sha256": entry.sha256,
                    "review_input_reference": review_input.relative_to(output_dir).as_posix(),
                    "reused": reused,
                },
            )
        except (OSError, ValueError) as exc:
            input_error = exc

        for tool in selected_tools:
            key = (entry.sha256, tool)
            config = configs[tool]
            if max_work_items is not None and processed_work_items >= max_work_items:
                continue
            if tool in paused_tools:
                signature, message = paused_tools[tool]
                ledger[key] = _blocked_row(
                    entry,
                    tool,
                    config["fingerprint"],
                    status="blocked_systemic",
                    error_type="SystemicToolFailure",
                    error_message=f"{signature}: {message}",
                )
                _append_event(
                    events_path,
                    {
                        "event": "work_item_blocked",
                        "membership_id": entry.membership_id,
                        "apk_sha256": entry.sha256,
                        "tool": tool,
                        "status": "blocked_systemic",
                        "error_type": "SystemicToolFailure",
                    },
                )
                continue
            if not config.get("available", True):
                ledger[key] = _blocked_row(
                    entry,
                    tool,
                    config["fingerprint"],
                    status="blocked_preflight",
                    error_type="MissingCredential" if tool == "mobsf" else "InvalidToolConfiguration",
                    error_message=str(config.get("unavailable_reason") or "tool preflight failed"),
                )
                _append_event(
                    events_path,
                    {
                        "event": "work_item_blocked",
                        "membership_id": entry.membership_id,
                        "apk_sha256": entry.sha256,
                        "tool": tool,
                        "status": "blocked_preflight",
                        "error_type": ledger[key]["error_type"],
                        "error_message": ledger[key]["error_message"],
                    },
                )
                continue
            if input_error is not None:
                ledger[key] = _blocked_row(
                    entry,
                    tool,
                    config["fingerprint"],
                    status="blocked_input",
                    error_type=type(input_error).__name__,
                    error_message=str(input_error),
                )
                _append_event(
                    events_path,
                    {
                        "event": "work_item_blocked",
                        "membership_id": entry.membership_id,
                        "apk_sha256": entry.sha256,
                        "tool": tool,
                        "status": "blocked_input",
                        "error_type": type(input_error).__name__,
                        "error_message": str(input_error),
                    },
                )
                continue
            assert review_input is not None

            previous = _attempts_for(output_dir, entry, tool)
            same_config = [
                attempt
                for attempt in previous
                if attempt.get("config_fingerprint") == config["fingerprint"]
            ]
            resume_reason = "first_attempt"
            if previous:
                valid, reason = _validate_completed_attempt(
                    previous[-1], output_dir, entry, config["fingerprint"]
                )
                resume_reason = reason
                if valid:
                    transient_attempt_count = sum(
                        1 for attempt in same_config if _is_transient(tool, attempt)
                    )
                    can_retry = (
                        _is_transient(tool, previous[-1])
                        and transient_attempt_count <= max_transient_retries
                    )
                    if not can_retry:
                        ledger[key] = _ledger_row(previous[-1])
                        ledger[key]["resume_reason"] = reason
                        _append_event(
                            events_path,
                            {
                                "event": "work_item_skipped",
                                "membership_id": entry.membership_id,
                                "apk_sha256": entry.sha256,
                                "tool": tool,
                                "attempt_id": previous[-1].get("attempt_id"),
                                "reason": reason,
                            },
                        )
                        continue
                    resume_reason = "bounded_transient_retry"

            attempt = _record_attempt(
                output_dir=output_dir,
                entry=entry,
                tool=tool,
                config=config,
                review_input=review_input,
                resume_reason=resume_reason,
                runner=runner,
                events_path=events_path,
            )
            processed_attempts += 1
            ledger[key] = _ledger_row(attempt)

            if _is_transient(tool, attempt):
                same_config_count = sum(
                    1 for old in same_config if _is_transient(tool, old)
                ) + 1
                if same_config_count <= max_transient_retries:
                    retry = _record_attempt(
                        output_dir=output_dir,
                        entry=entry,
                        tool=tool,
                        config=config,
                        review_input=review_input,
                        resume_reason="bounded_transient_retry",
                        runner=runner,
                        events_path=events_path,
                    )
                    processed_attempts += 1
                    attempt = retry
                    ledger[key] = _ledger_row(retry)

            processed_work_items += 1

            signature = _systemic_signature(tool, attempt)
            if signature:
                signature_key = (tool, signature)
                systemic_counts[signature_key] = systemic_counts.get(signature_key, 0) + 1
                if systemic_counts[signature_key] >= systemic_failure_threshold:
                    message = str(attempt.get("error_message") or "")
                    paused_tools[tool] = (signature, message)
                    _append_event(
                        events_path,
                        {
                            "event": "tool_paused",
                            "tool": tool,
                            "signature": signature,
                            "failure_count": systemic_counts[signature_key],
                            "reason": message,
                        },
                    )
            ordered_rows = [
                ledger[(member.sha256, ledger_tool)]
                for member in sorted(entries, key=lambda item: item.selection_rank)
                for ledger_tool in TOOLS
            ]
            _write_ledger(ledger_path, ordered_rows)

    ordered_rows = [
        ledger[(entry.sha256, tool)]
        for entry in sorted(entries, key=lambda item: item.selection_rank)
        for tool in TOOLS
    ]
    _write_ledger(ledger_path, ordered_rows)
    if batch_metadata["frozen_human_files"] != _frozen_human_file_snapshot():
        _append_event(
            events_path,
            {
                "event": "frozen_human_files_changed",
                "invocation_id": invocation_id,
            },
        )
        raise RuntimeError("批次期間 Golden membership／annotation／human review log 發生變更。")
    _append_event(
        events_path,
        {
            "event": "batch_completed",
            "invocation_id": invocation_id,
            "processed_attempt_count": processed_attempts,
            "processed_work_item_count": processed_work_items,
            "status_counts": _status_counts(ordered_rows),
            "paused_tools": sorted(paused_tools),
        },
    )
    write_batch_report(output_dir, ordered_rows, membership_audit)
    return ordered_rows


def _status_counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _duration_summary(rows: Sequence[Mapping[str, Any]], tool: str) -> str:
    values = sorted(
        float(row["duration_seconds"])
        for row in rows
        if row.get("tool") == tool and row.get("duration_seconds") not in (None, "")
    )
    if not values:
        return "無已完成 attempt"
    p95_index = max(0, min(len(values) - 1, int(round(0.95 * (len(values) - 1)))))
    return (
        f"n={len(values)}, min={values[0]:.3f}s, median={statistics.median(values):.3f}s, "
        f"p95={values[p95_index]:.3f}s, max={values[-1]:.3f}s"
    )


def _report_details(
    output_dir: Path, rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    error_counts: dict[str, int] = {}
    missing_artifacts: dict[str, int] = {}
    integrity_failures: list[str] = []
    attempted = 0
    component_apks: set[str] = set()
    manifest_apks: set[str] = set()
    method_api_apks: set[str] = set()
    source_to_sink_apks: set[str] = set()
    for row in rows:
        error_type = str(row.get("error_type") or "")
        if error_type:
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        attempt_id = str(row.get("attempt_id") or "")
        if not attempt_id:
            continue
        attempted += 1
        attempt_number = int(row["attempt_number"])
        attempt_dir = (
            output_dir
            / "runs"
            / str(row["apk_sha256"])
            / str(row["tool"])
            / f"attempt_{attempt_number:03d}"
        )
        metadata_path = attempt_dir / "attempt_metadata.json"
        if not metadata_path.is_file():
            integrity_failures.append(f"{attempt_id}:missing_attempt_metadata")
            continue
        try:
            attempt = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            integrity_failures.append(f"{attempt_id}:invalid_attempt_metadata")
            continue
        for artifact in attempt.get("artifacts", []):
            reference = str(artifact["reference"])
            if not artifact.get("exists"):
                relative_name = reference.split(f"attempt_{attempt_number:03d}/", 1)[-1]
                key = f"{row['tool']}:{relative_name}"
                missing_artifacts[key] = missing_artifacts.get(key, 0) + 1
                continue
            path = output_dir / reference
            if not path.is_file() or sha256_file(path) != artifact.get("sha256"):
                integrity_failures.append(f"{attempt_id}:{reference}")

        if row.get("tool") == "flowdroid":
            run_metadata = attempt_dir / "run_metadata.json"
            if run_metadata.is_file():
                try:
                    result = json.loads(run_metadata.read_text(encoding="utf-8"))["result"]
                except (OSError, KeyError, json.JSONDecodeError):
                    result = {}
                if int(result.get("finding_count") or 0) > 0:
                    source_to_sink_apks.add(str(row["apk_sha256"]))
        elif row.get("tool") == "mobsf":
            summary_path = attempt_dir / "candidate_summary.v2.json"
            if not summary_path.is_file():
                summary_path = attempt_dir / "candidate_summary.json"
            if not summary_path.is_file():
                continue
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            components = summary.get("components") or {}
            if any(
                components.get(field)
                for field in (
                    "manifest_activity_exposure",
                    "exported_activities",
                    "services",
                    "receivers",
                    "providers",
                )
            ):
                component_apks.add(str(row["apk_sha256"]))
            if components.get("manifest_activity_exposure") or summary.get("manifest_findings"):
                manifest_apks.add(str(row["apk_sha256"]))
            for group in (summary.get("selected_android_api_groups") or {}).values():
                if isinstance(group, Mapping) and group.get("application_files"):
                    method_api_apks.add(str(row["apk_sha256"]))
                    break
    return {
        "error_counts": dict(sorted(error_counts.items())),
        "missing_artifacts": dict(sorted(missing_artifacts.items())),
        "attempted_count": attempted,
        "integrity_failure_count": len(integrity_failures),
        "integrity_failures": integrity_failures,
        "component_apk_count": len(component_apks),
        "manifest_apk_count": len(manifest_apks),
        "method_api_apk_count": len(method_api_apks),
        "source_to_sink_apk_count": len(source_to_sink_apks),
    }


def write_batch_report(
    output_dir: Path,
    rows: Sequence[Mapping[str, Any]],
    membership_audit: Mapping[str, Any],
) -> None:
    counts = _status_counts(rows)
    details = _report_details(output_dir, rows)
    metadata = json.loads((output_dir / "batch_metadata.json").read_text(encoding="utf-8"))
    resources = metadata["resource_snapshot_at_creation"]
    flow_configs = [
        config
        for config in metadata.get("configurations", {}).values()
        if config.get("tool") == "flowdroid"
    ]
    flow_config = flow_configs[-1] if flow_configs else {}
    lines = [
        "# Golden-50 批次執行報告",
        "",
        f"更新時間：{taipei_now()}",
        "",
        "本報告只彙整 MobSF／FlowDroid 靜態候選證據與執行 provenance；"
        "工具結果不是 Gold label，缺少 finding／XML 也不是 authorization negative。",
        "",
        "## 凍結 membership",
        "",
        f"- Version：`{membership_audit['membership_version']}`",
        f"- APK 數：{membership_audit['membership_count']}",
        f"- Membership fingerprint：`{membership_audit['membership_sha256']}`",
        f"- CSV bytes SHA-256：`{membership_audit['membership_csv_sha256']}`",
        "- 本批次未重新 clustering、抽樣或替換任何 APK。",
        "",
        "## Current ledger 狀態",
        "",
    ]
    for status, count in counts.items():
        lines.append(f"- `{status}`：{count}")
    lines.extend(["", "### 錯誤／限制分類", ""])
    if details["error_counts"]:
        for error_type, count in details["error_counts"].items():
            lines.append(f"- `{error_type}`：{count}")
    else:
        lines.append("- 無")
    lines.extend(
        [
            "",
            "## Duration",
            "",
            f"- MobSF：{_duration_summary(rows, 'mobsf')}",
            f"- FlowDroid：{_duration_summary(rows, 'flowdroid')}",
            "",
            "## 資源與設定上限",
            "",
            f"- 邏輯 CPU：{resources.get('logical_cpu_count')}；同時重型 workers：1。",
            f"- 實體 RAM：{resources.get('physical_memory_total_bytes')} bytes；"
            f"batch 建立時 available：{resources.get('physical_memory_available_bytes')} bytes。",
            f"- FlowDroid：`-Xmx{flow_config.get('java_max_heap', '')}`、"
            f"`max_threads={flow_config.get('max_threads', '')}`、"
            f"process timeout={flow_config.get('process_timeout_seconds', '')}s。",
            "",
            "## Artifact 與 provenance 完整性",
            "",
            f"- 有 attempt metadata 的工作項目：{details['attempted_count']}。",
            f"- Artifact existence/hash integrity failures：{details['integrity_failure_count']}。",
        ]
    )
    if details["missing_artifacts"]:
        for reference, count in details["missing_artifacts"].items():
            lines.append(f"- 預期但不存在 `{reference}`：{count} attempts。")
    else:
        lines.append("- 已執行 attempts 沒有記錄為缺失的預期 artifact。")
    lines.extend(
        [
            "",
            "## 可定位候選證據（APK 去重計數）",
            "",
            f"- Component inventory：{details['component_apk_count']} APK。",
            f"- Manifest evidence：{details['manifest_apk_count']} APK。",
            f"- Method/API locator：{details['method_api_apk_count']} APK。",
            f"- FlowDroid source-to-sink result：{details['source_to_sink_apk_count']} APK。",
            "",
            "上述是工具輸出可定位性，不是 R/I/S/A 完整性或 authorization verdict。"
            "MobSF 未完成時，component／Manifest／API 計數仍是不完整下限。",
            "",
            "## 人工檔案不變性",
            "",
        ]
    )
    for reference, identity in metadata["frozen_human_files"].items():
        lines.append(f"- `{reference}`：`{identity['sha256']}`（{identity['size_bytes']} bytes）")
    lines.extend(
        [
            "",
            "## 邊界與續跑",
            "",
            "- `batch_events.jsonl` 是 append-only 歷史；`execution_ledger.csv` 只是 current view。",
            "- 每個新 attempt 使用新的 `attempt_NNN` 目錄，既有 raw report、logs、summary 與 metadata 不覆寫。",
            "- 正式 reviewer evidence packet 尚未建立；本目錄是 coordinator 區域，不宣稱已盲化。",
            "- 本批次不修改 annotation CSV 或 human review log，也不執行人工 Gold review／SLB 訓練。",
            "- 若 MobSF 仍為 pending／blocked，先以正常流程設定 `$env:MOBSF_API_KEY`，再執行：",
            "",
            "```powershell",
            ".\\.venv\\Scripts\\python.exe -m app.tools.golden_batch --tools mobsf",
            "```",
        ]
    )
    (output_dir / "BATCH_EXECUTION_REPORT.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--membership-csv",
        type=Path,
        default=Path("dataset/authz_v2/golden_50_membership.csv"),
    )
    parser.add_argument(
        "--selection-metadata",
        type=Path,
        default=Path("dataset/authz_v2/golden_50_selection_metadata.json"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output/framework_poc/golden_50_v1"),
    )
    parser.add_argument("--tools", nargs="+", choices=TOOLS, default=list(TOOLS))
    parser.add_argument("--max-work-items", type=int)
    parser.add_argument("--max-transient-retries", type=int, default=1)
    parser.add_argument("--systemic-failure-threshold", type=int, default=2)
    parser.add_argument("--mobsf-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--mobsf-container", default="mobsf-authz-poc")
    parser.add_argument("--mobsf-api-key-env", default="MOBSF_API_KEY")
    parser.add_argument("--mobsf-request-timeout", type=int, default=600)
    parser.add_argument(
        "--flowdroid-jar",
        type=Path,
        default=Path(
            ".external-tools/flowdroid/2.15.1/"
            "soot-infoflow-cmd-2.15.1-jar-with-dependencies.jar"
        ),
    )
    parser.add_argument(
        "--platforms-dir",
        type=Path,
        default=Path(
            "C:/Users/s1002/AppData/Local/Android/Sdk/platforms/android-37.1/android.jar"
        ),
    )
    parser.add_argument(
        "--sources-sinks",
        type=Path,
        default=Path("config/flowdroid/authz-v1-sources-sinks.txt"),
    )
    parser.add_argument("--java", default="java")
    parser.add_argument("--java-max-heap", default="6g")
    parser.add_argument("--callback-timeout", type=int, default=60)
    parser.add_argument("--dataflow-timeout", type=int, default=120)
    parser.add_argument("--result-timeout", type=int, default=30)
    parser.add_argument("--process-timeout", type=int, default=600)
    parser.add_argument("--max-threads", type=int, default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    entries, audit = load_frozen_membership(
        args.membership_csv, args.selection_metadata
    )
    configs = build_tool_configs(args)
    rows = run_batch(
        entries=entries,
        membership_audit=audit,
        output_dir=args.output_dir,
        configs=configs,
        tools=args.tools,
        max_work_items=args.max_work_items,
        max_transient_retries=args.max_transient_retries,
        systemic_failure_threshold=args.systemic_failure_threshold,
    )
    print(
        json.dumps(
            {
                "membership_sha256": audit["membership_sha256"],
                "status_counts": _status_counts(rows),
                "output_dir": str(args.output_dir.resolve()),
                "credentials_persisted": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
