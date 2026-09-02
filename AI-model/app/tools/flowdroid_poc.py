"""執行版本固定、輸出可稽核的單一 APK FlowDroid PoC。

本工具只產生候選的 input-to-sensitive-effect path evidence，不產生任何
``gold_label``、``observed_label`` 或 ``revised_label``。FlowDroid 沒有找到
結果也不能被解讀成 authorization-risk negative。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence


SCHEMA_VERSION = "flowdroid-authz-poc-v1"
FLOWDROID_VERSION = "2.15.1"
FLOWDROID_JAR_SHA256 = (
    "51dadead47a173c494c2fa4855b1e8bd3b54e702a2c4b5ed58e60153009ae218"
)
HASH_CHUNK_SIZE = 1024 * 1024
ATTEMPT_FIELDS = (
    "apk_path",
    "apk_sha256",
    "status",
    "exit_code",
    "duration_seconds",
    "result_xml_path",
    "result_xml_exists",
    "termination_state",
    "finding_count",
    "stdout_path",
    "stderr_path",
    "error_type",
    "error_message",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(HASH_CHUNK_SIZE):
            digest.update(block)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"{label} 不存在或不是檔案：{resolved}")
    return resolved


def require_platforms_path(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.is_file() and resolved.name == "android.jar":
        return resolved
    if not resolved.is_dir():
        raise FileNotFoundError(
            f"Android platforms 目錄或 android.jar 不存在：{resolved}"
        )
    platform_jars = [
        child / "android.jar"
        for child in resolved.iterdir()
        if child.is_dir() and child.name.startswith("android-")
    ]
    if not any(candidate.is_file() for candidate in platform_jars):
        raise ValueError(f"Android platforms 目錄內找不到可用的 android.jar：{resolved}")
    return resolved


def prepare_output_dir(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.exists() and any(resolved.iterdir()):
        raise FileExistsError(f"拒絕覆寫非空白輸出目錄：{resolved}")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def build_command(
    *,
    java: str,
    jar: Path,
    apk: Path,
    platforms_dir: Path,
    sources_sinks: Path,
    result_xml: Path,
    callback_timeout_seconds: int,
    dataflow_timeout_seconds: int,
    result_timeout_seconds: int,
    max_threads: int,
) -> list[str]:
    """建立固定且不經 shell 展開的 FlowDroid 命令。"""
    return [
        java,
        "-jar",
        str(jar),
        "-a",
        str(apk),
        "-p",
        str(platforms_dir),
        "-s",
        str(sources_sinks),
        "-o",
        str(result_xml),
        "-tw",
        "NONE",
        "-cp",
        "-ps",
        "-ol",
        "-ct",
        str(callback_timeout_seconds),
        "-dt",
        str(dataflow_timeout_seconds),
        "-rt",
        str(result_timeout_seconds),
        "-mt",
        str(max_threads),
    ]


def _write_text(path: Path, value: str | bytes | None) -> None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    path.write_text(value or "", encoding="utf-8")


def _write_attempt(path: Path, attempt: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ATTEMPT_FIELDS)
        writer.writeheader()
        writer.writerow({field: attempt.get(field, "") for field in ATTEMPT_FIELDS})


def inspect_result_xml(path: Path) -> tuple[str, int]:
    root = ET.parse(path).getroot()
    termination_state = root.attrib.get("TerminationState", "")
    finding_count = len(root.findall("./Results/Result"))
    return termination_state, finding_count


def run_flowdroid(
    *,
    jar: Path,
    apk: Path,
    platforms_dir: Path,
    sources_sinks: Path,
    output_dir: Path,
    java: str = "java",
    callback_timeout_seconds: int = 60,
    dataflow_timeout_seconds: int = 120,
    result_timeout_seconds: int = 30,
    process_timeout_seconds: int = 300,
    max_threads: int = 1,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """執行一次 FlowDroid，保留 raw output 與完整 provenance。"""
    jar = require_file(jar, "FlowDroid JAR")
    apk = require_file(apk, "APK")
    platforms_dir = require_platforms_path(platforms_dir)
    sources_sinks = require_file(sources_sinks, "Sources/Sinks 設定")

    jar_sha256 = sha256_file(jar)
    if jar_sha256 != FLOWDROID_JAR_SHA256:
        raise ValueError(
            "FlowDroid JAR SHA-256 不符："
            f"expected={FLOWDROID_JAR_SHA256}, actual={jar_sha256}"
        )

    output_dir = prepare_output_dir(output_dir)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir()
    result_xml = raw_dir / "flowdroid.xml"
    stdout_path = output_dir / "stdout.log"
    stderr_path = output_dir / "stderr.log"
    attempts_path = output_dir / "attempts.csv"
    metadata_path = output_dir / "run_metadata.json"

    command = build_command(
        java=java,
        jar=jar,
        apk=apk,
        platforms_dir=platforms_dir,
        sources_sinks=sources_sinks,
        result_xml=result_xml,
        callback_timeout_seconds=callback_timeout_seconds,
        dataflow_timeout_seconds=dataflow_timeout_seconds,
        result_timeout_seconds=result_timeout_seconds,
        max_threads=max_threads,
    )
    started_at = _utc_now()
    start = time.perf_counter()
    status = "analysis_failed"
    exit_code: int | str = ""
    error_type = ""
    error_message = ""
    termination_state = ""
    finding_count: int | str = ""

    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=process_timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        _write_text(stdout_path, completed.stdout)
        _write_text(stderr_path, completed.stderr)
        combined_logs = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        internal_failure = "The data flow analysis has failed." in combined_logs
        if completed.returncode == 0 and result_xml.is_file():
            try:
                termination_state, finding_count = inspect_result_xml(result_xml)
            except (ET.ParseError, OSError) as exc:
                status = "invalid_result_artifact"
                error_type = type(exc).__name__
                error_message = str(exc)
            else:
                status = "success" if termination_state == "Success" else "incomplete"
                if status == "incomplete":
                    error_type = "IncompleteTermination"
                    error_message = f"FlowDroid TerminationState={termination_state or '<missing>'}"
        elif completed.returncode == 0 and internal_failure:
            status = "analysis_failed"
            error_type = "FlowDroidInternalFailure"
            error_message = "FlowDroid 回傳 0，但 log 明示 data flow analysis failed。"
        elif completed.returncode == 0:
            status = "no_result_artifact"
            error_type = "MissingResultArtifact"
            error_message = "FlowDroid exit code 為 0，但沒有產生 result XML。"
        else:
            error_type = "NonZeroExit"
            error_message = f"FlowDroid exit code={completed.returncode}"
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        error_type = type(exc).__name__
        error_message = f"process timeout after {process_timeout_seconds} seconds"
        _write_text(stdout_path, exc.stdout)
        _write_text(stderr_path, exc.stderr)
    except OSError as exc:
        status = "launch_failed"
        error_type = type(exc).__name__
        error_message = str(exc)
        _write_text(stdout_path, "")
        _write_text(stderr_path, str(exc))

    duration = time.perf_counter() - start
    attempt = {
        "apk_path": str(apk),
        "apk_sha256": sha256_file(apk),
        "status": status,
        "exit_code": exit_code,
        "duration_seconds": f"{duration:.6f}",
        "result_xml_path": str(result_xml),
        "result_xml_exists": result_xml.is_file(),
        "termination_state": termination_state,
        "finding_count": finding_count,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "error_type": error_type,
        "error_message": error_message,
    }
    _write_attempt(attempts_path, attempt)

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "started_at_utc": started_at,
        "completed_at_utc": _utc_now(),
        "tool": {
            "name": "FlowDroid",
            "version": FLOWDROID_VERSION,
            "jar_path": str(jar),
            "jar_sha256": jar_sha256,
        },
        "input": {
            "apk_path": str(apk),
            "apk_sha256": attempt["apk_sha256"],
            "android_platforms_path": str(platforms_dir),
            "sources_sinks_path": str(sources_sinks),
            "sources_sinks_sha256": sha256_file(sources_sinks),
        },
        "execution": {
            "command": command,
            "shell": False,
            "callback_timeout_seconds": callback_timeout_seconds,
            "dataflow_timeout_seconds": dataflow_timeout_seconds,
            "result_timeout_seconds": result_timeout_seconds,
            "process_timeout_seconds": process_timeout_seconds,
            "max_threads": max_threads,
        },
        "result": {
            "status": status,
            "exit_code": exit_code,
            "duration_seconds": duration,
            "result_xml_exists": result_xml.is_file(),
            "termination_state": termination_state,
            "finding_count": finding_count,
            "error_type": error_type,
            "error_message": error_message,
        },
        "semantics": {
            "output_role": "candidate_evidence",
            "absence_is_negative_label": False,
            "produces_ground_truth": False,
        },
    }
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="執行可稽核的單一 APK FlowDroid authorization-evidence PoC。"
    )
    parser.add_argument("--jar", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--platforms-dir", type=Path, required=True)
    parser.add_argument("--sources-sinks", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--callback-timeout", type=int, default=60)
    parser.add_argument("--dataflow-timeout", type=int, default=120)
    parser.add_argument("--result-timeout", type=int, default=30)
    parser.add_argument("--process-timeout", type=int, default=300)
    parser.add_argument("--max-threads", type=int, default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metadata = run_flowdroid(
        jar=args.jar,
        apk=args.apk,
        platforms_dir=args.platforms_dir,
        sources_sinks=args.sources_sinks,
        output_dir=args.output_dir,
        java=args.java,
        callback_timeout_seconds=args.callback_timeout,
        dataflow_timeout_seconds=args.dataflow_timeout,
        result_timeout_seconds=args.result_timeout,
        process_timeout_seconds=args.process_timeout,
        max_threads=args.max_threads,
    )
    print(json.dumps(metadata["result"], ensure_ascii=False, indent=2))
    return 0 if metadata["result"]["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
