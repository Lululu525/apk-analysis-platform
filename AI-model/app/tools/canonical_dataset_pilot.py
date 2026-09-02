"""唯讀消費 canonical APK dataset，執行可重現的小型解析 pilot。

這個工具只用 canonical CSV 決定成員，並只讀取每列指定的 ``source_path``。
它不會掃描來源資料夾補樣，也不會修改 canonical CSV 或 APK。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean, median
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from .parse_manifest import build_model_features


SCHEMA_VERSION = "canonical-apk-pilot-v3"
DEFAULT_LABELS = ("benign", "non_benign")


@dataclass(frozen=True)
class StratumSpec:
    name: str
    source_dataset: Optional[str] = None
    original_label: Optional[str] = None
    binary_label: Optional[str] = None

    def matches(self, row: Mapping[str, str]) -> bool:
        return all(
            expected is None or row.get(field) == expected
            for field, expected in (
                ("source_dataset", self.source_dataset),
                ("original_label", self.original_label),
                ("binary_label", self.binary_label),
            )
        )

    def reason(self) -> str:
        criteria = [
            f"{field}={expected}"
            for field, expected in (
                ("source_dataset", self.source_dataset),
                ("original_label", self.original_label),
                ("binary_label", self.binary_label),
            )
            if expected is not None
        ]
        return " AND ".join(criteria)


DEFAULT_STRATA = (
    StratumSpec("fdroid_benign", source_dataset="F-Droid", original_label="Benign"),
    StratumSpec("maldroid_benign", source_dataset="MalDroid-2020", original_label="Benign"),
    StratumSpec("maldroid_adware", source_dataset="MalDroid-2020", original_label="Adware"),
    StratumSpec("maldroid_banking", source_dataset="MalDroid-2020", original_label="Banking"),
    StratumSpec("maldroid_riskware", source_dataset="MalDroid-2020", original_label="Riskware"),
    StratumSpec("maldroid_sms", source_dataset="MalDroid-2020", original_label="SMS"),
)

ENTRY_METHODS = {
    "activity": {"onCreate", "onNewIntent"},
    "service": {"onStartCommand", "onBind"},
    "receiver": {"onReceive"},
    "provider": {"query", "insert", "update", "delete", "openFile", "call"},
}
REQUIRED_COLUMNS = {
    "sample_id",
    "sha256",
    "source_dataset",
    "source_path",
    "original_label",
    "binary_label",
}
SHA256_HEX_LENGTH = 64
HASH_CHUNK_SIZE = 1024 * 1024

RESULT_FIELDS = [
    "selection_rank",
    "stratum",
    "stratum_reason",
    "stratum_rank",
    "selection_score",
    "canonical_row_number",
    "sample_id",
    "expected_sha256",
    "computed_sha256",
    "source_dataset",
    "original_label",
    "binary_label",
    "source_path",
    "expected_size_bytes",
    "actual_size_bytes",
    "size_match",
    "source_exists",
    "source_is_file",
    "sha256_match",
    "source_stat_unchanged",
    "validation_status",
    "parse_attempted",
    "parse_status",
    "error_code",
    "error_message",
    "hash_seconds",
    "parse_seconds",
    "total_seconds",
    "canonical_package_name",
    "parsed_package_name",
    "package_name_match",
    "component_total_count",
    "component_activity_count",
    "component_service_count",
    "component_provider_count",
    "component_receiver_count",
    "component_evidence_row_count",
    "manifest_resolution_path_count",
    "exported_component_count",
    "unique_exported_component_name_count",
    "exported_unprotected_count",
    "sensitive_api_scan_status",
    "sensitive_api_scan_error_count",
    "sensitive_api_call_site_count",
    "sensitive_api_caller_count",
    "sensitive_api_direct_component_caller_count",
    "sensitive_api_direct_entry_caller_count",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _silence_androguard_logs() -> None:
    """停用 Androguard 的逐指令 DEBUG/INFO，避免 console I/O 污染計時。"""
    try:
        from loguru import logger
    except ImportError:
        return
    logger.disable("androguard")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(HASH_CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
            total += len(block)
    return digest.hexdigest(), total


def _is_sha256(value: str) -> bool:
    if len(value) != SHA256_HEX_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def load_canonical_csv(path: Path) -> tuple[List[Dict[str, str]], List[str]]:
    """以唯讀模式載入並驗證 canonical membership CSV。"""
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        missing = sorted(REQUIRED_COLUMNS - set(fieldnames))
        if missing:
            raise ValueError(f"canonical CSV 缺少必要欄位: {', '.join(missing)}")

        rows: List[Dict[str, str]] = []
        seen_sha256: set[str] = set()
        seen_sample_ids: set[str] = set()
        for row_number, raw_row in enumerate(reader, start=2):
            row = {key: (value or "") for key, value in raw_row.items() if key is not None}
            sha256 = row["sha256"].strip().lower()
            sample_id = row["sample_id"].strip()
            source_path = row["source_path"].strip()
            binary_label = row["binary_label"].strip()

            if not _is_sha256(sha256):
                raise ValueError(f"第 {row_number} 列 sha256 不是 64 位十六進位值")
            if sample_id != f"sha256:{sha256}":
                raise ValueError(f"第 {row_number} 列 sample_id 與 sha256 不一致")
            if not source_path:
                raise ValueError(f"第 {row_number} 列 source_path 為空")
            if not binary_label:
                raise ValueError(f"第 {row_number} 列 binary_label 為空")
            if sha256 in seen_sha256:
                raise ValueError(f"第 {row_number} 列出現重複 sha256: {sha256}")
            if sample_id in seen_sample_ids:
                raise ValueError(f"第 {row_number} 列出現重複 sample_id: {sample_id}")
            if row.get("canonical_status") and row["canonical_status"] != "included":
                raise ValueError(
                    f"第 {row_number} 列 canonical_status 不是 included: "
                    f"{row['canonical_status']}"
                )

            row["sha256"] = sha256
            row["sample_id"] = sample_id
            row["source_path"] = source_path
            row["binary_label"] = binary_label
            row["_canonical_row_number"] = str(row_number)
            rows.append(row)
            seen_sha256.add(sha256)
            seen_sample_ids.add(sample_id)

    if not rows:
        raise ValueError("canonical CSV 沒有任何資料列")
    return rows, fieldnames


def select_balanced_samples(
    rows: Sequence[Mapping[str, str]],
    sample_size: int,
    seed: str,
    labels: Sequence[str] = DEFAULT_LABELS,
) -> List[Dict[str, str]]:
    """相容舊呼叫端：依 binary_label 等額分層抽樣。"""
    strata = tuple(StratumSpec(label, binary_label=label) for label in labels)
    return select_stratified_samples(rows, sample_size, seed, strata)


def select_stratified_samples(
    rows: Sequence[Mapping[str, str]],
    sample_size: int,
    seed: str,
    strata: Sequence[StratumSpec] = DEFAULT_STRATA,
) -> List[Dict[str, str]]:
    """依明確 source/original-label strata 做可重現、等額抽樣。"""
    if sample_size <= 0:
        raise ValueError("sample_size 必須大於 0")
    if not strata or len({spec.name for spec in strata}) != len(strata):
        raise ValueError("strata 不可為空，且 name 不可重複")
    if sample_size % len(strata) != 0:
        raise ValueError("sample_size 必須可被分層標籤數整除")

    per_stratum = sample_size // len(strata)
    selected: List[Dict[str, str]] = []
    for spec in strata:
        candidates: List[tuple[str, Mapping[str, str]]] = []
        for row in rows:
            if not spec.matches(row):
                continue
            score_input = f"{seed}\0{spec.name}\0{row['sha256']}".encode("utf-8")
            score = hashlib.sha256(score_input).hexdigest()
            candidates.append((score, row))
        if len(candidates) < per_stratum:
            raise ValueError(
                f"分層 {spec.name!r}（{spec.reason()}）只有 {len(candidates)} 筆，"
                f"少於需要的 {per_stratum} 筆"
            )

        candidates.sort(key=lambda item: (item[0], item[1]["sha256"]))
        for stratum_rank, (score, row) in enumerate(candidates[:per_stratum], start=1):
            item = dict(row)
            item["_stratum"] = spec.name
            item["_stratum_reason"] = spec.reason()
            item["_stratum_rank"] = str(stratum_rank)
            item["_selection_score"] = score
            selected.append(item)

    selected.sort(key=lambda row: (row["_selection_score"], row["sha256"]))
    for selection_rank, row in enumerate(selected, start=1):
        row["_selection_rank"] = str(selection_rank)
    return selected


def _prepare_output_dir(output_dir: Path) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"輸出目錄不是空的，拒絕覆寫: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)


def _write_selection_csv(
    path: Path,
    selected: Sequence[Mapping[str, str]],
    canonical_fields: Sequence[str],
) -> None:
    selection_fields = [
        "selection_rank",
        "stratum",
        "stratum_reason",
        "stratum_rank",
        "selection_score",
        "canonical_row_number",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=selection_fields + list(canonical_fields))
        writer.writeheader()
        for row in selected:
            writer.writerow({
                "selection_rank": row["_selection_rank"],
                "stratum": row["_stratum"],
                "stratum_reason": row["_stratum_reason"],
                "stratum_rank": row["_stratum_rank"],
                "selection_score": row["_selection_score"],
                "canonical_row_number": row["_canonical_row_number"],
                **{field: row.get(field, "") for field in canonical_fields},
            })


def _append_evidence(
    handle: Any,
    evidence_kind: str,
    canonical_row: Mapping[str, str],
    evidence_rows: Iterable[Mapping[str, Any]],
) -> int:
    count = 0
    for evidence in evidence_rows:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": evidence_kind,
            "sample_id": canonical_row["sample_id"],
            "sha256": canonical_row["sha256"],
            "source_dataset": canonical_row["source_dataset"],
            "original_label": canonical_row.get("original_label", ""),
            "binary_label": canonical_row["binary_label"],
            "evidence": evidence,
        }
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        count += 1
    handle.flush()
    return count


def _component_counts(app_summary: Mapping[str, Any]) -> Dict[str, int]:
    components = app_summary.get("components") or {}
    counts = {
        "activity": len(components.get("activities") or []),
        "service": len(components.get("services") or []),
        "provider": len(components.get("providers") or []),
        "receiver": len(components.get("receivers") or []),
    }
    counts["total"] = sum(counts.values())
    return counts


def _component_type_index(app_summary: Mapping[str, Any]) -> Dict[str, str]:
    components = app_summary.get("components") or {}
    index: Dict[str, str] = {}
    for plural, component_type in (
        ("activities", "activity"),
        ("services", "service"),
        ("providers", "provider"),
        ("receivers", "receiver"),
    ):
        for name in components.get(plural) or []:
            if name:
                index[str(name)] = component_type
    return index


def _dotted_class_name(raw_name: Any) -> str:
    name = str(raw_name or "").strip()
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _annotate_sensitive_callers(
    app_summary: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """加上可稽核的 direct identity match；不建立跨方法 call graph。"""
    component_types = _component_type_index(app_summary)
    annotated: List[Dict[str, Any]] = []
    for raw in app_summary.get("sensitive_api_callers") or []:
        row = dict(raw)
        caller_component = _dotted_class_name(row.get("caller_class"))
        component_type = component_types.get(caller_component)
        entry_method_match = (
            component_type is not None
            and str(row.get("caller_method") or "")
            in ENTRY_METHODS.get(component_type, set())
        )
        row.update({
            "caller_component_name": caller_component,
            "matched_manifest_component": component_type is not None,
            "matched_component_type": component_type,
            "matched_lifecycle_entry_method": entry_method_match,
            "linkage_status": (
                "direct_entry_caller"
                if entry_method_match
                else "component_class_caller"
                if component_type is not None
                else "unlinked_caller"
            ),
            "linkage_limit": (
                "只以 caller class/method 與 Manifest component/lifecycle 名稱直接比對；"
                "未建立跨方法 call graph。"
            ),
        })
        annotated.append(row)
    return annotated


def _distinct_caller_count(rows: Sequence[Mapping[str, Any]]) -> int:
    return len({
        (
            str(row.get("caller_class") or ""),
            str(row.get("caller_method") or ""),
            str(row.get("caller_descriptor") or ""),
        )
        for row in rows
    })


def _safe_expected_size(raw_value: str) -> Optional[int]:
    if not raw_value:
        return None
    try:
        value = int(raw_value)
    except ValueError:
        return None
    return value if value >= 0 else None


def _parse_error_code(exc: Exception) -> str:
    message = str(exc).lower()
    if "codec can't decode" in message or "unicode decode" in message:
        return "parse_encoding_error"
    if "invalid instruction" in message or "invalidinstruction" in message:
        return "parse_invalid_bytecode"
    return "parse_error"


def _stat_signature(stat_result: os.stat_result) -> tuple[int, int]:
    return stat_result.st_size, stat_result.st_mtime_ns


def _empty_result(row: Mapping[str, str]) -> Dict[str, Any]:
    return {
        "selection_rank": row["_selection_rank"],
        "stratum": row["_stratum"],
        "stratum_reason": row["_stratum_reason"],
        "stratum_rank": row["_stratum_rank"],
        "selection_score": row["_selection_score"],
        "canonical_row_number": row["_canonical_row_number"],
        "sample_id": row["sample_id"],
        "expected_sha256": row["sha256"],
        "computed_sha256": "",
        "source_dataset": row["source_dataset"],
        "original_label": row.get("original_label", ""),
        "binary_label": row["binary_label"],
        "source_path": row["source_path"],
        "expected_size_bytes": row.get("size_bytes", ""),
        "actual_size_bytes": "",
        "size_match": "",
        "source_exists": False,
        "source_is_file": False,
        "sha256_match": False,
        "source_stat_unchanged": "",
        "validation_status": "not_checked",
        "parse_attempted": False,
        "parse_status": "skipped",
        "error_code": "",
        "error_message": "",
        "hash_seconds": 0.0,
        "parse_seconds": 0.0,
        "total_seconds": 0.0,
        "canonical_package_name": row.get("package_name", ""),
        "parsed_package_name": "",
        "package_name_match": "",
        "component_total_count": 0,
        "component_activity_count": 0,
        "component_service_count": 0,
        "component_provider_count": 0,
        "component_receiver_count": 0,
        "component_evidence_row_count": 0,
        "manifest_resolution_path_count": 0,
        "exported_component_count": 0,
        "unique_exported_component_name_count": 0,
        "exported_unprotected_count": 0,
        "sensitive_api_scan_status": "not_attempted",
        "sensitive_api_scan_error_count": 0,
        "sensitive_api_call_site_count": 0,
        "sensitive_api_caller_count": 0,
        "sensitive_api_direct_component_caller_count": 0,
        "sensitive_api_direct_entry_caller_count": 0,
    }


def _process_sample(
    row: Mapping[str, str],
    component_handle: Any,
    path_handle: Any,
    sensitive_caller_handle: Any,
    feature_builder: Callable[[Path, Optional[str]], Mapping[str, Any]],
) -> Dict[str, Any]:
    started = time.perf_counter()
    result = _empty_result(row)
    source_path = Path(row["source_path"])
    result["source_exists"] = source_path.exists()
    if not result["source_exists"]:
        result.update({
            "validation_status": "source_missing",
            "error_code": "source_missing",
            "error_message": "source_path 不存在",
        })
        result["total_seconds"] = time.perf_counter() - started
        return result

    result["source_is_file"] = source_path.is_file()
    if not result["source_is_file"]:
        result.update({
            "validation_status": "source_not_file",
            "error_code": "source_not_file",
            "error_message": "source_path 不是一般檔案",
        })
        result["total_seconds"] = time.perf_counter() - started
        return result

    stat_before = source_path.stat()
    result["actual_size_bytes"] = stat_before.st_size
    expected_size = _safe_expected_size(row.get("size_bytes", ""))
    result["size_match"] = "" if expected_size is None else expected_size == stat_before.st_size

    hash_started = time.perf_counter()
    try:
        computed_sha256, bytes_read = _sha256_file(source_path)
    except OSError as exc:
        result.update({
            "validation_status": "source_read_error",
            "error_code": "source_read_error",
            "error_message": f"{type(exc).__name__}: {exc}",
            "hash_seconds": time.perf_counter() - hash_started,
        })
        result["total_seconds"] = time.perf_counter() - started
        return result

    result["hash_seconds"] = time.perf_counter() - hash_started
    result["computed_sha256"] = computed_sha256
    result["actual_size_bytes"] = bytes_read
    result["sha256_match"] = computed_sha256 == row["sha256"]
    if not result["sha256_match"]:
        result.update({
            "validation_status": "sha256_mismatch",
            "error_code": "sha256_mismatch",
            "error_message": "重算 SHA-256 與 canonical CSV 不符，未送入解析器",
        })
        result["source_stat_unchanged"] = (
            _stat_signature(stat_before) == _stat_signature(source_path.stat())
        )
        result["total_seconds"] = time.perf_counter() - started
        return result

    result["validation_status"] = "valid"
    result["parse_attempted"] = True
    parse_started = time.perf_counter()
    try:
        features = feature_builder(source_path, row["sample_id"])
        filter_rows = list(features.get("filter_rows") or [])
        resolution_rows = list(features.get("resolution_rows") or [])
        app_summary = features.get("app_summary") or {}
        sensitive_callers = _annotate_sensitive_callers(app_summary)
        direct_component_callers = [
            caller
            for caller in sensitive_callers
            if caller["matched_manifest_component"]
        ]
        direct_entry_callers = [
            caller
            for caller in sensitive_callers
            if caller["matched_lifecycle_entry_method"]
        ]
        counts = _component_counts(app_summary)
        exported_component_rows = [
            filter_row
            for filter_row in filter_rows
            if filter_row.get("exported") is True
        ]
        unique_exported_component_names = {
            str(filter_row.get("component_name") or "")
            for filter_row in exported_component_rows
        }

        result.update({
            "parse_status": "success",
            "parsed_package_name": app_summary.get("package_name") or "",
            "component_total_count": counts["total"],
            "component_activity_count": counts["activity"],
            "component_service_count": counts["service"],
            "component_provider_count": counts["provider"],
            "component_receiver_count": counts["receiver"],
            "component_evidence_row_count": len(filter_rows),
            "manifest_resolution_path_count": len(resolution_rows),
            "exported_component_count": len(exported_component_rows),
            "unique_exported_component_name_count": len(
                unique_exported_component_names
            ),
            "exported_unprotected_count": len(app_summary.get("exported_unprotected") or []),
            "sensitive_api_scan_status": app_summary.get("sensitive_api_scan_status") or "unknown",
            "sensitive_api_scan_error_count": int(
                app_summary.get("sensitive_api_scan_error_count") or 0
            ),
            "sensitive_api_call_site_count": len(sensitive_callers),
            "sensitive_api_caller_count": _distinct_caller_count(sensitive_callers),
            "sensitive_api_direct_component_caller_count": _distinct_caller_count(
                direct_component_callers
            ),
            "sensitive_api_direct_entry_caller_count": _distinct_caller_count(
                direct_entry_callers
            ),
        })
        canonical_package = result["canonical_package_name"]
        parsed_package = result["parsed_package_name"]
        result["package_name_match"] = (
            "" if not canonical_package or not parsed_package
            else canonical_package == parsed_package
        )
        _append_evidence(
            component_handle, "component_filter_row", row, filter_rows
        )
        _append_evidence(
            path_handle, "manifest_resolution_candidate", row, resolution_rows
        )
        _append_evidence(
            sensitive_caller_handle,
            "sensitive_api_caller",
            row,
            sensitive_callers,
        )
    except Exception as exc:
        result.update({
            "parse_status": "failed",
            "error_code": _parse_error_code(exc),
            "error_message": f"{type(exc).__name__}: {exc}"[:2000],
        })
    finally:
        result["parse_seconds"] = time.perf_counter() - parse_started
        try:
            result["source_stat_unchanged"] = (
                _stat_signature(stat_before) == _stat_signature(source_path.stat())
            )
        except OSError:
            result["source_stat_unchanged"] = False
        result["total_seconds"] = time.perf_counter() - started
    return result


def _percentile(values: Sequence[float], percentile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _timing_summary(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "total": 0.0,
            "mean": None,
            "p50": None,
            "p95": None,
            "max": None,
        }
    return {
        "count": len(values),
        "total": sum(values),
        "mean": fmean(values),
        "p50": median(values),
        "p95": _percentile(values, 0.95),
        "max": max(values),
    }


def _slowest_sample(
    rows: Sequence[Mapping[str, Any]],
    field: str,
) -> Optional[Dict[str, Any]]:
    if not rows:
        return None
    slowest = max(rows, key=lambda row: float(row[field]))
    return {
        "sample_id": slowest["sample_id"],
        "selection_rank": int(slowest["selection_rank"]),
        "stratum": slowest["stratum"],
        "parse_status": slowest["parse_status"],
        field: float(slowest[field]),
    }


def _selected_fingerprint(selected: Sequence[Mapping[str, str]]) -> str:
    payload = "".join(
        f"{row['_selection_rank']},{row['sample_id']},{row['_selection_score']}\n"
        for row in selected
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _build_summary(
    *,
    canonical_csv: Path,
    canonical_stat_before: os.stat_result,
    canonical_sha256_before: str,
    canonical_sha256_after: str,
    canonical_record_count: int,
    canonical_label_counts: Mapping[str, int],
    selected: Sequence[Mapping[str, str]],
    results: Sequence[Mapping[str, Any]],
    seed: str,
    strata: Sequence[StratumSpec],
    started_at: str,
    completed_at: str,
    duration_seconds: float,
) -> Dict[str, Any]:
    canonical_stat_after = canonical_csv.stat()
    selected_count = len(results)
    hash_verified = [row for row in results if row["sha256_match"]]
    parse_attempted = [row for row in results if row["parse_attempted"]]
    parse_success = [row for row in results if row["parse_status"] == "success"]
    error_counts = Counter(row["error_code"] for row in results if row["error_code"])
    source_dataset_counts = Counter(row["source_dataset"] for row in selected)
    selected_label_counts = Counter(row["binary_label"] for row in selected)
    selected_stratum_counts = Counter(row["_stratum"] for row in selected)
    scan_status_counts = Counter(
        str(row["sensitive_api_scan_status"]) for row in parse_success
    )
    sensitive_caller_count = sum(
        int(row["sensitive_api_caller_count"]) for row in parse_success
    )
    direct_entry_caller_count = sum(
        int(row["sensitive_api_direct_entry_caller_count"])
        for row in parse_success
    )
    manifest_candidate_count = sum(
        int(row["manifest_resolution_path_count"]) for row in parse_success
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "run_status": "complete",
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "duration_seconds": duration_seconds,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "input": {
            "canonical_csv": str(canonical_csv.resolve()),
            "canonical_record_count": canonical_record_count,
            "canonical_label_counts": dict(sorted(canonical_label_counts.items())),
            "canonical_csv_size_bytes": canonical_stat_before.st_size,
            "canonical_csv_mtime_ns_before": canonical_stat_before.st_mtime_ns,
            "canonical_csv_mtime_ns_after": canonical_stat_after.st_mtime_ns,
            "canonical_csv_sha256_before": canonical_sha256_before,
            "canonical_csv_sha256_after": canonical_sha256_after,
            "canonical_csv_unchanged": (
                canonical_sha256_before == canonical_sha256_after
                and _stat_signature(canonical_stat_before)
                == _stat_signature(canonical_stat_after)
            ),
        },
        "selection": {
            "algorithm": "每個明確 stratum 依 sha256(seed\\0stratum_name\\0sha256) 排序後等額取前 N 筆",
            "seed": seed,
            "strata": [
                {
                    "name": spec.name,
                    "source_dataset": spec.source_dataset,
                    "original_label": spec.original_label,
                    "binary_label": spec.binary_label,
                    "reason": spec.reason(),
                }
                for spec in strata
            ],
            "sample_size": len(selected),
            "per_stratum": len(selected) // len(strata),
            "selected_stratum_counts": dict(sorted(selected_stratum_counts.items())),
            "selected_label_counts": dict(sorted(selected_label_counts.items())),
            "selected_source_dataset_counts": dict(sorted(source_dataset_counts.items())),
            "selected_manifest_sha256": _selected_fingerprint(selected),
        },
        "validation": {
            "selected_count": selected_count,
            "source_exists_count": sum(bool(row["source_exists"]) for row in results),
            "source_file_count": sum(bool(row["source_is_file"]) for row in results),
            "sha256_match_count": len(hash_verified),
            "sha256_match_rate_selected": (
                len(hash_verified) / selected_count if selected_count else None
            ),
            "size_match_count": sum(row["size_match"] is True for row in results),
            "source_stat_unchanged_count": sum(
                row["source_stat_unchanged"] is True for row in results
            ),
            "error_counts": dict(sorted(error_counts.items())),
        },
        "parsing": {
            "attempted_count": len(parse_attempted),
            "success_count": len(parse_success),
            "failure_count": len(parse_attempted) - len(parse_success),
            "success_rate_selected": (
                len(parse_success) / selected_count if selected_count else None
            ),
            "success_rate_hash_verified": (
                len(parse_success) / len(hash_verified) if hash_verified else None
            ),
        },
        "timing_seconds": {
            "hash_selected": _timing_summary(
                [float(row["hash_seconds"]) for row in results if row["source_is_file"]]
            ),
            "parse_attempted": _timing_summary(
                [float(row["parse_seconds"]) for row in parse_attempted]
            ),
            "parse_success": _timing_summary(
                [float(row["parse_seconds"]) for row in parse_success]
            ),
            "total_selected": _timing_summary(
                [float(row["total_seconds"]) for row in results]
            ),
            "slowest_parse_attempted": _slowest_sample(
                parse_attempted, "parse_seconds"
            ),
            "slowest_parse_success": _slowest_sample(
                parse_success, "parse_seconds"
            ),
            "slowest_total_selected": _slowest_sample(
                results, "total_seconds"
            ),
            "percentile_method": "linear interpolation, zero-based index",
        },
        "evidence": {
            "component_total_count": sum(
                int(row["component_total_count"]) for row in parse_success
            ),
            "component_evidence_row_count": sum(
                int(row["component_evidence_row_count"]) for row in parse_success
            ),
            "manifest_resolution_path_count": manifest_candidate_count,
            "exported_component_count": sum(
                int(row["exported_component_count"]) for row in parse_success
            ),
            "unique_exported_component_name_count": sum(
                int(row["unique_exported_component_name_count"])
                for row in parse_success
            ),
            "exported_unprotected_component_count": sum(
                int(row["exported_unprotected_count"]) for row in parse_success
            ),
            "apps_with_component_evidence": sum(
                int(row["component_evidence_row_count"]) > 0 for row in parse_success
            ),
            "apps_with_manifest_resolution_paths": sum(
                int(row["manifest_resolution_path_count"]) > 0 for row in parse_success
            ),
            "mean_component_total_per_success": (
                fmean(int(row["component_total_count"]) for row in parse_success)
                if parse_success else None
            ),
            "mean_component_evidence_rows_per_success": (
                fmean(int(row["component_evidence_row_count"]) for row in parse_success)
                if parse_success else None
            ),
            "mean_manifest_resolution_paths_per_success": (
                fmean(int(row["manifest_resolution_path_count"]) for row in parse_success)
                if parse_success else None
            ),
            "sensitive_api_scan_status_counts": dict(sorted(scan_status_counts.items())),
            "sensitive_api_call_site_count": sum(
                int(row["sensitive_api_call_site_count"]) for row in parse_success
            ),
            "sensitive_api_caller_count": sensitive_caller_count,
            "apps_with_sensitive_api_callers": sum(
                int(row["sensitive_api_caller_count"]) > 0 for row in parse_success
            ),
            "sensitive_api_direct_component_caller_count": sum(
                int(row["sensitive_api_direct_component_caller_count"])
                for row in parse_success
            ),
            "sensitive_api_direct_entry_caller_count": direct_entry_caller_count,
            "sensitive_api_caller_without_direct_entry_link_count": (
                sensitive_caller_count - direct_entry_caller_count
            ),
            "entry_to_caller_linkage": (
                "只確認同一 class 中 lifecycle entry method 直接呼叫 sensitive API；"
                "尚無跨方法 call graph，因此不能證明一般 component entry-to-sink reachability。"
            ),
            "sensitive_api_interpretation_limit": (
                "計數是 allowlist 的靜態 XREF matches/candidates；部分 API（例如 "
                "Cursor.getString、FileInputStream）需要額外資料流脈絡，不能直接視為"
                "已確認 sensitive sink，更不能視為漏洞。"
            ),
            "interpretation_limit": (
                "manifest_resolution_path_count 是 manifest-only 1:1 resolution candidates；"
                "caller 為 UNKNOWN，不能視為 bytecode 已證實的實際 IPC 路徑。"
            ),
        },
        "unknown_abstain": {
            "parse_failed_apk_count": len(parse_attempted) - len(parse_success),
            "parsed_without_component_evidence_apk_count": sum(
                int(row["component_evidence_row_count"]) == 0
                for row in parse_success
            ),
            "sensitive_api_scan_not_complete_apk_count": sum(
                row["sensitive_api_scan_status"] != "complete"
                for row in parse_success
            ),
            "manifest_candidate_unknown_caller_count": manifest_candidate_count,
            "sensitive_caller_without_direct_entry_link_count": (
                sensitive_caller_count - direct_entry_caller_count
            ),
            "complete_scan_zero_allowlist_match_apk_count": sum(
                row["sensitive_api_scan_status"] == "complete"
                and int(row["sensitive_api_caller_count"]) == 0
                for row in parse_success
            ),
            "runtime_authorization_guard_unknown_caller_count": sensitive_caller_count,
            "attacker_input_controllability_unknown_caller_count": sensitive_caller_count,
            "static_coverage_limit": (
                "reflection、native code、runtime-loaded code 與 unresolved dynamic dispatch "
                "無法由本 pilot 完整排除；未偵測到不能解讀為不存在。"
            ),
            "label_policy": (
                "上述缺口不得強迫標成 negative；在 component-path authorization label 中"
                "保留 unknown/abstain。"
            ),
        },
    }


def _write_report(path: Path, summary: Mapping[str, Any]) -> None:
    validation = summary["validation"]
    parsing = summary["parsing"]
    timing = summary["timing_seconds"]
    evidence = summary["evidence"]
    unknown = summary["unknown_abstain"]

    def pct(value: Optional[float]) -> str:
        return "N/A" if value is None else f"{value:.2%}"

    def seconds(value: Optional[float]) -> str:
        return "N/A" if value is None else f"{value:.4f} 秒"

    text = f"""# Canonical APK 300 筆 pilot 報告

## 結果摘要

- Canonical CSV：`{summary['input']['canonical_csv']}`
- Canonical 總筆數：{summary['input']['canonical_record_count']}
- 抽樣：{summary['selection']['sample_size']} 筆；seed=`{summary['selection']['seed']}`；六層={summary['selection']['selected_stratum_counts']}
- `source_path` 存在：{validation['source_exists_count']} / {validation['selected_count']}
- SHA-256 相符：{validation['sha256_match_count']} / {validation['selected_count']}（{pct(validation['sha256_match_rate_selected'])}）
- 解析成功：{parsing['success_count']} / {parsing['attempted_count']} attempted；以 300 筆為分母為 {pct(parsing['success_rate_selected'])}
- 解析失敗分類：{validation['error_counts']}
- 成功解析時間：mean={seconds(timing['parse_success']['mean'])}、p50={seconds(timing['parse_success']['p50'])}、p95={seconds(timing['parse_success']['p95'])}、max={seconds(timing['parse_success']['max'])}、total={seconds(timing['parse_success']['total'])}
- 最慢成功樣本：{timing['slowest_parse_success']}
- 全部 Manifest components：{evidence['component_total_count']}
- Component evidence (`filter_rows`)：{evidence['component_evidence_row_count']}
- Exported component rows：{evidence['exported_component_count']}；唯一 `(APK, component_name)`：{evidence['unique_exported_component_name_count']}；其中現行規則視為 unprotected：{evidence['exported_unprotected_component_count']}
- Manifest-only path candidates (`resolution_rows`)：{evidence['manifest_resolution_path_count']}
- Sensitive API call sites：{evidence['sensitive_api_call_site_count']}
- Distinct sensitive API callers：{evidence['sensitive_api_caller_count']}；涵蓋 APK：{evidence['apps_with_sensitive_api_callers']}
- 可直接對到 Manifest component class 的 callers：{evidence['sensitive_api_direct_component_caller_count']}
- 可直接對到 lifecycle entry method 的 callers：{evidence['sensitive_api_direct_entry_caller_count']}
- Sensitive API scan 狀態：{evidence['sensitive_api_scan_status_counts']}
- Sensitive API 計數邊界：{evidence['sensitive_api_interpretation_limit']}
- Canonical CSV 前後未變：{summary['input']['canonical_csv_unchanged']}

## Component entry 與 sensitive caller 串接結論

{evidence['entry_to_caller_linkage']}

## 必須保留 unknown／abstain 的證據

- 解析失敗 APK：{unknown['parse_failed_apk_count']}
- 成功解析但沒有 component evidence 的 APK：{unknown['parsed_without_component_evidence_apk_count']}
- Sensitive API scan 非 complete APK：{unknown['sensitive_api_scan_not_complete_apk_count']}
- Scan complete 但沒有 allowlist match 的 APK：{unknown['complete_scan_zero_allowlist_match_apk_count']}（不能據此證明沒有 sensitive behavior）
- Caller identity 仍為未知的 manifest-only candidates：{unknown['manifest_candidate_unknown_caller_count']}
- 無法直接對到 lifecycle entry 的 sensitive callers：{unknown['sensitive_caller_without_direct_entry_link_count']}
- Runtime authorization guard 尚未分析的 sensitive callers：{unknown['runtime_authorization_guard_unknown_caller_count']}
- Attacker-controlled input 尚未分析的 sensitive callers：{unknown['attacker_input_controllability_unknown_caller_count']}
- 靜態覆蓋限制：{unknown['static_coverage_limit']}
- Label policy：{unknown['label_policy']}

## 指標邊界

`component_total_count` 是成功解析 APK 的全部 Manifest component 數量；`component_evidence_row_count` 只計現有模型可產生的 `filter_rows`。`manifest_resolution_path_count` 是 manifest-only、1:1 推導的 resolution candidate 數量，caller 欄位仍為 `<UNKNOWN>`，不可宣稱為 bytecode 或動態執行已證實的真實 IPC 路徑。

完整逐筆狀態請看 `sample_results.csv`；逐列證據請看 `component_evidence.jsonl`、`manifest_path_evidence.jsonl` 與 `sensitive_api_callers.jsonl`；機器可讀彙總請看 `summary.json`。
"""
    path.write_text(text, encoding="utf-8")


def run_pilot(
    canonical_csv: Path,
    output_dir: Path,
    *,
    sample_size: int = 300,
    seed: str = "20260823",
    strata: Sequence[StratumSpec] = DEFAULT_STRATA,
    progress_every: int = 10,
    feature_builder: Callable[[Path, Optional[str]], Mapping[str, Any]] = build_model_features,
) -> Dict[str, Any]:
    """執行 pilot 並回傳 summary；所有來源輸入皆只讀。"""
    if not canonical_csv.is_file():
        raise FileNotFoundError(f"找不到 canonical CSV: {canonical_csv}")
    if progress_every <= 0:
        raise ValueError("progress_every 必須大於 0")

    _prepare_output_dir(output_dir)
    _silence_androguard_logs()
    run_started_perf = time.perf_counter()
    started_at = _utc_now()
    canonical_stat_before = canonical_csv.stat()
    canonical_sha256_before, _ = _sha256_file(canonical_csv)
    rows, canonical_fields = load_canonical_csv(canonical_csv)
    canonical_label_counts = Counter(row["binary_label"] for row in rows)
    selected = select_stratified_samples(rows, sample_size, seed, strata)
    _write_selection_csv(output_dir / "selected_samples.csv", selected, canonical_fields)

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "run_status": "running",
        "started_at_utc": started_at,
        "canonical_csv": str(canonical_csv.resolve()),
        "canonical_csv_sha256": canonical_sha256_before,
        "sample_size": sample_size,
        "seed": seed,
        "strata": [
            {"name": spec.name, "reason": spec.reason()}
            for spec in strata
        ],
    }
    metadata_path = output_dir / "run_metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    results: List[Dict[str, Any]] = []
    with (
        (output_dir / "sample_results.csv").open(
            "w", encoding="utf-8-sig", newline=""
        ) as result_handle,
        (output_dir / "component_evidence.jsonl").open(
            "w", encoding="utf-8", newline="\n"
        ) as component_handle,
        (output_dir / "manifest_path_evidence.jsonl").open(
            "w", encoding="utf-8", newline="\n"
        ) as path_handle,
        (output_dir / "sensitive_api_callers.jsonl").open(
            "w", encoding="utf-8", newline="\n"
        ) as sensitive_caller_handle,
    ):
        result_writer = csv.DictWriter(result_handle, fieldnames=RESULT_FIELDS)
        result_writer.writeheader()
        result_handle.flush()

        for index, row in enumerate(selected, start=1):
            result = _process_sample(
                row,
                component_handle,
                path_handle,
                sensitive_caller_handle,
                feature_builder,
            )
            results.append(result)
            result_writer.writerow(result)
            result_handle.flush()

            if index == 1 or index % progress_every == 0 or index == len(selected):
                successes = sum(r["parse_status"] == "success" for r in results)
                print(
                    f"[{index}/{len(selected)}] parse_success={successes} "
                    f"last={result['parse_status']} sample_id={result['sample_id']}",
                    file=sys.stderr,
                    flush=True,
                )

    canonical_sha256_after, _ = _sha256_file(canonical_csv)
    completed_at = _utc_now()
    duration_seconds = time.perf_counter() - run_started_perf
    summary = _build_summary(
        canonical_csv=canonical_csv,
        canonical_stat_before=canonical_stat_before,
        canonical_sha256_before=canonical_sha256_before,
        canonical_sha256_after=canonical_sha256_after,
        canonical_record_count=len(rows),
        canonical_label_counts=canonical_label_counts,
        selected=selected,
        results=results,
        seed=seed,
        strata=strata,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_seconds,
    )
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_report(output_dir / "REPORT.md", summary)

    metadata.update({
        "run_status": "complete",
        "completed_at_utc": completed_at,
        "summary": "summary.json",
    })
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.tools.canonical_dataset_pilot",
        description=(
            "從 canonical_balanced_dataset.csv 依六個 source/original-label strata "
            "各等額抽樣並唯讀驗證/解析 APK，輸出 component、manifest-only path "
            "與 sensitive API caller pilot evidence。"
        ),
    )
    parser.add_argument("--canonical-csv", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--sample-size", type=int, default=300)
    parser.add_argument("--seed", default="20260823")
    parser.add_argument("--progress-every", type=int, default=10)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        summary = run_pilot(
            args.canonical_csv,
            args.output_dir,
            sample_size=args.sample_size,
            seed=args.seed,
            progress_every=args.progress_every,
        )
    except (FileNotFoundError, FileExistsError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
