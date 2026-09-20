"""建立 Golden-50 的盲化 reviewer evidence packets。

本模組只整理 reviewer 可見的身分、Manifest、caller/sink、source locator、
FlowDroid trace 與 coverage limitation。它不推導 R/I/S/A、不產生 Gold label，
也不修改 frozen membership、annotation placeholder 或 append-only review log。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .golden_batch import (
    EXPECTED_MEMBERSHIP_CSV_SHA256,
    EXPECTED_MEMBERSHIP_SHA256,
    MEMBERSHIP_VERSION,
    MembershipEntry,
    canonical_fingerprint,
    load_frozen_membership,
    sha256_file,
    taipei_now,
)
from .mobsf_poc import validate_base_url


SCHEMA_VERSION = "golden-review-packet-v1"
COLLECTION_SCHEMA_VERSION = "golden-review-packet-collection-v1"
MATERIALIZATION_VERSION = "golden-50-review-packets-v1"
SPEC_VERSION = "authz-label-spec-v0.2-meeting-approved"
GUIDE_VERSION = "authz-annotation-guide-v0.2-meeting-approved"
ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
DEFAULT_MEMBERSHIP = Path("dataset/authz_v2/golden_50_membership.csv")
DEFAULT_SELECTION_METADATA = Path("dataset/authz_v2/golden_50_selection_metadata.json")
DEFAULT_BATCH_ROOT = Path("output/framework_poc/golden_50_v1")
DEFAULT_PILOT_CALLERS = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/"
    "sensitive_api_callers.jsonl"
)
DEFAULT_PILOT_COMPONENTS = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/"
    "component_evidence.jsonl"
)
DEFAULT_OUTPUT = DEFAULT_BATCH_ROOT / "reviewer_packets_v1"

FORBIDDEN_STRUCTURED_KEYS = {
    "binary_label",
    "original_label",
    "source_dataset",
    "source_path",
    "canonical_csv_reference",
    "cluster_id",
    "cluster_size",
    "cluster_distance",
    "selection_role",
    "selection_rank",
    "selection_distance",
    "representativeness_basis",
    "risk_hint",
    "lf_votes",
    "observed_authz_label",
    "revised_authz_label",
    "model_score",
    "model_decision",
    "gold_authz_label",
}

CALLER_EVIDENCE_FIELDS = (
    "api_class",
    "api_method",
    "call_offset",
    "caller_class",
    "caller_component_name",
    "caller_descriptor",
    "caller_method",
    "description",
    "group_id",
    "group_label",
    "linkage_limit",
    "linkage_status",
    "matched_component_type",
    "matched_lifecycle_entry_method",
    "matched_manifest_component",
    "source",
)

COMPONENT_EVIDENCE_FIELDS = (
    "actions",
    "categories",
    "component_name",
    "component_type",
    "data_schemes",
    "data_types",
    "exported",
    "permission",
)

LIFECYCLE_METHODS = {
    "activity": {"onCreate", "onNewIntent"},
    "activity-alias": {"onCreate", "onNewIntent"},
    "receiver": {"onReceive"},
    "service": {"onStartCommand", "onBind"},
    "provider": {"query", "insert", "update", "delete", "openFile", "call"},
}

INPUT_TERMS = (
    "getIntent(",
    "getStringExtra(",
    "getBooleanExtra(",
    "getIntExtra(",
    "getLongExtra(",
    "getExtras(",
    "getData(",
    "getDataString(",
    "getQueryParameter(",
    "getCallingUid(",
)
GUARD_TERMS = (
    "checkCallingPermission(",
    "checkCallingOrSelfPermission(",
    "enforceCallingPermission(",
    "enforceCallingOrSelfPermission(",
    "checkPermission(",
    "checkUriPermission(",
    "enforceUriPermission(",
    "getCallingUid(",
    "getCallingPid(",
    "checkSignatures(",
    "checkUidSignatures(",
)

INVENTORY_FIELDS = (
    "membership_id",
    "apk_sha256",
    "package_name",
    "packet_reference",
    "packet_sha256",
    "review_unit_count",
    "candidate_count",
    "concrete_path_count",
    "source_file_count",
    "source_fetch_failure_count",
    "mobsf_status",
    "flowdroid_status",
)

REVIEW_UNIT_FIELDS = (
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
)


@dataclass(frozen=True)
class LedgerAttempt:
    tool: str
    status: str
    attempt_number: int
    error_type: str
    candidate_summary_reference: str


class NeutralInputUnavailableError(RuntimeError):
    """Neutral APK 缺失、被攔截或 identity 不符；允許 evidence-only fallback。"""


class MobSFSourceClient:
    """只在 request header 使用 API key；key 不會進入回傳值或檔案。"""

    def __init__(self, *, base_url: str, api_key: str, timeout: int = 60) -> None:
        self.base_url = validate_base_url(base_url)
        if not api_key:
            raise ValueError("MOBSF_API_KEY 未設定，無法擷取 reviewer source evidence。")
        self._api_key = api_key
        self.timeout = timeout

    def fetch(self, scan_hash: str, relative_path: str, source_type: str) -> str:
        body = urllib.parse.urlencode(
            {"hash": scan_hash, "type": source_type, "file": relative_path}
        ).encode("ascii")
        request = urllib.request.Request(
            f"{self.base_url}/api/v1/view_source",
            data=body,
            headers={"Authorization": self._api_key},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, Mapping) or "data" not in payload:
            raise ValueError("MobSF view_source 回傳缺少 data。")
        return str(payload["data"])


def _android_attr(element: ET.Element, name: str) -> str | None:
    value = element.get(f"{{{ANDROID_NAMESPACE}}}{name}")
    if value is None:
        value = element.get(name)
    return str(value) if value is not None else None


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _resolve_component_name(package_name: str, name: str | None) -> str:
    value = str(name or "")
    if value.startswith("."):
        return package_name + value
    if value and "." not in value:
        return f"{package_name}.{value}"
    return value


def _intent_filters(element: ET.Element) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for intent_filter in element.findall("./intent-filter"):
        rows.append(
            {
                "actions": sorted(
                    filter(None, (_android_attr(row, "name") for row in intent_filter.findall("./action")))
                ),
                "categories": sorted(
                    filter(None, (_android_attr(row, "name") for row in intent_filter.findall("./category")))
                ),
                "data": [
                    {
                        key: value
                        for key in (
                            "scheme",
                            "host",
                            "port",
                            "path",
                            "pathPrefix",
                            "pathPattern",
                            "mimeType",
                        )
                        if (value := _android_attr(row, key)) is not None
                    }
                    for row in intent_filter.findall("./data")
                ],
            }
        )
    return rows


def _exported_interpretation(
    component_type: str,
    explicit_exported: bool | None,
    has_intent_filter: bool,
    target_sdk: str | None,
) -> dict[str, Any]:
    """保留 Manifest-level interpretation；不把它當成 R verdict。"""
    if explicit_exported is not None:
        return {
            "value": explicit_exported,
            "basis": "explicit_android_exported",
            "limitation": "仍須檢查 permission、platform semantics 與 caller 前提。",
        }
    if component_type == "provider":
        try:
            target = int(str(target_sdk))
        except (TypeError, ValueError):
            return {
                "value": None,
                "basis": "provider_default_requires_target_sdk",
                "limitation": "target SDK 無法解析。",
            }
        return {
            "value": target < 17,
            "basis": "provider_platform_default_target_sdk_lt_17",
            "limitation": "仍須檢查 provider/path permission 與 URI grants。",
        }
    return {
        "value": has_intent_filter,
        "basis": (
            "implicit_intent_filter" if has_intent_filter else "implicit_no_intent_filter"
        ),
        "limitation": "仍須依 target/platform semantics 與 permission 進行人工確認。",
    }


def extract_manifest_evidence(root: ET.Element) -> dict[str, Any]:
    package_name = str(root.get("package") or "")
    uses_sdk = root.find("./uses-sdk")
    min_sdk = _android_attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    target_sdk = _android_attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    application = root.find("./application")
    application_permission = _android_attr(application, "permission") if application is not None else None
    tag_to_type = {
        "activity": "activity",
        "activity-alias": "activity-alias",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }
    components: list[dict[str, Any]] = []
    if application is not None:
        for tag, component_type in tag_to_type.items():
            for element in application.findall(f"./{tag}"):
                raw_name = _android_attr(element, "name")
                name = _resolve_component_name(package_name, raw_name)
                filters = _intent_filters(element)
                explicit = _parse_bool(_android_attr(element, "exported"))
                row: dict[str, Any] = {
                    "component_type": component_type,
                    "manifest_name": name,
                    "raw_manifest_name": raw_name,
                    "resolved_code_owner": (
                        _resolve_component_name(package_name, _android_attr(element, "targetActivity"))
                        if component_type == "activity-alias"
                        else name
                    ),
                    "explicit_exported": explicit,
                    "has_intent_filter": bool(filters),
                    "static_exported_interpretation": _exported_interpretation(
                        component_type, explicit, bool(filters), target_sdk
                    ),
                    "permission": _android_attr(element, "permission") or application_permission,
                    "intent_filters": filters,
                }
                if component_type == "provider":
                    row.update(
                        {
                            "authorities": _android_attr(element, "authorities"),
                            "read_permission": _android_attr(element, "readPermission"),
                            "write_permission": _android_attr(element, "writePermission"),
                            "grant_uri_permissions": _parse_bool(
                                _android_attr(element, "grantUriPermissions")
                            ),
                            "path_permissions": [
                                {
                                    key: value
                                    for key in (
                                        "path",
                                        "pathPrefix",
                                        "pathPattern",
                                        "permission",
                                        "readPermission",
                                        "writePermission",
                                    )
                                    if (value := _android_attr(path_row, key)) is not None
                                }
                                for path_row in element.findall("./path-permission")
                            ],
                        }
                    )
                components.append(row)
    components.sort(key=lambda row: (row["component_type"], row["manifest_name"]))
    return {
        "package_name": package_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "application_permission": application_permission,
        "uses_permissions": sorted(
            filter(None, (_android_attr(row, "name") for row in root.findall("./uses-permission")))
        ),
        "declared_permissions": [
            {
                "name": _android_attr(row, "name"),
                "protection_level": _android_attr(row, "protectionLevel"),
            }
            for row in root.findall("./permission")
        ],
        "components": components,
    }


def load_manifest_from_apk(apk_path: Path) -> ET.Element:
    # Androguard 4 使用 loguru，預設會把每個 AXML token 以 DEBUG 輸出。
    # Packet 產生只需要錯誤，避免 50 APK 執行產生數百萬行無關 log。
    try:
        from loguru import logger

        logger.disable("androguard")
    except ImportError:
        logging.getLogger("androguard").setLevel(logging.ERROR)
    from androguard.core.axml import AXMLPrinter

    with zipfile.ZipFile(apk_path) as archive:
        payload = archive.read("AndroidManifest.xml")
    parser = AXMLPrinter(payload)
    root = parser.get_xml_obj()
    if not parser.is_valid() or root is None:
        raise ValueError(f"AndroidManifest.xml 無法解析：{apk_path.name}")
    return root


def load_projected_callers(
    path: Path, membership_sha256s: set[str]
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            sha256 = str(row.get("sha256") or "")
            if sha256 not in membership_sha256s:
                continue
            evidence = row.get("evidence")
            if not isinstance(evidence, Mapping):
                raise ValueError(f"caller evidence line {line_number} 缺少 evidence object。")
            projected = {field: evidence.get(field) for field in CALLER_EVIDENCE_FIELDS}
            projected["evidence_reference"] = (
                "coordinator:sensitive_api_callers.jsonl#" + str(line_number)
            )
            result[sha256].append(projected)
    for rows in result.values():
        rows.sort(
            key=lambda row: (
                str(row.get("caller_component_name") or ""),
                str(row.get("caller_class") or ""),
                str(row.get("caller_method") or ""),
                str(row.get("caller_descriptor") or ""),
                int(row.get("call_offset") or 0),
                str(row.get("api_class") or ""),
                str(row.get("api_method") or ""),
            )
        )
    return dict(result)


def load_projected_components(
    path: Path, membership_sha256s: set[str]
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            sha256 = str(row.get("sha256") or "")
            if sha256 not in membership_sha256s:
                continue
            evidence = row.get("evidence")
            if not isinstance(evidence, Mapping):
                raise ValueError(f"component evidence line {line_number} 缺少 evidence object。")
            projected = {field: evidence.get(field) for field in COMPONENT_EVIDENCE_FIELDS}
            projected["evidence_reference"] = (
                "coordinator:component_evidence.jsonl#" + str(line_number)
            )
            result[sha256].append(projected)
    for rows in result.values():
        rows.sort(
            key=lambda row: (
                str(row.get("component_type") or ""),
                str(row.get("component_name") or ""),
            )
        )
    return dict(result)


def fallback_manifest_evidence(
    *,
    entry: MembershipEntry,
    report: Mapping[str, Any],
    component_rows: Sequence[Mapping[str, Any]],
    binary_manifest_error: str,
) -> dict[str, Any]:
    """在 host 無法重讀 APK 時使用已 SHA 綁定的 allowlisted evidence。

    這是明確降級：不補猜 explicit exported、custom permission protection level、
    Provider path permission 或 activity-alias code owner。
    """
    components: list[dict[str, Any]] = []
    for projected in component_rows:
        name = str(projected.get("component_name") or "")
        component_type = str(projected.get("component_type") or "")
        actions = sorted(str(value) for value in (projected.get("actions") or []))
        categories = sorted(str(value) for value in (projected.get("categories") or []))
        data_schemes = sorted(str(value) for value in (projected.get("data_schemes") or []))
        data_types = sorted(str(value) for value in (projected.get("data_types") or []))
        components.append(
            {
                "component_type": component_type,
                "manifest_name": name,
                "raw_manifest_name": None,
                "resolved_code_owner": name,
                "explicit_exported": None,
                "has_intent_filter": bool(actions or categories or data_schemes or data_types),
                "static_exported_interpretation": {
                    "value": projected.get("exported"),
                    "basis": "sha_bound_pilot_component_projection",
                    "limitation": (
                        "binary Manifest 本次無法重讀；不得把 projected exported boolean "
                        "單獨當成 R verdict。"
                    ),
                },
                "permission": projected.get("permission"),
                "intent_filters": [
                    {
                        "actions": actions,
                        "categories": categories,
                        "data": [
                            {"scheme": value} for value in data_schemes
                        ]
                        + [{"mimeType": value} for value in data_types],
                    }
                ]
                if actions or categories or data_schemes or data_types
                else [],
                "fallback_evidence_reference": projected.get("evidence_reference"),
            }
        )
    components.sort(key=lambda row: (row["component_type"], row["manifest_name"]))
    permissions = report.get("permissions")
    permission_names = sorted(str(key) for key in permissions) if isinstance(permissions, Mapping) else []
    return {
        "package_name": entry.package_name,
        "min_sdk": report.get("min_sdk"),
        "target_sdk": report.get("target_sdk"),
        "application_permission": None,
        "uses_permissions": permission_names,
        "declared_permissions": [],
        "components": components,
        "extraction_status": "fallback_sha_bound_projected_evidence",
        "binary_manifest_error": binary_manifest_error[:500],
        "fallback_limitations": [
            "binary_manifest_host_read_blocked",
            "explicit_exported_unavailable",
            "custom_permission_declarations_unavailable",
            "provider_path_permission_details_unavailable",
        ],
    }


def load_ledger(path: Path) -> dict[tuple[str, str], LedgerAttempt]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result: dict[tuple[str, str], LedgerAttempt] = {}
    for row in rows:
        attempt = LedgerAttempt(
            tool=str(row.get("tool") or ""),
            status=str(row.get("status") or ""),
            attempt_number=int(row.get("attempt_number") or 0),
            error_type=str(row.get("error_type") or ""),
            candidate_summary_reference=str(row.get("candidate_summary_reference") or ""),
        )
        result[(str(row.get("apk_sha256") or ""), attempt.tool)] = attempt
    return result


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"預期 JSON object：{path}")
    return value


def _canonical_id(prefix: str, value: Mapping[str, Any]) -> str:
    return f"{prefix}:{canonical_fingerprint(value)}"


def _class_to_source_requests(class_name: str) -> list[tuple[str, str]]:
    normalized = str(class_name or "").strip()
    if normalized.startswith("L") and normalized.endswith(";"):
        normalized = normalized[1:-1]
    normalized = normalized.replace(".", "/")
    outer = normalized.split("$", 1)[0]
    candidates: list[tuple[str, str]] = []
    for value in (normalized, outer):
        for request in ((f"{value}.java", "apk"), (f"{value}.smali", "smali")):
            if request not in candidates:
                candidates.append(request)
    return candidates


def _method_from_signature(signature: str) -> tuple[str, str]:
    match = re.match(r"^<([^:]+):\s+.+?\s+([^\s(]+)\((.*)\)>$", signature or "")
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def parse_flowdroid_results(path: Path) -> list[dict[str, Any]]:
    root = ET.parse(path).getroot()
    rows: list[dict[str, Any]] = []
    for result in root.findall("./Results/Result"):
        sink = result.find("./Sink")
        if sink is None:
            continue
        sink_data = {
            "statement": sink.get("Statement"),
            "line_number": sink.get("LineNumber"),
            "method": sink.get("Method"),
            "definition": sink.get("MethodSourceSinkDefinition"),
        }
        for source in result.findall("./Sources/Source"):
            path_elements = [
                {
                    "statement": element.get("Statement"),
                    "method": element.get("Method"),
                }
                for element in source.findall("./TaintPath/PathElement")
            ]
            rows.append(
                {
                    "source": {
                        "statement": source.get("Statement"),
                        "line_number": source.get("LineNumber"),
                        "method": source.get("Method"),
                        "definition": source.get("MethodSourceSinkDefinition"),
                    },
                    "sink": sink_data,
                    "taint_path": path_elements,
                    "termination_state": root.get("TerminationState"),
                }
            )
    return rows


def _find_component(
    manifest: Mapping[str, Any], component_name: str, component_type: str | None = None
) -> dict[str, Any] | None:
    for component in manifest.get("components", []):
        names = {component.get("manifest_name"), component.get("resolved_code_owner")}
        if component_name not in names:
            continue
        if component_type and component.get("component_type") != component_type:
            continue
        return dict(component)
    return None


def _caller_unit(
    *, entry: MembershipEntry, manifest: Mapping[str, Any], caller: Mapping[str, Any]
) -> dict[str, Any] | None:
    component_name = str(caller.get("caller_component_name") or "")
    component_type = str(caller.get("matched_component_type") or "")
    component = _find_component(manifest, component_name, component_type)
    if not component:
        return None
    identity = {
        "apk_sha256": entry.sha256,
        "manifest_component_name": component.get("manifest_name"),
        "resolved_code_owner": component.get("resolved_code_owner"),
        "caller_class": caller.get("caller_class"),
        "caller_method": caller.get("caller_method"),
        "caller_descriptor": caller.get("caller_descriptor"),
        "sink_class": caller.get("api_class"),
        "sink_method": caller.get("api_method"),
        "call_offset": caller.get("call_offset"),
    }
    candidate_id = _canonical_id("candidate-v1", identity)
    linkage = str(caller.get("linkage_status") or "")
    limitations = ["attacker_input_not_analyzed", "runtime_guard_not_analyzed"]
    if linkage != "direct_entry_caller":
        limitations.append("no_entry_to_sink_chain")
    else:
        limitations.append("direct_entry_identity_without_full_path")
    return {
        "review_unit_id": _canonical_id("review-unit-v1", {"candidate_id": candidate_id}),
        "row_kind": "candidate",
        "candidate_id": candidate_id,
        "path_id": None,
        "component_identity": component,
        "entry_evidence": {
            "entry_method": (
                caller.get("caller_method")
                if caller.get("matched_lifecycle_entry_method")
                else None
            ),
            "entry_descriptor": (
                caller.get("caller_descriptor")
                if caller.get("matched_lifecycle_entry_method")
                else None
            ),
            "linkage_status": linkage,
            "linkage_limit": caller.get("linkage_limit"),
        },
        "sensitive_effect_candidate": {
            "group_id": caller.get("group_id"),
            "group_label": caller.get("group_label"),
            "api_class": caller.get("api_class"),
            "api_method": caller.get("api_method"),
            "description": caller.get("description"),
            "caller_class": caller.get("caller_class"),
            "caller_method": caller.get("caller_method"),
            "caller_descriptor": caller.get("caller_descriptor"),
            "call_offset": caller.get("call_offset"),
            "evidence_source": caller.get("source"),
        },
        "attacker_input_evidence": {"status": "not_analyzed", "references": []},
        "authorization_guard_evidence": {"status": "not_analyzed", "references": []},
        "coverage_limitations": sorted(set(limitations)),
        "coordinator_evidence_reference": caller.get("evidence_reference"),
    }


def _flow_unit(
    *, entry: MembershipEntry, manifest: Mapping[str, Any], flow: Mapping[str, Any]
) -> dict[str, Any]:
    source_method = str(flow.get("source", {}).get("method") or "")
    source_class, entry_method = _method_from_signature(source_method)
    component = _find_component(manifest, source_class)
    component_type = str(component.get("component_type") if component else "")
    is_lifecycle = entry_method in LIFECYCLE_METHODS.get(component_type, set())
    is_concrete = bool(component and is_lifecycle and flow.get("taint_path"))
    sink = flow.get("sink", {})
    candidate_identity = {
        "apk_sha256": entry.sha256,
        "manifest_component_name": component.get("manifest_name") if component else None,
        "entry_method": source_method,
        "sink_method": sink.get("method"),
        "sink_statement": sink.get("statement"),
    }
    candidate_id = _canonical_id("candidate-v1", candidate_identity)
    path_id = _canonical_id("path-v1", flow) if is_concrete else None
    review_identity = {"candidate_id": candidate_id, "path_id": path_id}
    limitations: list[str] = []
    if not component:
        limitations.append("manifest_component_link_unresolved")
    if not is_lifecycle:
        limitations.append("no_lifecycle_link")
    return {
        "review_unit_id": _canonical_id("review-unit-v1", review_identity),
        "row_kind": "concrete_path" if is_concrete else "candidate",
        "candidate_id": candidate_id,
        "path_id": path_id,
        "component_identity": component,
        "entry_evidence": {
            "entry_method": entry_method or None,
            "entry_signature": source_method or None,
            "source_statement": flow.get("source", {}).get("statement"),
            "source_line_number": flow.get("source", {}).get("line_number"),
            "linkage_status": "flowdroid_taint_path" if is_concrete else "unresolved",
        },
        "sensitive_effect_candidate": dict(sink),
        "attacker_input_evidence": {
            "status": "flowdroid_source_to_sink_trace_present",
            "source": dict(flow.get("source", {})),
            "taint_path": list(flow.get("taint_path", [])),
        },
        "authorization_guard_evidence": {
            "status": "not_analyzed",
            "references": [],
        },
        "coverage_limitations": limitations + ["runtime_guard_not_analyzed"],
        "flowdroid_termination_state": flow.get("termination_state"),
    }


def _deduplicate_units(units: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for unit in units:
        unit_id = str(unit["review_unit_id"])
        if unit_id not in by_id:
            by_id[unit_id] = unit
            continue
        existing = by_id[unit_id]
        references = existing.setdefault("duplicate_evidence_references", [])
        reference = unit.get("coordinator_evidence_reference")
        if reference and reference not in references:
            references.append(reference)
    return [by_id[key] for key in sorted(by_id)]


def _line_hits(text: str, terms: Sequence[str], *, max_hits: int = 80) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        matched = [term for term in terms if term in line]
        if matched:
            hits.append({"line": number, "terms": matched, "text": line.strip()[:500]})
        if len(hits) >= max_hits:
            break
    return hits


def _safe_source_target(packet_root: Path, relative_path: str, source_type: str) -> Path:
    suffix_root = "java" if source_type == "apk" else "smali"
    normalized = Path(relative_path.replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError(f"不安全的 source path：{relative_path}")
    target = packet_root / "sources" / suffix_root / normalized
    target.resolve().relative_to(packet_root.resolve())
    return target


def _fetch_unit_sources(
    *,
    packet_root: Path,
    scan_hash: str,
    units: Sequence[dict[str, Any]],
    fetch_source: Callable[[str, str, str], str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    classes: set[str] = set()
    for unit in units:
        component = unit.get("component_identity") or {}
        if component.get("resolved_code_owner"):
            classes.add(str(component["resolved_code_owner"]))
        effect = unit.get("sensitive_effect_candidate") or {}
        if effect.get("caller_class"):
            classes.add(str(effect["caller_class"]))
        entry_signature = str(unit.get("entry_evidence", {}).get("entry_signature") or "")
        entry_class, _ = _method_from_signature(entry_signature)
        if entry_class:
            classes.add(entry_class)

    successes: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    class_to_reference: dict[str, str] = {}
    fetched_requests: set[tuple[str, str]] = set()
    for class_name in sorted(classes):
        last_error = ""
        for relative_path, source_type in _class_to_source_requests(class_name):
            request_key = (relative_path, source_type)
            existing = next(
                (row for row in successes if row["request"] == request_key), None
            )
            if existing:
                class_to_reference[class_name] = existing["reference"]
                break
            if request_key in fetched_requests:
                continue
            fetched_requests.add(request_key)
            try:
                text = fetch_source(scan_hash, relative_path, source_type)
                target = _safe_source_target(packet_root, relative_path, source_type)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8", newline="\n")
                reference = target.relative_to(packet_root).as_posix()
                row = {
                    "request": request_key,
                    "reference": reference,
                    "sha256": sha256_file(target),
                    "size_bytes": target.stat().st_size,
                    "source_type": "java" if source_type == "apk" else "smali",
                }
                successes.append(row)
                class_to_reference[class_name] = reference
                break
            except (OSError, ValueError, urllib.error.URLError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"[:500]
        if class_name not in class_to_reference:
            failures.append({"class_name": class_name, "error": last_error or "source_not_found"})

    source_texts = {
        row["reference"]: (packet_root / row["reference"]).read_text(
            encoding="utf-8", errors="replace"
        )
        for row in successes
    }
    for unit in units:
        relevant_classes: list[str] = []
        component = unit.get("component_identity") or {}
        if component.get("resolved_code_owner"):
            relevant_classes.append(str(component["resolved_code_owner"]))
        effect = unit.get("sensitive_effect_candidate") or {}
        if effect.get("caller_class"):
            relevant_classes.append(str(effect["caller_class"]))
        locators = []
        seen_source_references: set[str] = set()
        for class_name in dict.fromkeys(relevant_classes):
            reference = class_to_reference.get(class_name)
            if not reference or reference in seen_source_references:
                continue
            seen_source_references.add(reference)
            source_text = source_texts[reference]
            sink_method = str(effect.get("api_method") or "")
            entry_method = str(unit.get("entry_evidence", {}).get("entry_method") or "")
            locators.append(
                {
                    "class_name": class_name,
                    "source_reference": reference,
                    "entry_method_name_hits": _line_hits(
                        source_text, (f" {entry_method}(",) if entry_method else ()
                    ),
                    "sink_method_name_hits": _line_hits(
                        source_text, (f".{sink_method}(",) if sink_method else ()
                    ),
                    "attacker_input_keyword_hits": _line_hits(source_text, INPUT_TERMS),
                    "authorization_guard_keyword_hits": _line_hits(source_text, GUARD_TERMS),
                    "locator_warning": "keyword hit 只是定位線索，不是 predicate verdict。",
                }
            )
        unit["source_locators"] = locators

    clean_successes = [
        {key: value for key, value in row.items() if key != "request"}
        for row in successes
    ]
    return clean_successes, failures


def _assert_no_forbidden_keys(value: Any, *, location: str = "root") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key) in FORBIDDEN_STRUCTURED_KEYS:
                raise ValueError(f"blinding breach：{location}.{key}")
            _assert_no_forbidden_keys(child, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_no_forbidden_keys(child, location=f"{location}[{index}]")


def _relative_reference(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def build_packet(
    *,
    entry: MembershipEntry,
    batch_root: Path,
    packet_root: Path,
    attempts: Mapping[tuple[str, str], LedgerAttempt],
    callers: Sequence[Mapping[str, Any]],
    component_rows: Sequence[Mapping[str, Any]],
    fetch_source: Callable[[str, str, str], str],
) -> dict[str, Any]:
    apk_path = batch_root / "review_inputs" / f"{entry.sha256}.apk"
    mobsf = attempts.get((entry.sha256, "mobsf"))
    flowdroid = attempts.get((entry.sha256, "flowdroid"))
    if mobsf is None or flowdroid is None:
        raise ValueError(f"execution ledger 缺少工具列：{entry.sha256}")
    if not mobsf.candidate_summary_reference:
        raise ValueError(f"MobSF summary reference 缺失：{entry.sha256}")
    summary_path = batch_root / mobsf.candidate_summary_reference
    summary = _load_json(summary_path)
    if summary.get("identity", {}).get("sha256") != entry.sha256:
        raise ValueError(f"MobSF summary identity 不符：{entry.sha256}")
    report_path = summary_path.parent / "raw" / "report.json"
    report = _load_json(report_path)
    scan_hash = str(report.get("md5") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", scan_hash):
        raise ValueError(f"MobSF scan hash 無效：{entry.sha256}")

    try:
        if not apk_path.is_file():
            raise NeutralInputUnavailableError(f"neutral APK 不存在：{apk_path.name}")
        actual_sha256 = sha256_file(apk_path)
        if actual_sha256 != entry.sha256:
            raise NeutralInputUnavailableError(
                "neutral APK SHA-256 不符："
                f"expected={entry.sha256}, actual={actual_sha256}"
            )
        manifest = extract_manifest_evidence(load_manifest_from_apk(apk_path))
        manifest["extraction_status"] = "binary_manifest_verified"
    except (OSError, NeutralInputUnavailableError) as exc:
        manifest = fallback_manifest_evidence(
            entry=entry,
            report=report,
            component_rows=component_rows,
            binary_manifest_error=f"{type(exc).__name__}: {exc}",
        )
    if manifest["package_name"] != entry.package_name:
        raise ValueError(f"Manifest package 與 membership 不符：{entry.sha256}")

    units: list[dict[str, Any]] = []
    unlinked_callers: list[dict[str, Any]] = []
    for caller in callers:
        unit = _caller_unit(entry=entry, manifest=manifest, caller=caller)
        if unit is None:
            unlinked_callers.append(dict(caller))
        else:
            units.append(unit)

    flow_xml = (
        batch_root
        / "runs"
        / entry.sha256
        / "flowdroid"
        / f"attempt_{flowdroid.attempt_number:03d}"
        / "raw"
        / "flowdroid.xml"
    )
    flow_rows = parse_flowdroid_results(flow_xml) if flow_xml.is_file() else []
    unlinked_flow_traces: list[dict[str, Any]] = []
    for flow_row in flow_rows:
        flow_unit = _flow_unit(entry=entry, manifest=manifest, flow=flow_row)
        if flow_unit.get("component_identity") is None:
            unlinked_flow_traces.append(
                {
                    "source": flow_row.get("source"),
                    "sink": flow_row.get("sink"),
                    "taint_path": flow_row.get("taint_path"),
                    "coverage_limitations": flow_unit.get("coverage_limitations"),
                    "review_status": "not_materialized_without_manifest_component_identity",
                }
            )
        else:
            units.append(flow_unit)
    units = _deduplicate_units(units)

    source_files, source_failures = _fetch_unit_sources(
        packet_root=packet_root,
        scan_hash=scan_hash,
        units=units,
        fetch_source=fetch_source,
    )
    packet = {
        "schema_version": SCHEMA_VERSION,
        "materialization_version": MATERIALIZATION_VERSION,
        "spec_version": SPEC_VERSION,
        "guide_version": GUIDE_VERSION,
        "generated_at": taipei_now(),
        "packet_role": "reviewer_visible_evidence_verdict_blind",
        "produces_ground_truth": False,
        "absence_is_negative_label": False,
        "identity": {
            "membership_id": entry.membership_id,
            "apk_sha256": entry.sha256,
            "package_name": entry.package_name,
        },
        "threat_model": {
            "caller": "一般未受信任第三方 Android app、不同 UID、非同簽章、無 root/ADB/system 權限",
            "scope": "single-target-APK component entry to sensitive effect",
        },
        "manifest_evidence": manifest,
        "analysis_coverage": {
            "mobsf": {
                "status": mobsf.status,
                "candidate_summary_schema": summary.get("schema_version"),
            },
            "flowdroid": {
                "status": flowdroid.status,
                "classification": flowdroid.error_type or None,
                "result_artifact_present": flow_xml.is_file(),
                "trace_count": len(flow_rows),
                "warning": "工具無結果、失敗或零 finding 均不是 authorization negative。",
            },
            "xref_caller_count": len(callers),
            "unlinked_xref_caller_count": len(unlinked_callers),
        },
        "source_evidence": {
            "files": source_files,
            "fetch_failures": source_failures,
            "warning": "反編譯 source 可能不完整；line/keyword hit 只供人工定位。",
        },
        "unlinked_sensitive_callers": unlinked_callers,
        "unlinked_flow_traces": unlinked_flow_traces,
        "review_units": units,
        "review_instructions": {
            "predicate_order": ["R", "I", "S", "A"],
            "positive_rule": "R/I/S/A 全部 confirmed",
            "negative_rule": "至少一項以充分證據 refuted",
            "unknown_rule": "沒有可靠 refutation，但至少一項 unknown",
            "do_not_infer": "不得由 tool status、zero finding、keyword hit 或 metadata 推導 label。",
        },
    }
    _assert_no_forbidden_keys(packet)
    return packet


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _flatten_review_units(
    packets: Sequence[tuple[dict[str, Any], str, str]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for packet, packet_reference, packet_sha256 in packets:
        identity = packet["identity"]
        for unit in packet["review_units"]:
            component = unit.get("component_identity") or {}
            effect = unit.get("sensitive_effect_candidate") or {}
            entry = unit.get("entry_evidence") or {}
            rows.append(
                {
                    "membership_id": identity["membership_id"],
                    "apk_sha256": identity["apk_sha256"],
                    "package_name": identity["package_name"],
                    "review_unit_id": unit["review_unit_id"],
                    "row_kind": unit["row_kind"],
                    "candidate_id": unit["candidate_id"],
                    "path_id": unit.get("path_id") or "",
                    "component_type": component.get("component_type") or "",
                    "manifest_component_name": component.get("manifest_name") or "",
                    "entry_method": entry.get("entry_method") or "",
                    "caller_method": effect.get("caller_method")
                    or effect.get("method")
                    or "",
                    "sensitive_sink": effect.get("definition")
                    or ":".join(
                        filter(None, (str(effect.get("api_class") or ""), str(effect.get("api_method") or "")))
                    ),
                    "evidence_packet_reference": packet_reference,
                    "evidence_packet_sha256": packet_sha256,
                    "materialization_version": MATERIALIZATION_VERSION,
                    "spec_version": SPEC_VERSION,
                    "guide_version": GUIDE_VERSION,
                }
            )
    rows.sort(key=lambda row: (row["apk_sha256"], row["review_unit_id"]))
    return rows


def _write_report(
    path: Path,
    *,
    inventory: Sequence[Mapping[str, Any]],
    unit_rows: Sequence[Mapping[str, Any]],
    collection_fingerprint: str,
) -> None:
    statuses_mobsf = Counter(str(row["mobsf_status"]) for row in inventory)
    statuses_flowdroid = Counter(str(row["flowdroid_status"]) for row in inventory)
    row_kinds = Counter(str(row["row_kind"]) for row in unit_rows)
    source_failures = sum(int(row["source_fetch_failure_count"]) for row in inventory)
    lines = [
        "# Golden-50 盲化 reviewer evidence packet 稽核報告",
        "",
        f"- Schema：`{COLLECTION_SCHEMA_VERSION}`",
        f"- Materialization：`{MATERIALIZATION_VERSION}`",
        f"- 產生時間：`{taipei_now()}`",
        f"- APK packet containers：**{len(inventory)}**",
        f"- Review units：**{len(unit_rows)}**",
        f"- Candidate units：**{row_kinds.get('candidate', 0)}**",
        f"- Concrete-path units：**{row_kinds.get('concrete_path', 0)}**",
        f"- Source fetch failures：**{source_failures}**",
        f"- Collection fingerprint：`{collection_fingerprint}`",
        "",
        "## Blinding gate",
        "",
        "- PASS：未輸出 dataset/family labels、source path、risk_hint、cluster/selection hints、weak/model verdict 或 Gold label。",
        "- PASS：所有 packet reference 為集合內相對路徑，API key 未持久化。",
        "- PASS：membership authority 與 neutral APK 以 SHA-256 驗證；frozen human artifacts 未由本工具寫入。",
        "- 注意：package/component identity 與反編譯程式碼依規格允許 reviewer 查看；程式碼內容本身仍須人工判讀。",
        "",
        "## 工具 coverage（不是 label）",
        "",
        f"- MobSF：`{dict(statuses_mobsf)}`",
        f"- FlowDroid：`{dict(statuses_flowdroid)}`",
        "- `no_result_artifact`、`memory_termination`、零 trace 或 source fetch failure 都不能轉成 negative。",
        "",
        "## 使用方式",
        "",
        "1. 只從 `review_units.csv` 選取 unit。",
        "2. 開啟該列的 `evidence_packet_reference`，依序審查 R、I、S、A。",
        "3. Candidate 不得因有 XREF／keyword hit 而視為 concrete path。",
        "4. 人工 decision 必須另寫 append-only `gold-review-event-v1`；本集合不含人工 verdict 欄位。",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def audit_collection(output_dir: Path) -> dict[str, Any]:
    """獨立驗證已產生 collection；不需要 MobSF key 或 raw APK。"""
    output_dir = output_dir.resolve()
    manifest = _load_json(output_dir / "packet_collection_manifest.json")
    if manifest.get("schema_version") != COLLECTION_SCHEMA_VERSION:
        raise ValueError("packet collection schema version 不符。")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("packet collection manifest 缺少 artifacts list。")
    if manifest.get("artifact_count") != len(artifacts):
        raise ValueError("artifact_count 與 manifest artifacts 數量不符。")
    if manifest.get("collection_fingerprint") != canonical_fingerprint(artifacts):
        raise ValueError("collection fingerprint 不符。")

    listed_references: set[str] = set()
    for artifact in artifacts:
        reference = str(artifact.get("reference") or "")
        relative = Path(reference)
        if not reference or relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"不安全的 artifact reference：{reference!r}")
        if reference in listed_references:
            raise ValueError(f"artifact reference 重複：{reference}")
        listed_references.add(reference)
        path = (output_dir / relative).resolve()
        path.relative_to(output_dir)
        if not path.is_file():
            raise FileNotFoundError(f"manifest artifact 不存在：{reference}")
        if path.stat().st_size != int(artifact.get("size_bytes") or -1):
            raise ValueError(f"artifact size 不符：{reference}")
        if sha256_file(path) != artifact.get("sha256"):
            raise ValueError(f"artifact SHA-256 不符：{reference}")

    expected_references = {
        _relative_reference(path, output_dir)
        for path in (output_dir / "packets").rglob("*")
        if path.is_file()
    } | {"packet_inventory.csv", "review_units.csv"}
    if listed_references != expected_references:
        raise ValueError("artifact manifest 與實際 reviewer artifacts 集合不一致。")

    with (output_dir / "packet_inventory.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        inventory_reader = csv.DictReader(handle)
        if tuple(inventory_reader.fieldnames or ()) != INVENTORY_FIELDS:
            raise ValueError("packet inventory schema 不符。")
        inventory = list(inventory_reader)
    with (output_dir / "review_units.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        units_reader = csv.DictReader(handle)
        if tuple(units_reader.fieldnames or ()) != REVIEW_UNIT_FIELDS:
            raise ValueError("review units schema 不符。")
        units = list(units_reader)
    if len(inventory) != int(manifest.get("packet_count", -1)):
        raise ValueError("packet inventory count 不符。")
    if len(units) != int(manifest.get("review_unit_count", -1)):
        raise ValueError("review unit count 不符。")
    if len({row["apk_sha256"] for row in inventory}) != len(inventory):
        raise ValueError("packet inventory APK SHA-256 不唯一。")
    if len({row["review_unit_id"] for row in units}) != len(units):
        raise ValueError("review_unit_id 不唯一。")
    if any(not row["manifest_component_name"] for row in units):
        raise ValueError("review unit 缺少 Manifest component identity。")
    if any(row["spec_version"] != SPEC_VERSION for row in units):
        raise ValueError("review unit spec version 不符。")
    if any(row["guide_version"] != GUIDE_VERSION for row in units):
        raise ValueError("review unit guide version 不符。")

    for row in inventory:
        packet_path = output_dir / row["packet_reference"]
        if sha256_file(packet_path) != row["packet_sha256"]:
            raise ValueError(f"inventory packet SHA-256 不符：{row['packet_reference']}")
        packet = _load_json(packet_path)
        _assert_no_forbidden_keys(packet)
        if packet.get("identity", {}).get("apk_sha256") != row["apk_sha256"]:
            raise ValueError(f"inventory/packet identity 不符：{row['apk_sha256']}")

    return {
        "status": "PASS",
        "packet_count": len(inventory),
        "review_unit_count": len(units),
        "unique_review_unit_count": len({row["review_unit_id"] for row in units}),
        "artifact_count": len(artifacts),
        "collection_fingerprint": manifest["collection_fingerprint"],
    }


def build_collection(
    *,
    membership_csv: Path,
    selection_metadata: Path,
    batch_root: Path,
    pilot_callers: Path,
    pilot_components: Path,
    output_dir: Path,
    fetch_source: Callable[[str, str, str], str],
    api_key_for_leak_check: str = "",
) -> dict[str, Any]:
    entries, membership_audit = load_frozen_membership(
        membership_csv, selection_metadata
    )
    frozen_before = {
        path.as_posix(): sha256_file(path)
        for path in (
            membership_csv,
            selection_metadata,
            Path("dataset/authz_v2/golden_50_annotations.csv"),
            Path("dataset/authz_v2/gold_review_log.jsonl"),
        )
    }
    attempts = load_ledger(batch_root / "execution_ledger.csv")
    callers_by_sha = load_projected_callers(
        pilot_callers, {entry.sha256 for entry in entries}
    )
    components_by_sha = load_projected_components(
        pilot_components, {entry.sha256 for entry in entries}
    )
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"拒絕覆寫既有 reviewer packet collection：{output_dir}")
    staging = output_dir.with_name(f".{output_dir.name}.staging-{uuid.uuid4().hex}")
    staging.mkdir(parents=True)
    try:
        inventory: list[dict[str, Any]] = []
        packets_with_refs: list[tuple[dict[str, Any], str, str]] = []
        for entry in sorted(entries, key=lambda row: row.sha256):
            packet_dir = staging / "packets" / entry.sha256
            packet_dir.mkdir(parents=True)
            packet = build_packet(
                entry=entry,
                batch_root=batch_root,
                packet_root=packet_dir,
                attempts=attempts,
                callers=callers_by_sha.get(entry.sha256, []),
                component_rows=components_by_sha.get(entry.sha256, []),
                fetch_source=fetch_source,
            )
            packet_path = packet_dir / "packet.json"
            _write_json(packet_path, packet)
            packet_reference = _relative_reference(packet_path, staging)
            packet_sha256 = sha256_file(packet_path)
            row_kinds = Counter(unit["row_kind"] for unit in packet["review_units"])
            inventory.append(
                {
                    "membership_id": entry.membership_id,
                    "apk_sha256": entry.sha256,
                    "package_name": entry.package_name,
                    "packet_reference": packet_reference,
                    "packet_sha256": packet_sha256,
                    "review_unit_count": len(packet["review_units"]),
                    "candidate_count": row_kinds.get("candidate", 0),
                    "concrete_path_count": row_kinds.get("concrete_path", 0),
                    "source_file_count": len(packet["source_evidence"]["files"]),
                    "source_fetch_failure_count": len(
                        packet["source_evidence"]["fetch_failures"]
                    ),
                    "mobsf_status": packet["analysis_coverage"]["mobsf"]["status"],
                    "flowdroid_status": packet["analysis_coverage"]["flowdroid"]["status"],
                }
            )
            packets_with_refs.append((packet, packet_reference, packet_sha256))

        _write_csv(staging / "packet_inventory.csv", INVENTORY_FIELDS, inventory)
        unit_rows = _flatten_review_units(packets_with_refs)
        if len({row["review_unit_id"] for row in unit_rows}) != len(unit_rows):
            raise ValueError("review_unit_id 必須在整個 packet collection 中唯一。")
        if any(not row["manifest_component_name"] for row in unit_rows):
            raise ValueError("review unit 缺少 Manifest component identity。")
        _write_csv(staging / "review_units.csv", REVIEW_UNIT_FIELDS, unit_rows)
        artifact_paths = list((staging / "packets").rglob("*")) + [
            staging / "packet_inventory.csv",
            staging / "review_units.csv",
        ]
        artifact_rows = []
        for path in sorted(artifact_paths):
            if path.is_file():
                artifact_rows.append(
                    {
                        "reference": _relative_reference(path, staging),
                        "sha256": sha256_file(path),
                        "size_bytes": path.stat().st_size,
                    }
                )
        collection_fingerprint = canonical_fingerprint(artifact_rows)
        collection_manifest = {
            "schema_version": COLLECTION_SCHEMA_VERSION,
            "materialization_version": MATERIALIZATION_VERSION,
            "generated_at": taipei_now(),
            "membership": {
                "membership_version": MEMBERSHIP_VERSION,
                "membership_count": len(entries),
                "membership_sha256": membership_audit["membership_sha256"],
                "membership_csv_sha256": membership_audit["membership_csv_sha256"],
            },
            "packet_count": len(inventory),
            "review_unit_count": len(unit_rows),
            "candidate_count": sum(row["row_kind"] == "candidate" for row in unit_rows),
            "concrete_path_count": sum(
                row["row_kind"] == "concrete_path" for row in unit_rows
            ),
            "collection_fingerprint": collection_fingerprint,
            "artifact_count": len(artifact_rows),
            "artifacts": artifact_rows,
            "blinding_audit": {
                "status": "PASS",
                "forbidden_structured_keys": sorted(FORBIDDEN_STRUCTURED_KEYS),
                "api_key_persisted": False,
                "verdict_fields_present": False,
            },
        }
        _assert_no_forbidden_keys(collection_manifest)
        _write_json(staging / "packet_collection_manifest.json", collection_manifest)
        _write_report(
            staging / "PACKET_AUDIT_REPORT.md",
            inventory=inventory,
            unit_rows=unit_rows,
            collection_fingerprint=collection_fingerprint,
        )

        if api_key_for_leak_check:
            needle = api_key_for_leak_check.encode("utf-8")
            for path in staging.rglob("*"):
                if path.is_file() and needle in path.read_bytes():
                    raise ValueError(f"API key 洩漏到 reviewer artifact：{path}")
        frozen_after = {path: sha256_file(Path(path)) for path in frozen_before}
        if frozen_after != frozen_before:
            raise RuntimeError("frozen human artifacts 在 packet 產生期間遭到修改。")

        staging.replace(output_dir)
        return collection_manifest
    except Exception:
        if staging.exists():
            try:
                shutil.rmtree(staging)
            except OSError:
                # Windows Defender／indexer 可能短暫持有 source 檔。保留原始例外，
                # staging 名稱本身即標示未完成，之後可精確清理。
                pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--membership", type=Path, default=DEFAULT_MEMBERSHIP)
    parser.add_argument("--selection-metadata", type=Path, default=DEFAULT_SELECTION_METADATA)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--pilot-callers", type=Path, default=DEFAULT_PILOT_CALLERS)
    parser.add_argument("--pilot-components", type=Path, default=DEFAULT_PILOT_COMPONENTS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--mobsf-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--source-timeout", type=int, default=60)
    parser.add_argument("--audit-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.audit_only:
        print(json.dumps(audit_collection(args.output_dir), ensure_ascii=False, indent=2))
        return 0
    api_key = os.environ.get("MOBSF_API_KEY", "")
    client = MobSFSourceClient(
        base_url=args.mobsf_base_url,
        api_key=api_key,
        timeout=args.source_timeout,
    )
    result = build_collection(
        membership_csv=args.membership,
        selection_metadata=args.selection_metadata,
        batch_root=args.batch_root,
        pilot_callers=args.pilot_callers,
        pilot_components=args.pilot_components,
        output_dir=args.output_dir,
        fetch_source=client.fetch,
        api_key_for_leak_check=api_key,
    )
    print(
        json.dumps(
            {
                "status": "success",
                "output_dir": str(args.output_dir.resolve()),
                "packet_count": result["packet_count"],
                "review_unit_count": result["review_unit_count"],
                "candidate_count": result["candidate_count"],
                "concrete_path_count": result["concrete_path_count"],
                "collection_fingerprint": result["collection_fingerprint"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
