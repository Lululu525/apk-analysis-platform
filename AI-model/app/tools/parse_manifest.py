"""
Standalone CLI: extract Android manifest features from an APK.

Usage:
    python -m app.tools.parse_manifest <apk> [--out FILE] [--pretty]

Output (JSON on stdout, or to --out FILE):
    {
      "package_name": str,
      "version_code": int | None,
      "version_name": str | None,
      "min_sdk": int | None,
      "target_sdk": int | None,
      "permissions": [str, ...],
      "permission_count": int,
      "components": {
        "activities": [str, ...],
        "services":   [str, ...],
        "providers":  [str, ...],
        "receivers":  [str, ...]
      },
      "intents": [
        {"component": str, "action": str | None,
         "category": str | None, "data_scheme": str | None,
         "data_type": str | None, "permission": str | None},
        ...
      ],
      "exported_unprotected": [str, ...]
    }

Matches the feature vector used by El-Zawawy & Hamdy (ASE 2025) for the
n-order IPC escalation classifier. The tool is intentionally stateless
and does NOT emit Finding objects or write into the pipeline — it is a
data-extraction utility for downstream ML / dataset work.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..detectors.privilege_rules import (
    DANGEROUS_PERMS_FOR_DEPUTY,
    SENSITIVE_BROADCAST_ACTIONS,
)
from ..extractors.androguard_analyzer import (
    ANDROGUARD_AVAILABLE,
    AnalysisResult,
    ComponentInfo,
    analyze_apk,
)


_COMPONENT_KEY = {
    "activity": "activities",
    "service": "services",
    "provider": "providers",
    "receiver": "receivers",
}


def _component_permission(comp: ComponentInfo) -> Optional[str]:
    if comp.type == "provider":
        if comp.read_permission and comp.write_permission:
            return comp.read_permission
        return None
    if not comp.permissions_required:
        return None
    return comp.permissions_required[0]


def _normalize_feature_suffix(value: str) -> str:
    """Return a stable ASCII-safe suffix for generated multi-hot fields."""
    suffix = re.sub(r"[^0-9a-zA-Z]+", "_", value.lower())
    suffix = re.sub(r"_+", "_", suffix).strip("_")
    return suffix or "unknown"


def _collect_filter_values(comp: ComponentInfo, key: str) -> List[str]:
    values: List[str] = []
    seen: set[str] = set()
    for intent_filter in comp.intent_filters or []:
        raw_values = intent_filter.get(key) or []
        if isinstance(raw_values, str):
            raw_values = [raw_values]
        for value in raw_values:
            if value and value not in seen:
                values.append(value)
                seen.add(value)
    return values


def _add_multi_hot_fields(row: Dict[str, Any], prefix: str, values: List[str]) -> None:
    for value in values:
        row[f"has_{prefix}_{_normalize_feature_suffix(value)}"] = True


def _flatten_intents(comp: ComponentInfo) -> List[Dict[str, Optional[str]]]:
    """Expand a component's intent-filters into flat (action, category,
    data_scheme, data_type, permission) rows suitable for an ML feature
    vector. Missing fields are emitted as None rather than dropped.
    """
    if not comp.intent_filters:
        return []
    perm = _component_permission(comp)
    rows: List[Dict[str, Optional[str]]] = []
    for f in comp.intent_filters:
        actions = f.get("actions") or [None]
        categories = f.get("categories") or [None]
        schemes = f.get("data_schemes") or [None]
        data_types = f.get("data_types") or [None]
        for action, category, scheme, mime in product(
            actions, categories, schemes, data_types
        ):
            rows.append({
                "component": comp.name,
                "action": action,
                "category": category,
                "data_scheme": scheme,
                "data_type": mime,
                "permission": perm,
            })
    return rows


def _summarize(result: AnalysisResult) -> Dict[str, Any]:
    """Convert an AnalysisResult to the manifest summary dict (same shape as build_features)."""
    permissions = sorted((result.permissions or {}).keys())
    components_by_type: Dict[str, List[str]] = {v: [] for v in _COMPONENT_KEY.values()}
    intents: List[Dict[str, Optional[str]]] = []
    exported_unprotected: List[str] = []

    for comp in result.components or []:
        key = _COMPONENT_KEY.get(comp.type)
        if key is None:
            continue
        components_by_type[key].append(comp.name)
        intents.extend(_flatten_intents(comp))
        if comp.exported and _component_permission(comp) is None:
            exported_unprotected.append(comp.name)

    return {
        "package_name": result.package_name,
        "version_code": result.version_code,
        "version_name": result.version_name,
        "min_sdk": result.min_sdk,
        "target_sdk": result.target_sdk,
        "permissions": permissions,
        "permission_count": len(permissions),
        "components": components_by_type,
        "intents": intents,
        "exported_unprotected": exported_unprotected,
    }


def _build_filter_rows(
    result: AnalysisResult,
    sample_id: str,
    package_name: str,
) -> List[Dict[str, Any]]:
    """Build filter_rows from all relevant components.

    Components with intent-filters: one component-level row with raw value lists
    plus multi-hot action/category/data_type fields.
    Exported components without intent-filters: one empty-list row (covers IPC_SERVICE_HIJACK
    and IPC_PROVIDER_REDELEGATION cases reachable via explicit intent).
    Non-exported components without intent-filters are skipped.
    """
    rows: List[Dict[str, Any]] = []
    for comp in result.components or []:
        perm = _component_permission(comp)
        protected = perm is not None

        if not comp.intent_filters and not comp.exported:
            continue

        actions = _collect_filter_values(comp, "actions")
        categories = _collect_filter_values(comp, "categories")
        data_types = _collect_filter_values(comp, "data_types")
        data_schemes = _collect_filter_values(comp, "data_schemes")

        row: Dict[str, Any] = {
            "sample_id": sample_id,
            "package_name": package_name,
            "component_name": comp.name,
            "component_type": comp.type,
            "actions": actions,
            "categories": categories,
            "data_types": data_types,
            "data_schemes": data_schemes,
            "permission": perm,
            "exported": comp.exported,
            "protected": protected,
        }
        _add_multi_hot_fields(row, "action", actions)
        _add_multi_hot_fields(row, "category", categories)
        _add_multi_hot_fields(row, "data_type", data_types)
        rows.append(row)
    return rows


def _build_intent_rows(filter_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Infer manifest-only intent_rows 1:1 from filter_rows.

    The caller is unknown from manifest alone, so component identity fields are
    "<UNKNOWN>" and is_explicit=False. Bytecode extraction (v2) replaces these.
    """
    rows: List[Dict[str, Any]] = []
    for fr in filter_rows:
        rows.append({
            "sample_id": fr["sample_id"],
            "package_name": fr["package_name"],
            "component_name": "<UNKNOWN>",
            "component_type": "<UNKNOWN>",
            "actions": list(fr["actions"]),
            "categories": list(fr["categories"]),
            "data_types": list(fr["data_types"]),
            "data_schemes": list(fr["data_schemes"]),
            "permission": None,
            "is_explicit": False,
            "source": "manifest_only",
        })
    return rows


def _compute_risk_hint(
    comp_type: str,
    exported: bool,
    protected: bool,
    actions: List[str],
    app_permission_names: set,
) -> Optional[str]:
    """Return the IPC risk hint for a filter_row, or None if no risk applies."""
    if not exported or protected:
        return None
    if comp_type == "service":
        return "IPC_SERVICE_HIJACK"
    if comp_type == "receiver" and (set(actions) & SENSITIVE_BROADCAST_ACTIONS):
        return "IPC_BROADCAST_THEFT"
    if comp_type == "activity" and (app_permission_names & DANGEROUS_PERMS_FOR_DEPUTY):
        return "IPC_CONFUSED_DEPUTY"
    if comp_type == "provider":
        return "IPC_PROVIDER_REDELEGATION"
    return None


def _matches_any(intent_values: List[str], filter_values: List[str]) -> bool:
    if not intent_values:
        return True
    return bool(set(intent_values) & set(filter_values))


def _build_resolution_rows(
    filter_rows: List[Dict[str, Any]],
    intent_rows: List[Dict[str, Any]],
    permission_names: set,
) -> List[Dict[str, Any]]:
    """Build manifest-only 1:1 resolution_rows from inferred intent/filter rows."""
    if len(intent_rows) != len(filter_rows):
        raise ValueError("manifest-only resolution expects 1:1 intent/filter rows")

    rows: List[Dict[str, Any]] = []
    for ir, fr in zip(intent_rows, filter_rows):
        rows.append({
            "sample_id": fr["sample_id"],
            "intent_component_name": ir["component_name"],
            "intent_component_type": ir["component_type"],
            "intent_actions": list(ir["actions"]),
            "intent_categories": list(ir["categories"]),
            "intent_data_types": list(ir["data_types"]),
            "intent_data_schemes": list(ir["data_schemes"]),
            "intent_permission": ir["permission"],
            "filter_component_name": fr["component_name"],
            "filter_component_type": fr["component_type"],
            "filter_actions": list(fr["actions"]),
            "filter_categories": list(fr["categories"]),
            "filter_data_types": list(fr["data_types"]),
            "filter_data_schemes": list(fr["data_schemes"]),
            "filter_permission": fr["permission"],
            "filter_exported": fr["exported"],
            "filter_protected": fr["protected"],
            "match_action": _matches_any(ir["actions"], fr["actions"]),
            "match_category": _matches_any(ir["categories"], fr["categories"]),
            "match_type": _matches_any(ir["data_types"], fr["data_types"]),
            "caller_permission": ir["permission"],
            "callee_permission": fr["permission"],
            "risk_hint": _compute_risk_hint(
                comp_type=fr["component_type"],
                exported=fr["exported"],
                protected=fr["protected"],
                actions=fr["actions"],
                app_permission_names=permission_names,
            ),
        })
    return rows


def build_features(apk_path: Path) -> Dict[str, Any]:
    """Extract a flat manifest feature dict from an APK.

    Raises:
        RuntimeError: androguard is not installed.
        ValueError:   androguard failed to parse the APK.
    """
    if not ANDROGUARD_AVAILABLE:
        raise RuntimeError(
            "androguard is not installed in this environment. "
            "Install with: pip install androguard>=4.0"
        )

    result: AnalysisResult = analyze_apk(apk_path)
    if not result.success:
        raise ValueError(
            f"Failed to parse APK {apk_path}: {'; '.join(result.errors or ['unknown error'])}"
        )

    return _summarize(result)


def build_model_features(
    apk_path: Path,
    sample_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build row-level feature dicts for ML training/inference.

    Args:
        apk_path:  Path to the .apk file.
        sample_id: Caller-supplied identifier injected into every row.
                   Defaults to apk_path.stem when omitted.

    Returns:
        {
            "intent_rows":     [intent_row, ...],
            "filter_rows":     [filter_row, ...],
            "resolution_rows": [resolution_row, ...],
            "app_summary":     {...}   # identical to build_features() output
        }

    Raises:
        RuntimeError: androguard is not installed.
        ValueError:   androguard failed to parse the APK.
    """
    if not ANDROGUARD_AVAILABLE:
        raise RuntimeError(
            "androguard is not installed in this environment. "
            "Install with: pip install androguard>=4.0"
        )

    result: AnalysisResult = analyze_apk(apk_path)
    if not result.success:
        raise ValueError(
            f"Failed to parse APK {apk_path}: {'; '.join(result.errors or ['unknown error'])}"
        )

    sid = sample_id or apk_path.stem
    pkg = result.package_name or "<UNKNOWN>"
    perm_names: set[str] = set((result.permissions or {}).keys())

    filter_rows = _build_filter_rows(result, sid, pkg)
    intent_rows = _build_intent_rows(filter_rows)
    resolution_rows = _build_resolution_rows(filter_rows, intent_rows, perm_names)

    return {
        "intent_rows": intent_rows,
        "filter_rows": filter_rows,
        "resolution_rows": resolution_rows,
        "app_summary": _summarize(result),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.tools.parse_manifest",
        description="Extract Android manifest features from an APK as JSON.",
    )
    parser.add_argument("apk", type=Path, help="Path to the .apk file")
    parser.add_argument("--out", type=Path, default=None,
                        help="Write JSON to this file instead of stdout")
    parser.add_argument("--pretty", action="store_true",
                        help="Indent the JSON output")
    args = parser.parse_args(argv)

    if not args.apk.exists():
        print(f"error: APK not found: {args.apk}", file=sys.stderr)
        return 2

    try:
        features = build_features(args.apk)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    payload = json.dumps(features, ensure_ascii=False,
                         indent=2 if args.pretty else None)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
