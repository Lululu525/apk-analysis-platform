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
import sys
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    if not comp.permissions_required:
        return None
    return comp.permissions_required[0]


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
        if comp.exported and not comp.permissions_required:
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
