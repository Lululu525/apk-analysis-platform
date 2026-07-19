from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .schemas import AnalyzeRequest, AnalyzeReport, Artifacts, Finding
from .detectors.rules import scan_text_for_rules
from .detectors.strings_detector import extract_strings, extract_strings_from_dir
from .detectors.network_detector import scan_strings as net_scan_strings
from .detectors.android_static_detector import findings_from_analysis
from .extractors.dex_parser import extract_strings_from_dex
from .extractors.androguard_analyzer import (
    analyze_apk,
    ANDROGUARD_AVAILABLE,
)
from app.ml.predictor import FilterRowPredictor, app_level_risk, MODEL_VERSION
from .detectors.privilege_rules import check_combinations as check_privilege_escalation
from .tools.parse_manifest import build_model_features
from .report.builder import build_report

AI_MODEL_ROOT = Path(__file__).resolve().parent.parent
FILTER_ROW_MODEL_DIR = Path(
    os.environ.get(
        "FILTER_ROW_MODEL_DIR",
        str(AI_MODEL_ROOT / "dataset" / "training" / "model_v1"),
    )
)


def _now_iso() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


_SCAN_SUFFIXES = {
    ".dex",
    ".so",
    ".xml",
    ".json",
    ".txt",
    ".js",
    ".html",
    ".properties",
    ".conf",
    ".cfg",
}
_SKIP_PREFIXES = {"res/drawable", "res/mipmap", "res/anim", "res/color", "res/raw/"}


def _should_scan_entry(name: str) -> bool:
    name_lower = name.lower()
    for prefix in _SKIP_PREFIXES:
        if name_lower.startswith(prefix):
            return False
    suffix = Path(name).suffix.lower()
    return suffix in _SCAN_SUFFIXES or suffix == ""


def _extract_apk(apk_path: Path, dest: Path) -> tuple[int, list[str]]:
    dest.mkdir(parents=True, exist_ok=True)
    extracted = 0
    skipped: list[str] = []

    try:
        with zipfile.ZipFile(apk_path) as zf:
            for entry in zf.infolist():
                if entry.is_dir():
                    continue
                if not _should_scan_entry(entry.filename):
                    skipped.append(entry.filename)
                    continue

                out_path = dest / entry.filename
                out_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    out_path.write_bytes(zf.read(entry.filename))
                    extracted += 1
                except Exception:
                    skipped.append(entry.filename)
    except zipfile.BadZipFile as e:
        return 0, [f"BadZipFile: {e}"]

    return extracted, skipped


def _safe_slug(value: str) -> str:
    return (
        value.lower()
        .replace("android.permission.", "")
        .replace(".", "_")
        .replace(" ", "_")
    )


def _append_unique_tags(finding: Finding, tags: list[str]) -> None:
    existing = {tag.lower() for tag in finding.tags}
    for tag in tags:
        normalized = tag.strip()
        if normalized and normalized.lower() not in existing:
            finding.tags.append(normalized)
            existing.add(normalized.lower())


def _infer_android_context_for_finding(finding: Finding) -> None:
    haystack = " ".join(
        [
            finding.id or "",
            finding.title or "",
            finding.description or "",
            finding.category or "",
            " ".join(finding.cwe or []),
            json.dumps(finding.evidence or {}, ensure_ascii=False),
        ]
    ).lower()

    tags: list[str] = []

    permission = (finding.evidence or {}).get("permission")
    if isinstance(permission, str) and permission:
        tags.append("dangerous_permission")
        tags.append(permission.lower())
        tags.append(_safe_slug(permission))

    permissions = (finding.evidence or {}).get("permissions")
    if isinstance(permissions, list):
        lowered_permissions = []
        for perm in permissions:
            if isinstance(perm, str):
                lowered_permissions.append(perm.lower())
                tags.append(perm.lower())
                tags.append(_safe_slug(perm))

        if any("internet" in perm for perm in lowered_permissions):
            tags.append("network_exfiltration")

    if "exported" in haystack:
        tags.append("exported_component")

    if "unprotected" in haystack:
        tags.append("unprotected_component")

    if "provider" in haystack:
        tags.append("provider")

    if "service" in haystack:
        tags.append("service")

    if "receiver" in haystack:
        tags.append("receiver")

    if "activity" in haystack:
        tags.append("activity")

    if "runtime.exec" in haystack or "command" in haystack:
        tags.append("command_exec")
        tags.append("sensitive_api")

    if "webview" in haystack or "javascriptinterface" in haystack:
        tags.append("sensitive_api")

    if "class.forname" in haystack or "method.invoke" in haystack or "reflection" in haystack:
        tags.append("reflection")
        tags.append("sensitive_api")

    if "too_many_permissions" in haystack or "overprivilege" in haystack or "overprivileged" in haystack:
        tags.append("overprivileged")

    if finding.category == "android_permission":
        tags.append("android_permission")
    elif finding.category == "android_component":
        tags.append("android_component")
    elif finding.category == "android_behavior":
        tags.append("android_behavior")
    elif finding.category == "analysis_limitation":
        tags.append("analysis_limitation")

    _append_unique_tags(finding, tags)


def _enrich_android_findings(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        _infer_android_context_for_finding(finding)
    return findings


def run(req: AnalyzeRequest, output_dir: Path | None = None) -> AnalyzeReport:
    started_at = _now_iso()
    errors: list[str] = []
    findings: list[Finding] = []
    ml_risk_assessment: Finding | None = None

    fp = req.firmware.file_path
    if not fp:
        errors.append("firmware.file_path (APK path) is missing.")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    apk_path = Path(fp)
    if not apk_path.exists():
        errors.append(f"APK file not found: {apk_path}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    ag_result = None

    try:
        sha256 = _sha256_file(apk_path)
        size_bytes = apk_path.stat().st_size
        with zipfile.ZipFile(apk_path) as zf:
            all_entries = zf.namelist()
    except Exception as e:
        errors.append(f"failed to read APK: {e}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    extract_dir: Path | None = None
    strings_list: list[str] = []
    strings_method = "none"
    extracted_count = 0

    if output_dir:
        extract_dir = output_dir / "apk_extracted"
        extracted_count, _ = _extract_apk(apk_path, extract_dir)

    if extract_dir and extract_dir.exists() and extracted_count > 0:
        for dex_file in sorted(extract_dir.rglob("*.dex")):
            dex_strings = extract_strings_from_dex(dex_file, min_len=6, limit=3000)
            strings_list.extend(dex_strings)

        per_file = extract_strings_from_dir(
            extract_dir,
            min_len=6,
            per_file_limit=1000,
            file_limit=40,
        )
        for fname, s_list in per_file.items():
            if not fname.endswith(".dex"):
                strings_list.extend(s_list)

        strings_method = "dex_parser+per_file"
    else:
        strings_list, strings_method = extract_strings(apk_path, min_len=6)

    strings_list = strings_list[:5000]

    if req.options.run_static_scan:
        findings.extend(scan_text_for_rules("\n".join(strings_list)))

    findings.extend(net_scan_strings(strings_list))

    if ANDROGUARD_AVAILABLE:
        ag_result = analyze_apk(apk_path)

        androguard_findings = findings_from_analysis(ag_result)
        findings.extend(_enrich_android_findings(androguard_findings))

        if ag_result.success:
            findings.extend(check_privilege_escalation(ag_result))
        else:
            findings.append(
                Finding(
                    id="ANDROGUARD_PARSE_ERROR",
                    title="Androguard could not parse this APK manifest",
                    severity="info",
                    confidence=1.0,
                    category="analysis_limitation",
                    evidence={"errors": (ag_result.errors or [])[:3]},
                    remediation=(
                        "Make sure the APK is valid. Obfuscation or hardening may cause "
                        "manifest parsing to fail."
                    ),
                    tags=["analysis_limitation"],
                )
            )
    else:
        findings.append(
            Finding(
                id="TOOL_ANDROGUARD_MISSING",
                title="Androguard is not installed - manifest, permission, and component analysis skipped",
                severity="info",
                confidence=1.0,
                category="analysis_limitation",
                evidence={"hint": "pip install androguard>=4.0"},
                remediation=(
                    "Install androguard to enable AndroidManifest permission and "
                    "exported-component analysis."
                ),
                tags=["analysis_limitation"],
            )
        )

    artifacts = Artifacts()
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

        manifest_features: dict[str, Any] | None = None
        if ag_result is not None and getattr(ag_result, "success", False):
            _perms = getattr(ag_result, "permissions", {}) or {}
            _comps = getattr(ag_result, "components", []) or []
            _exported = [c for c in _comps if getattr(c, "exported", False)]
            manifest_features = {
                "package_name": getattr(ag_result, "package_name", None),
                "app_name": getattr(ag_result, "app_name", None),
                "permissions": list(_perms.keys()) if isinstance(_perms, dict) else list(_perms),
                "permissions_count": len(_perms),
                "exported_components": [getattr(c, "name", str(c)) for c in _exported],
                "exported_count": len(_exported),
            }

        features: dict[str, Any] = {
            "job_id": req.job_id,
            "apk": {
                "name": req.firmware.name,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "total_entries": len(all_entries),
                "extracted_for_scan": extracted_count,
            },
            "device_meta": req.device_meta.model_dump() if req.device_meta else None,
            "options": req.options.model_dump(),
            "stats": {
                "strings_count": len(strings_list),
                "strings_method": strings_method,
            },
            "manifest_analysis": manifest_features,
        }

        features_path = output_dir / f"{req.job_id}.features.json"
        features_path.write_text(
            json.dumps(features, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        artifacts.features_path = str(features_path)

        if ag_result is not None and getattr(ag_result, "success", False):
            try:
                ml_features = build_model_features(apk_path, sample_id=req.job_id)
            except Exception as exc:
                findings.append(
                    Finding(
                        id="ML_FEATURE_EXTRACTION_FAILED",
                        title="ML feature extraction failed",
                        severity="info",
                        confidence=1.0,
                        category="analysis_limitation",
                        evidence={"error": str(exc)},
                        remediation=(
                            "Check APK parseability and row-level feature builder inputs."
                        ),
                        tags=["analysis_limitation", "ml_feature_extraction"],
                    )
                )
            else:
                ml_features_path = output_dir / f"{req.job_id}.ml_features.json"
                ml_features_path.write_text(
                    json.dumps(ml_features, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                artifacts.ml_features_path = str(ml_features_path)

                try:
                    predictor = FilterRowPredictor.load(FILTER_ROW_MODEL_DIR)
                except FileNotFoundError:
                    findings.append(
                        Finding(
                            id="MODEL_NOT_AVAILABLE",
                            title="ML risk model not available",
                            severity="info",
                            confidence=1.0,
                            category="analysis_limitation",
                            evidence={"model_dir": str(FILTER_ROW_MODEL_DIR)},
                            remediation=(
                                "Train the filter_row model (see docs/PLAN.md Task 6) "
                                "to enable ML risk assessment."
                            ),
                            tags=["analysis_limitation", "ml_prediction"],
                        )
                    )
                else:
                    try:
                        predictions = predictor.predict_raw_rows(ml_features["filter_rows"])
                    except Exception as exc:
                        findings.append(
                            Finding(
                                id="ML_PREDICTION_FAILED",
                                title="ML risk prediction failed",
                                severity="info",
                                confidence=1.0,
                                category="analysis_limitation",
                                evidence={"error": str(exc)},
                                tags=["analysis_limitation", "ml_prediction"],
                            )
                        )
                    else:
                        ml_predictions_path = (
                            output_dir / f"{req.job_id}.ml_predictions.json"
                        )
                        ml_predictions_path.write_text(
                            json.dumps(predictions, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
                        artifacts.ml_predictions_path = str(ml_predictions_path)

                        risk = app_level_risk(predictions)
                        if risk is not None:
                            ml_risk_assessment = Finding(
                                id="ML_RISK_ASSESSMENT",
                                title=(
                                    "ML model risk assessment "
                                    f"(app_risk_probability={risk:.2f})"
                                ),
                                severity="info",
                                confidence=1.0,
                                category="ml_risk_assessment",
                                evidence={
                                    "app_risk_probability": risk,
                                    "model_version": MODEL_VERSION,
                                    "component_predictions": predictions,
                                },
                                tags=["ml_prediction"],
                            )

        strings_path = output_dir / f"{req.job_id}.strings.txt"
        strings_path.write_text(
            "\n".join(strings_list[:2000]),
            encoding="utf-8",
            errors="ignore",
        )
        artifacts.strings_path = str(strings_path)

        if extract_dir:
            artifacts.extracted_path = str(extract_dir)

    report = build_report(req.job_id, started_at, findings, artifacts, errors)
    if ml_risk_assessment is not None:
        report.findings.append(ml_risk_assessment)
        report.summary.counts["info"] = report.summary.counts.get("info", 0) + 1
    return report
