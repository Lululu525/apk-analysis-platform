from __future__ import annotations

import math
from typing import List, Set
from datetime import datetime, timezone, timedelta

from ..schemas import AnalyzeReport, ReportSummary, Finding, Artifacts


_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_BASE_SCORE = {
    "critical": 5.0,
    "high": 4.0,
    "medium": 3.0,
    "low": 2.0,
    "info": 1.0,
}

DEFAULT_EXPLOITABILITY = {
    "critical": 1.30,
    "high": 1.20,
    "medium": 1.00,
    "low": 0.90,
    "info": 0.80,
}

DEFAULT_IMPACT = {
    "critical": 1.40,
    "high": 1.25,
    "medium": 1.00,
    "low": 0.90,
    "info": 0.80,
}

DATA_SENSITIVITY_IMPACT = {
    "credentials": 1.50,
    "token": 1.50,
    "sms": 1.50,
    "otp": 1.50,
    "contacts": 1.30,
    "call_log": 1.30,
    "location": 1.30,
    "camera": 1.25,
    "microphone": 1.25,
    "storage": 1.20,
    "network": 1.10,
    "general": 1.00,
}

EXPOSURE_MODIFIER_BY_TAG = {
    "exported_component": 1.20,
    "unprotected_component": 1.20,
    "provider": 1.15,
    "service": 1.10,
    "receiver": 1.05,
    "activity": 1.00,
    "sensitive_api": 1.15,
    "network_exfiltration": 1.20,
    "reflection": 1.10,
    "command_exec": 1.20,
    "overprivileged": 1.10,
}

PERMISSION_COMBO_BONUS_RULES = [
    ({"read_sms", "internet"}, 8.0),
    ({"read_contacts", "internet"}, 6.0),
    ({"access_fine_location", "internet"}, 6.0),
    ({"camera", "record_audio"}, 7.0),
    ({"read_call_log", "internet"}, 6.0),
    ({"write_external_storage", "internet"}, 5.0),
]

OVERPRIVILEGE_BONUS = 6.0
EXPORTED_COMPONENT_BONUS_PER_ITEM = 1.5
EXPORTED_COMPONENT_BONUS_CAP = 8.0


def _now_iso() -> str:
    tz_utc_8 = timezone(timedelta(hours=8))
    return datetime.now(tz_utc_8).isoformat()


def _normalize_severity(severity: str) -> str:
    sev = (severity or "info").strip().lower()
    if sev not in SEVERITY_BASE_SCORE:
        return "info"
    return sev


def _infer_data_sensitivity(finding: Finding) -> str:
    if finding.data_sensitivity:
        return finding.data_sensitivity.strip().lower()

    haystack = " ".join(
        [
            finding.finding_id or "",
            finding.title or "",
            finding.description or "",
            finding.category or "",
            " ".join(finding.tags or []),
            str(finding.evidence or {}),
        ]
    ).lower()

    if "sms" in haystack or "otp" in haystack:
        return "sms"
    if "password" in haystack or "credential" in haystack or "secret" in haystack:
        return "credentials"
    if "token" in haystack:
        return "token"
    if "contact" in haystack:
        return "contacts"
    if "call log" in haystack or "read_call_log" in haystack:
        return "call_log"
    if "location" in haystack or "fine_location" in haystack:
        return "location"
    if "camera" in haystack:
        return "camera"
    if "microphone" in haystack or "record_audio" in haystack or "audio" in haystack:
        return "microphone"
    if "storage" in haystack:
        return "storage"
    if "internet" in haystack or "network" in haystack:
        return "network"

    return "general"


def _infer_exploitability(finding: Finding) -> float:
    if finding.exploitability is not None:
        return max(0.5, min(2.0, finding.exploitability))

    sev = _normalize_severity(finding.severity)
    value = DEFAULT_EXPLOITABILITY[sev]

    tags = {tag.strip().lower() for tag in finding.tags if tag}
    text = " ".join(
        [
            finding.finding_id or "",
            finding.title or "",
            finding.description or "",
            finding.category or "",
            str(finding.evidence or {}),
        ]
    ).lower()

    if "exported_component" in tags or "exported" in text:
        value += 0.20
    if "unprotected_component" in tags or "unprotected" in text:
        value += 0.20
    if "provider" in tags or "provider" in text:
        value += 0.10
    if "service" in tags or "service" in text:
        value += 0.08
    if "network_exfiltration" in tags:
        value += 0.15
    if "sensitive_api" in tags:
        value += 0.10
    if "command_exec" in tags:
        value += 0.20
    if "reflection" in tags:
        value += 0.10

    return max(0.5, min(2.0, value))


def _infer_impact(finding: Finding) -> float:
    if finding.impact is not None:
        return max(0.5, min(2.0, finding.impact))

    sev = _normalize_severity(finding.severity)
    value = DEFAULT_IMPACT[sev]
    sensitivity = _infer_data_sensitivity(finding)
    value *= DATA_SENSITIVITY_IMPACT.get(sensitivity, 1.0)

    return max(0.5, min(2.0, value))


def _infer_exposure(finding: Finding) -> float:
    if finding.exposure is not None:
        return max(0.5, min(2.0, finding.exposure))

    tags = {tag.strip().lower() for tag in finding.tags if tag}
    modifier = 1.0

    for tag in tags:
        modifier *= EXPOSURE_MODIFIER_BY_TAG.get(tag, 1.0)

    text = " ".join(
        [
            finding.finding_id or "",
            finding.title or "",
            finding.description or "",
            finding.category or "",
        ]
    ).lower()

    if "exported_unprotected_provider" in text:
        modifier *= 1.20
    elif "exported_unprotected_service" in text:
        modifier *= 1.15
    elif "exported_unprotected_receiver" in text:
        modifier *= 1.08
    elif "exported_unprotected_activity" in text:
        modifier *= 1.05

    return max(0.5, min(2.0, modifier))


def _score_finding(finding: Finding) -> float:
    sev = _normalize_severity(finding.severity)
    base = SEVERITY_BASE_SCORE[sev]
    confidence = max(0.3, min(1.0, finding.confidence))
    exploitability = _infer_exploitability(finding)
    impact = _infer_impact(finding)
    exposure = _infer_exposure(finding)

    final = base * confidence * exploitability * impact * exposure

    finding.score_breakdown = {
        "base": round(base, 4),
        "confidence": round(confidence, 4),
        "exploitability": round(exploitability, 4),
        "impact": round(impact, 4),
        "exposure": round(exposure, 4),
        "final": round(final, 4),
    }

    return final


def _infer_permission_tags(findings: List[Finding]) -> Set[str]:
    permission_tags: Set[str] = set()

    for finding in findings:
        text = " ".join(
            [
                finding.finding_id or "",
                finding.title or "",
                finding.description or "",
                finding.category or "",
                " ".join(finding.tags or []),
                str(finding.evidence or {}),
            ]
        ).lower()

        if "read_sms" in text:
            permission_tags.add("read_sms")
        if "internet" in text:
            permission_tags.add("internet")
        if "read_contacts" in text:
            permission_tags.add("read_contacts")
        if "access_fine_location" in text or "fine_location" in text:
            permission_tags.add("access_fine_location")
        if "camera" in text:
            permission_tags.add("camera")
        if "record_audio" in text or "microphone" in text:
            permission_tags.add("record_audio")
        if "read_call_log" in text or "call log" in text:
            permission_tags.add("read_call_log")
        if "write_external_storage" in text or "external storage" in text:
            permission_tags.add("write_external_storage")

    return permission_tags


def _permission_combo_bonus(findings: List[Finding]) -> float:
    tags = _infer_permission_tags(findings)
    bonus = 0.0

    for required_tags, rule_bonus in PERMISSION_COMBO_BONUS_RULES:
        if required_tags.issubset(tags):
            bonus += rule_bonus

    return bonus


def _overprivilege_bonus(findings: List[Finding]) -> float:
    for finding in findings:
        text = " ".join(
            [
                finding.finding_id or "",
                finding.title or "",
                finding.description or "",
                finding.category or "",
                " ".join(finding.tags or []),
            ]
        ).lower()

        if "overprivilege" in text or "overprivileged" in text:
            return OVERPRIVILEGE_BONUS

    return 0.0


def _exposed_component_bonus(findings: List[Finding]) -> float:
    count = 0
    for finding in findings:
        text = " ".join(
            [
                finding.finding_id or "",
                finding.title or "",
                finding.description or "",
                finding.category or "",
                " ".join(finding.tags or []),
            ]
        ).lower()

        if "exported_unprotected" in text or "exported component" in text:
            count += 1

    return min(count * EXPORTED_COMPONENT_BONUS_PER_ITEM, EXPORTED_COMPONENT_BONUS_CAP)


def _compress_score(raw_score: float) -> int:
    if raw_score <= 0:
        return 0
    compressed = 100 * (1 - math.exp(-raw_score / 18.0))
    return max(0, min(100, round(compressed)))


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def summarize(findings: List[Finding]) -> ReportSummary:
    counts = {sev: 0 for sev in _SEV_ORDER}  # type: ignore

    base_score = 0.0
    for finding in findings:
        sev = _normalize_severity(finding.severity)
        counts[sev] += 1
        base_score += _score_finding(finding)

    bonus = 0.0
    bonus += _permission_combo_bonus(findings)
    bonus += _overprivilege_bonus(findings)
    bonus += _exposed_component_bonus(findings)

    risk_score = _compress_score(base_score + bonus)
    risk_level = _risk_level(risk_score)

    return ReportSummary(
        risk_score=risk_score,
        risk_level=risk_level,
        counts=counts,  # type: ignore
    )


def build_report(
    job_id: str,
    started_at: str,
    findings: List[Finding],
    artifacts: Artifacts,
    errors: List[str],
) -> AnalyzeReport:
    finished_at = _now_iso()
    status = "success" if len(errors) == 0 else "failed"
    summary = summarize(findings)

    return AnalyzeReport(
        job_id=job_id,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        summary=summary,
        findings=findings,
        artifacts=artifacts,
        errors=errors,
    )