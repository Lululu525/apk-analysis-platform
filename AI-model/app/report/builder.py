from __future__ import annotations
from typing import List
from datetime import datetime, timezone, timedelta
from ..schemas import AnalyzeReport, ReportSummary, Finding, Artifacts

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

def _now_iso() -> str:
    tz_utc_8 = timezone(timedelta(hours=8)) 
    return datetime.now(tz_utc_8).isoformat()

def summarize(findings: List[Finding]) -> ReportSummary:
    counts = {sev: 0 for sev in _SEV_ORDER}  # type: ignore
    score = 0
    weight = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 1}
    for f in findings:
        counts[f.severity] += 1
        score += weight.get(f.severity, 0)

    # 轉成 0-100：簡單壓縮（你後面可換更合理的）
    risk_score = min(100, score)
    return ReportSummary(risk_score=risk_score, counts=counts)  # type: ignore

def build_report(job_id: str, started_at: str, findings: List[Finding], artifacts: Artifacts, errors: List[str]) -> AnalyzeReport:
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