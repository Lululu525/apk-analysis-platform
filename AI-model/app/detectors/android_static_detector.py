from __future__ import annotations

from typing import Dict, List, Tuple

from ..extractors.androguard_analyzer import AnalysisResult, ComponentInfo
from ..schemas import Finding, Severity


def findings_from_analysis(result: AnalysisResult) -> List[Finding]:
    """
    Convert extracted Android facts into static-analysis findings.

    This detector owns risk interpretation for Android manifest/API facts.
    The extractor should only populate AnalysisResult with raw facts.
    """
    if not result.success:
        return []

    findings: List[Finding] = []

    # ── 1. Dangerous permissions ──────────────────────────────────────────
    perm_severity: Dict[str, Tuple[Severity, str]] = {
        "高風險": ("high", "CWE-272"),
        "中風險": ("medium", "CWE-272"),
    }
    if result.permissions:
        for risk_label, (severity, cwe) in perm_severity.items():
            perms = [
                p.name
                for p in result.permissions.values()
                if getattr(p, "risk_level", None) == risk_label
            ]
            if not perms:
                continue
            findings.append(Finding(
                id=f"DANGEROUS_PERMISSIONS_{risk_label.replace('風險', '')}",
                title=f"聲明 {risk_label} 權限（{len(perms)} 項）",
                severity=severity,
                confidence=1.0,
                category="permission",
                cwe=[cwe, "CWE-269"],
                evidence={"permissions": perms},
                remediation=(
                    "確認每項危險權限是否真正需要；"
                    "移除不必要的權限聲明，並在程式碼中以 checkSelfPermission() 驗證後再使用。"
                ),
            ))

    # ── 2. Exported components without permission protection ──────────────
    # service / provider are covered by privilege_rules.IPC_SERVICE_HIJACK
    # and IPC_PROVIDER_REDELEGATION, which include attack-vector context.
    component_severity: Dict[str, Severity] = {
        "activity": "medium",
        "receiver": "medium",
    }

    if result.components:
        by_type: Dict[str, List[ComponentInfo]] = {}
        for comp in result.components:
            if comp.type not in component_severity:
                continue
            if comp.exported and not comp.permissions_required:
                by_type.setdefault(comp.type, []).append(comp)

        for comp_type, comps in by_type.items():
            findings.append(Finding(
                id=f"EXPORTED_UNPROTECTED_{comp_type.upper()}",
                title=f"未受保護的導出 {comp_type}（{len(comps)} 個）",
                severity=component_severity[comp_type],
                confidence=0.95,
                category="privilege_escalation",
                cwe=["CWE-926"],
                evidence={
                    "components": [
                        {"name": c.name, "intent_filters": c.intent_filters}
                        for c in comps
                    ]
                },
                remediation=(
                    f"為每個導出的 {comp_type} 加上 android:permission 屬性，"
                    "或將不需對外公開的元件設定 android:exported=\"false\"。"
                ),
            ))

    # ── 3. Sensitive API calls ────────────────────────────────────────────
    if result.sensitive_api_calls:
        findings.append(Finding(
            id="SENSITIVE_API_CALLS",
            title=f"偵測到敏感 API 呼叫（{len(result.sensitive_api_calls)} 個）",
            severity="medium",
            confidence=0.75,
            category="sensitive_api",
            cwe=["CWE-78", "CWE-95"],
            evidence={"calls": sorted(result.sensitive_api_calls)[:20]},
            remediation=(
                "審查 Runtime.exec()、反射（Class.forName / Method.invoke）"
                "和 loadLibrary() 的呼叫點，確認所有外部輸入都已驗證或白名單化。"
            ),
        ))

    # ── 4. Outdated target SDK ────────────────────────────────────────────
    if result.target_sdk and result.target_sdk < 23:
        findings.append(Finding(
            id="LOW_TARGET_SDK",
            title=f"targetSdkVersion 過舊（API {result.target_sdk}）",
            severity="medium",
            confidence=1.0,
            category="sdk_version",
            cwe=["CWE-693"],
            evidence={"target_sdk": result.target_sdk, "runtime_permission_threshold": 23},
            remediation=(
                "將 targetSdkVersion 提升至 API 33 以上；"
                "API < 23 代表 App 不使用運行時權限模型，"
                "系統會在安裝時一次授予全部權限，使用者無法個別拒絕。"
            ),
        ))

    return findings
