from __future__ import annotations
from typing import List
from .schemas import Finding


# 高風險權限
HIGH_RISK_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
}

# 網路權限（常用來外傳資料）
NETWORK_PERMS = {
    "android.permission.INTERNET",
}


def analyze_android_risk(ag_result) -> List[Finding]:
    findings: List[Finding] = []

    if not ag_result or not ag_result.success:
        return findings

    permissions = set(ag_result.permissions or [])
    exported_components = ag_result.exported_components or []

    # ─────────────────────────────────────────────
    # 1️⃣ 高風險權限
    # ─────────────────────────────────────────────
    for perm in HIGH_RISK_PERMS:
        if perm in permissions:
            findings.append(Finding(
                finding_id=f"APK_HIGH_RISK_PERMISSION_{perm.split('.')[-1]}",
                title=f"High-risk permission used: {perm}",
                severity="high",
                confidence=0.9,
                category="android_permission",
                cwe=["CWE-250"],
                evidence={"permission": perm},
                remediation="Ensure this permission is necessary and justified.",
            ))

    # ─────────────────────────────────────────────
    # 2️⃣ 權限組合（資料外洩）
    # ─────────────────────────────────────────────
    if "android.permission.READ_SMS" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(Finding(
            finding_id="APK_SMS_EXFILTRATION",
            title="App can read SMS and access network (possible data exfiltration)",
            severity="critical",
            confidence=0.95,
            category="android_behavior",
            cwe=["CWE-359"],
            evidence={"permissions": ["READ_SMS", "INTERNET"]},
            remediation="Restrict access or justify usage of both permissions.",
        ))

    if "android.permission.READ_CONTACTS" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(Finding(
            finding_id="APK_CONTACTS_EXFILTRATION",
            title="App can read contacts and access network",
            severity="high",
            confidence=0.9,
            category="android_behavior",
            cwe=["CWE-359"],
            evidence={"permissions": ["READ_CONTACTS", "INTERNET"]},
            remediation="Ensure contacts are not transmitted externally.",
        ))

    if "android.permission.RECORD_AUDIO" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(Finding(
            finding_id="APK_AUDIO_SPYING",
            title="App can record audio and access network",
            severity="critical",
            confidence=0.95,
            category="android_behavior",
            cwe=["CWE-532"],
            evidence={"permissions": ["RECORD_AUDIO", "INTERNET"]},
            remediation="Prevent unauthorized audio recording or transmission.",
        ))

    # ─────────────────────────────────────────────
    # 3️⃣ exported component 風險
    # ─────────────────────────────────────────────
    for comp in exported_components:
        findings.append(Finding(
            finding_id="APK_EXPORTED_COMPONENT",
            title="Exported component without proper protection",
            severity="high",
            confidence=0.85,
            category="android_component",
            cwe=["CWE-926"],
            evidence={"component": comp},
            remediation="Restrict exported components or add permission protection.",
        ))

    # ─────────────────────────────────────────────
    # 4️⃣ 權限數量過多
    # ─────────────────────────────────────────────
    if len(permissions) > 15:
        findings.append(Finding(
            finding_id="APK_TOO_MANY_PERMISSIONS",
            title="App requests excessive number of permissions",
            severity="medium",
            confidence=0.8,
            category="android_permission",
            cwe=["CWE-250"],
            evidence={"count": len(permissions)},
            remediation="Reduce unnecessary permissions.",
        ))

    return findings