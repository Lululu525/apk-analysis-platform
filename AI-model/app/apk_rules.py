from __future__ import annotations

from typing import List

from .schemas import Finding


HIGH_RISK_PERMS = {
    "android.permission.READ_SMS": "sms",
    "android.permission.SEND_SMS": "sms",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.ACCESS_FINE_LOCATION": "location",
}

NETWORK_PERMS = {
    "android.permission.INTERNET",
}


def _perm_slug(permission_name: str) -> str:
    return permission_name.lower().replace("android.permission.", "")


def analyze_android_risk(ag_result) -> List[Finding]:
    findings: List[Finding] = []

    if not ag_result or not ag_result.success:
        return findings

    permissions = set(ag_result.permissions or [])
    exported_components = ag_result.exported_components or []

    for perm, sensitivity in HIGH_RISK_PERMS.items():
        if perm in permissions:
            findings.append(
                Finding(
                    finding_id=f"APK_HIGH_RISK_PERMISSION_{perm.split('.')[-1]}",
                    title=f"High-risk permission used: {perm}",
                    severity="high",
                    confidence=0.9,
                    category="android_permission",
                    cwe=["CWE-250"],
                    evidence={"permission": perm},
                    remediation="Ensure this permission is necessary and justified.",
                    data_sensitivity=sensitivity,
                    tags=["dangerous_permission", _perm_slug(perm)],
                )
            )

    if "android.permission.INTERNET" in permissions:
        findings.append(
            Finding(
                finding_id="APK_NETWORK_CAPABILITY",
                title="App has network transmission capability",
                severity="info",
                confidence=0.95,
                category="android_permission",
                cwe=[],
                evidence={"permission": "android.permission.INTERNET"},
                remediation="Ensure outbound network communication is necessary and expected.",
                data_sensitivity="network",
                tags=["internet", "network_capability"],
            )
        )

    if "android.permission.READ_SMS" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(
            Finding(
                finding_id="APK_SMS_EXFILTRATION",
                title="App can read SMS and access network (possible data exfiltration)",
                severity="critical",
                confidence=0.95,
                category="android_behavior",
                cwe=["CWE-359"],
                evidence={"permissions": ["READ_SMS", "INTERNET"]},
                remediation="Restrict access or justify usage of both permissions.",
                data_sensitivity="sms",
                tags=["read_sms", "internet", "network_exfiltration", "sensitive_api"],
                exploitability=1.4,
                impact=1.5,
                exposure=1.2,
            )
        )

    if "android.permission.READ_CONTACTS" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(
            Finding(
                finding_id="APK_CONTACTS_EXFILTRATION",
                title="App can read contacts and access network",
                severity="high",
                confidence=0.9,
                category="android_behavior",
                cwe=["CWE-359"],
                evidence={"permissions": ["READ_CONTACTS", "INTERNET"]},
                remediation="Ensure contacts are not transmitted externally.",
                data_sensitivity="contacts",
                tags=["read_contacts", "internet", "network_exfiltration"],
                exploitability=1.3,
                impact=1.3,
                exposure=1.15,
            )
        )

    if "android.permission.RECORD_AUDIO" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(
            Finding(
                finding_id="APK_AUDIO_SPYING",
                title="App can record audio and access network",
                severity="critical",
                confidence=0.95,
                category="android_behavior",
                cwe=["CWE-532"],
                evidence={"permissions": ["RECORD_AUDIO", "INTERNET"]},
                remediation="Prevent unauthorized audio recording or transmission.",
                data_sensitivity="microphone",
                tags=["record_audio", "internet", "network_exfiltration"],
                exploitability=1.4,
                impact=1.4,
                exposure=1.15,
            )
        )

    if "android.permission.ACCESS_FINE_LOCATION" in permissions and "android.permission.INTERNET" in permissions:
        findings.append(
            Finding(
                finding_id="APK_LOCATION_TRACKING",
                title="App can access precise location and network",
                severity="high",
                confidence=0.9,
                category="android_behavior",
                cwe=["CWE-359"],
                evidence={"permissions": ["ACCESS_FINE_LOCATION", "INTERNET"]},
                remediation="Ensure location data is strictly required and not transmitted unnecessarily.",
                data_sensitivity="location",
                tags=["access_fine_location", "internet", "network_exfiltration"],
                exploitability=1.3,
                impact=1.3,
                exposure=1.10,
            )
        )

    if "android.permission.CAMERA" in permissions and "android.permission.RECORD_AUDIO" in permissions:
        findings.append(
            Finding(
                finding_id="APK_AUDIO_VIDEO_SURVEILLANCE",
                title="App can access both camera and microphone",
                severity="critical",
                confidence=0.9,
                category="android_behavior",
                cwe=["CWE-359"],
                evidence={"permissions": ["CAMERA", "RECORD_AUDIO"]},
                remediation="Ensure background surveillance capability is not abused.",
                data_sensitivity="camera",
                tags=["camera", "record_audio", "sensitive_api"],
                exploitability=1.2,
                impact=1.45,
                exposure=1.05,
            )
        )

    for comp in exported_components:
        comp_name = str(comp)

        tags = ["exported_component", "unprotected_component"]
        comp_lower = comp_name.lower()

        if "provider" in comp_lower:
            tags.append("provider")
            exploitability = 1.35
            impact = 1.25
            exposure = 1.20
        elif "service" in comp_lower:
            tags.append("service")
            exploitability = 1.30
            impact = 1.20
            exposure = 1.15
        elif "receiver" in comp_lower:
            tags.append("receiver")
            exploitability = 1.15
            impact = 1.10
            exposure = 1.08
        else:
            tags.append("activity")
            exploitability = 1.10
            impact = 1.05
            exposure = 1.05

        findings.append(
            Finding(
                finding_id="APK_EXPORTED_COMPONENT",
                title="Exported component without proper protection",
                severity="high",
                confidence=0.85,
                category="android_component",
                cwe=["CWE-926"],
                evidence={"component": comp_name},
                remediation="Restrict exported components or add permission protection.",
                tags=tags,
                exploitability=exploitability,
                impact=impact,
                exposure=exposure,
            )
        )

    if len(permissions) > 15:
        findings.append(
            Finding(
                finding_id="APK_TOO_MANY_PERMISSIONS",
                title="App requests excessive number of permissions",
                severity="medium",
                confidence=0.8,
                category="android_permission",
                cwe=["CWE-250"],
                evidence={"count": len(permissions)},
                remediation="Reduce unnecessary permissions.",
                tags=["overprivileged"],
                exploitability=1.1,
                impact=1.1,
                exposure=1.0,
            )
        )

    return findings