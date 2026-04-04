"""
Privilege escalation detection rule library.

Three-layer rule system:
  Layer 1: Over-privilege detection (permission count threshold)
  Layer 2: Dangerous permission combination rules
  Layer 3: IPC privilege escalation rules (re-delegation attack patterns)

References:
  [1] AndroCom: Arikan & Yilmaz, Appl. Sci. 2025, 15, 2665
      → vulnerability taxonomy, CWE/CVE mappings (Table 3)
  [2] Detection of Hidden Privilege Escalations in Android:
      El-Zawawy & Hamdy, Automated Software Engineering 2025, 32:68
      → n-order IPC escalation, permission re-delegation, attack classification
        (Section 3.2: Broadcast Theft / Service Hijacking / Confused Deputy)
      → statistical baseline: malicious avg=27.18 perms, benign avg=16.11 perms
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set, Tuple

from ..schemas import Finding
from ..extractors.androguard_analyzer import AnalysisResult, ComponentInfo


# ── Layer 1: Over-privilege threshold ────────────────────────────────────────
# Source [2] Table 2: malicious apps average 27.18 permissions vs 16.11 for
# benign apps. Threshold set at 25 to flag apps in the malicious range.
OVER_PRIVILEGE_THRESHOLD = 25


# ── Layer 2: Dangerous permission combination rules ───────────────────────────
# Source [1] Table 3: privilege escalation, information disclosure, unauthorized
# access — with associated CVEs.

@dataclass(frozen=True)
class ComboRule:
    rule_id: str
    required_perms: frozenset
    severity: str
    title: str
    cwe: Tuple[str, ...]
    cve_examples: Tuple[str, ...]
    remediation: str


COMBO_RULES: List[ComboRule] = [
    # Stalkerware: location + camera + microphone simultaneously declared
    # AndroCom [1]: Privilege Escalation, CVE-2019-16303 (Critical)
    ComboRule(
        rule_id="COMBO_STALKERWARE",
        required_perms=frozenset({
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
        }),
        severity="critical",
        title="潛在監控軟體特徵：位置 + 相機 + 麥克風同時宣告",
        cwe=("CWE-359", "CWE-269"),
        cve_examples=("CVE-2019-16303",),
        remediation=(
            "三項高敏感權限同時宣告與監控軟體特徵高度吻合。"
            "確認是否有合法使用情境，否則移除非必要項目。"
        ),
    ),
    # SMS exfiltration: read SMS + internet
    # AndroCom [1]: Information Disclosure, CVE-2017-13309 (Medium)
    ComboRule(
        rule_id="COMBO_SMS_EXFIL",
        required_perms=frozenset({
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        }),
        severity="critical",
        title="簡訊竊取風險：READ_SMS + INTERNET",
        cwe=("CWE-359", "CWE-319"),
        cve_examples=("CVE-2017-13309",),
        remediation=(
            "讀取簡訊並同時具備網路存取能力，可將 OTP / 私人簡訊外傳。"
            "若非核心功能，移除 READ_SMS 權限。"
        ),
    ),
    # Audio exfiltration: record audio + internet
    ComboRule(
        rule_id="COMBO_AUDIO_EXFIL",
        required_perms=frozenset({
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
        }),
        severity="critical",
        title="麥克風錄音外傳風險：RECORD_AUDIO + INTERNET",
        cwe=("CWE-359", "CWE-319"),
        cve_examples=(),
        remediation=(
            "應用程式可在背景錄音並透過網路上傳。"
            "確保錄音功能僅在前景執行，並明確告知使用者。"
        ),
    ),
    # Contact exfiltration: read contacts + internet
    # AndroCom [1]: Unauthorized Access, CVE-2020-8908 (Low)
    ComboRule(
        rule_id="COMBO_CONTACT_EXFIL",
        required_perms=frozenset({
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        }),
        severity="high",
        title="通訊錄外洩風險：READ_CONTACTS + INTERNET",
        cwe=("CWE-359",),
        cve_examples=("CVE-2020-8908",),
        remediation=(
            "讀取通訊錄與網路存取組合具備資料外洩能力。"
            "確認通訊錄資料不被傳送至第三方伺服器。"
        ),
    ),
    # Call interception: call log + audio
    # AndroCom [1]: Unauthorized Access, CVE-2020-8908
    ComboRule(
        rule_id="COMBO_CALL_INTERCEPT",
        required_perms=frozenset({
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
        }),
        severity="high",
        title="通話攔截風險：READ_CALL_LOG + RECORD_AUDIO",
        cwe=("CWE-359", "CWE-269"),
        cve_examples=("CVE-2020-8908",),
        remediation=(
            "通話記錄與錄音權限組合可用於攔截並記錄通話。"
            "確認兩項權限均有獨立且正當的使用情境。"
        ),
    ),
    # Overlay abuse / clickjacking: system alert window + accessibility
    ComboRule(
        rule_id="COMBO_OVERLAY_ABUSE",
        required_perms=frozenset({
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        }),
        severity="critical",
        title="覆蓋攻擊風險：SYSTEM_ALERT_WINDOW + BIND_ACCESSIBILITY_SERVICE",
        cwe=("CWE-1021", "CWE-269"),
        cve_examples=(),
        remediation=(
            "覆蓋視窗與無障礙服務組合是 Clickjacking 和憑證竊取的常見手法。"
            "確認兩項權限均為無障礙輔助功能的必要需求。"
        ),
    ),
    # Location exfiltration: fine location + internet
    ComboRule(
        rule_id="COMBO_LOCATION_EXFIL",
        required_perms=frozenset({
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        }),
        severity="high",
        title="位置資料外洩風險：ACCESS_FINE_LOCATION + INTERNET",
        cwe=("CWE-359",),
        cve_examples=(),
        remediation=(
            "精確位置資料可即時透過網路傳送。"
            "確認位置資料不被持續追蹤或傳送至未授權的第三方。"
        ),
    ),
]


# ── Layer 3: IPC privilege escalation rules ───────────────────────────────────
# Source [2] Section 3.2: four IPC attack types identified in Android ecosystem.
#
# Attack types:
#   Broadcast Theft    — unprotected exported receiver intercepts sensitive broadcasts
#   Service Hijacking  — unprotected exported service receives hijacked implicit intents
#   Confused Deputy    — exported activity/component acts on behalf of caller using
#                        its own dangerous permissions (permission re-delegation)
#   Provider leak      — unprotected exported ContentProvider exposes structured data

# Sensitive system broadcasts that should not be freely receivable
# Source [2] Section 3.1: SMS_RECEIVED and BOOT_COMPLETED cited as primary examples
SENSITIVE_BROADCAST_ACTIONS: Set[str] = {
    "android.provider.Telephony.SMS_RECEIVED",
    "android.intent.action.BOOT_COMPLETED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.CAMERA_BUTTON",
    "android.telephony.action.CARRIER_CONFIG_CHANGED",
    "android.intent.action.SIM_STATE_CHANGED",
}

# Permissions that — when held by an app with an unprotected exported component —
# indicate a Confused Deputy / permission re-delegation risk
# Source [2] Section 3.2: re-delegation = victim app uses its permissions on behalf
# of a caller that does not hold those permissions
DANGEROUS_PERMS_FOR_DEPUTY: Set[str] = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
}


def _get_intent_actions(component: ComponentInfo) -> Set[str]:
    """Return all declared intent-filter actions for a component."""
    actions: Set[str] = set()
    if not component.intent_filters:
        return actions
    for f in component.intent_filters:
        for action in (f.get("actions") or []):
            if action:
                actions.add(action)
    return actions


# ── Public API ────────────────────────────────────────────────────────────────

def check_combinations(result: AnalysisResult) -> List[Finding]:
    """
    Run all three layers of privilege escalation rules against an AnalysisResult.

    Args:
        result: Output of androguard_analyzer.analyze_apk()

    Returns:
        List of Finding objects; empty list if result.success is False.
    """
    if not result or not result.success:
        return []

    findings: List[Finding] = []

    # Normalize: permissions is Dict[str, PermissionInfo] — keys are permission names
    permission_names: Set[str] = set(result.permissions.keys()) if result.permissions else set()
    components: List[ComponentInfo] = result.components or []

    # ── Layer 1: Over-privilege ───────────────────────────────────────────────
    perm_count = len(permission_names)
    if perm_count > OVER_PRIVILEGE_THRESHOLD:
        findings.append(Finding(
            finding_id="OVER_PRIVILEGE",
            title=f"過度宣告權限（{perm_count} 項，超過惡意 App 統計基準值 {OVER_PRIVILEGE_THRESHOLD}）",
            severity="high",
            confidence=0.85,
            category="privilege_escalation",
            cwe=["CWE-250"],
            cve_examples=[],
            evidence={
                "permission_count": perm_count,
                "threshold": OVER_PRIVILEGE_THRESHOLD,
                "reference": "El-Zawawy & Hamdy 2025: malicious avg=27.18, benign avg=16.11",
            },
            remediation=(
                "依照最小權限原則（Principle of Least Privilege）逐一確認每項權限的業務用途，"
                "移除非核心功能所需的權限。"
            ),
        ))

    # ── Layer 2: Combination rules ────────────────────────────────────────────
    for rule in COMBO_RULES:
        if rule.required_perms.issubset(permission_names):
            findings.append(Finding(
                finding_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=0.9,
                category="privilege_escalation",
                cwe=list(rule.cwe),
                cve_examples=list(rule.cve_examples),
                evidence={"matched_permissions": sorted(rule.required_perms)},
                remediation=rule.remediation,
            ))

    # ── Layer 3a: Service Hijacking ───────────────────────────────────────────
    # Source [2] Section 3.2: exported service without permission protection
    # allows any app to hijack implicit intents directed at the service.
    unprotected_services = [
        c for c in components
        if c.type == "service" and c.exported and not c.permissions_required
    ]
    if unprotected_services:
        findings.append(Finding(
            finding_id="IPC_SERVICE_HIJACK",
            title=f"Service Hijacking 風險：{len(unprotected_services)} 個 exported service 無權限保護",
            severity="high",
            confidence=0.9,
            category="ipc_privilege_escalation",
            cwe=["CWE-926", "CWE-927"],
            cve_examples=[],
            evidence={
                "services": [c.name for c in unprotected_services[:10]],
                "attack_type": "Service Hijacking",
                "reference": "El-Zawawy & Hamdy 2025, Section 3.2",
            },
            remediation=(
                "為每個 exported service 加上 android:permission 屬性，"
                "或將不對外公開的服務設為 android:exported=\"false\"。"
            ),
        ))

    # ── Layer 3b: Broadcast Theft ─────────────────────────────────────────────
    # Source [2] Section 3.2: malicious receiver with no permission can intercept
    # system broadcasts before legitimate recipients.
    for comp in components:
        if comp.type != "receiver" or not comp.exported or comp.permissions_required:
            continue
        matched_actions = _get_intent_actions(comp) & SENSITIVE_BROADCAST_ACTIONS
        if matched_actions:
            short_name = comp.name.rsplit(".", 1)[-1].upper()
            findings.append(Finding(
                finding_id=f"IPC_BROADCAST_THEFT_{short_name}",
                title=f"Broadcast Theft 風險：{comp.name} 可攔截系統敏感廣播",
                severity="high",
                confidence=0.85,
                category="ipc_privilege_escalation",
                cwe=["CWE-926", "CWE-284"],
                cve_examples=[],
                evidence={
                    "receiver": comp.name,
                    "sensitive_actions": sorted(matched_actions),
                    "attack_type": "Broadcast Theft",
                    "reference": "El-Zawawy & Hamdy 2025, Section 3.2",
                },
                remediation=(
                    f"為 {comp.name} 加上 android:permission 屬性以限制廣播存取，"
                    "或改用 LocalBroadcastManager 處理 App 內部廣播。"
                ),
            ))

    # ── Layer 3c: Confused Deputy (Intent Spoofing) ───────────────────────────
    # Source [2] Section 3.2, Definition 2/3: external app calls an unprotected
    # exported component; the victim app performs actions using its own dangerous
    # permissions on behalf of the caller — a permission re-delegation attack.
    app_dangerous_perms = permission_names & DANGEROUS_PERMS_FOR_DEPUTY
    if app_dangerous_perms:
        unprotected_activities = [
            c for c in components
            if c.type == "activity" and c.exported and not c.permissions_required
        ]
        if unprotected_activities:
            findings.append(Finding(
                finding_id="IPC_CONFUSED_DEPUTY",
                title=(
                    f"Confused Deputy 風險：{len(unprotected_activities)} 個 exported activity"
                    " 可被 Intent Spoofing 利用以繞過權限管制"
                ),
                severity="high",
                confidence=0.8,
                category="ipc_privilege_escalation",
                cwe=["CWE-441", "CWE-926"],
                cve_examples=[],
                evidence={
                    "unprotected_activities": [c.name for c in unprotected_activities[:10]],
                    "dangerous_permissions_held": sorted(app_dangerous_perms),
                    "attack_type": "Confused Deputy / Intent Spoofing",
                    "reference": "El-Zawawy & Hamdy 2025, Section 3.2",
                },
                remediation=(
                    "外部 App 可透過 Intent 呼叫這些未受保護的 Activity，"
                    "間接使用本 App 的危險權限（Permission Re-delegation）。"
                    "加入 android:permission 屬性或在入口驗證 Intent 來源（checkCallingPermission）。"
                ),
            ))

    # ── Layer 3d: ContentProvider re-delegation ───────────────────────────────
    # Source [2] Section 3.2: unprotected exported ContentProvider allows any app
    # to read/write structured data without holding the corresponding permission.
    unprotected_providers = [
        c for c in components
        if c.type == "provider" and c.exported and not c.permissions_required
    ]
    if unprotected_providers:
        findings.append(Finding(
            finding_id="IPC_PROVIDER_REDELEGATION",
            title=f"ContentProvider 越權存取：{len(unprotected_providers)} 個 provider 無讀寫權限保護",
            severity="critical",
            confidence=0.95,
            category="ipc_privilege_escalation",
            cwe=["CWE-926", "CWE-276"],
            cve_examples=[],
            evidence={
                "providers": [c.name for c in unprotected_providers[:10]],
                "attack_type": "Permission Re-delegation via ContentProvider",
                "reference": "El-Zawawy & Hamdy 2025, Section 3.2",
            },
            remediation=(
                "為 ContentProvider 設定 android:readPermission 與 android:writePermission，"
                "或在 query()/insert()/update()/delete() 入口手動驗證呼叫者身份。"
            ),
        ))

    return findings
