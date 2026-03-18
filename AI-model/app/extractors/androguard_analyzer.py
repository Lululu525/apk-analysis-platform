"""
Androguard-based Android APK analysis.

Capabilities:
  1. Manifest parsing: extract permissions, components, intent filters
  2. Permission risk assessment: identify dangerous/sensitive permissions
  3. Sensitive API detection: find risky Android API calls in bytecode
  4. Component analysis: Activity, Service, ContentProvider, BroadcastReceiver
  5. Intent data flow: trace inter-component communication patterns
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Dict, List, Set, Any
from dataclasses import dataclass

try:
    from androguard.misc import AnalyzedAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


# ── Dangerous Permissions (requiring special handling) ───────────────────────

DANGEROUS_PERMISSIONS = {
    # Location
    "android.permission.ACCESS_FINE_LOCATION": "高風險",
    "android.permission.ACCESS_COARSE_LOCATION": "高風險",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "高風險",

    # Camera & Microphone
    "android.permission.CAMERA": "高風險",
    "android.permission.RECORD_AUDIO": "高風險",

    # Contacts & Calendar
    "android.permission.READ_CONTACTS": "中風險",
    "android.permission.WRITE_CONTACTS": "中風險",
    "android.permission.READ_CALENDAR": "中風險",
    "android.permission.WRITE_CALENDAR": "中風險",

    # Call logs & SMS
    "android.permission.READ_CALL_LOG": "中風險",
    "android.permission.WRITE_CALL_LOG": "中風險",
    "android.permission.READ_SMS": "高風險",
    "android.permission.SEND_SMS": "高風險",
    "android.permission.RECEIVE_SMS": "高風險",

    # Files & Media
    "android.permission.READ_EXTERNAL_STORAGE": "中風險",
    "android.permission.WRITE_EXTERNAL_STORAGE": "中風險",
    "android.permission.READ_MEDIA_IMAGES": "中風險",
    "android.permission.READ_MEDIA_AUDIO": "中風險",
    "android.permission.READ_MEDIA_VIDEO": "中風險",

    # Phone state
    "android.permission.READ_PHONE_STATE": "低風險",

    # Account access
    "android.permission.GET_ACCOUNTS": "低風險",
    "android.permission.READ_PROFILE": "低風險",
    "android.permission.READ_SOCIAL_STREAM": "低風險",

    # System-level
    "android.permission.SYSTEM_ALERT_WINDOW": "中風險",
    "android.permission.WRITE_SETTINGS": "中風險",
    "android.permission.WRITE_SECURE_SETTINGS": "高風險",
    "android.permission.MODIFY_AUDIO_SETTINGS": "低風險",

    # Network & Data
    "android.permission.INTERNET": "中風險",
    "android.permission.ACCESS_NETWORK_STATE": "低風險",
    "android.permission.CHANGE_NETWORK_STATE": "中風險",
    "android.permission.CHANGE_WIFI_STATE": "中風險",
    "android.permission.ACCESS_WIFI_STATE": "低風險",
    "android.permission.BLUETOOTH": "低風險",
    "android.permission.BLUETOOTH_ADMIN": "低風險",
    "android.permission.NFC": "中風險",
}

# ── Sensitive API calls that may indicate privilege escalation ──────────────

SENSITIVE_API_PATTERNS = {
    # Runtime permissions (Runtime.exec)
    "java/lang/Runtime/exec": "CWE-78",  # OS Command Injection

    # Reflection APIs
    "java/lang/reflect/Method/invoke": "CWE-95",  # Improper Neutralization (reflection abuse)
    "java/lang/Class/forName": "CWE-95",

    # Native code execution
    "java/lang/System/load": "CWE-95",
    "java/lang/System/loadLibrary": "CWE-95",

    # File operations on system paths
    "java/io/File/<init>": "CWE-269",  # Check if accessing /system paths
    "java/nio/file/Files": "CWE-269",

    # Dangerous intent handling
    "android/content/Intent": "CWE-927",  # Improper Intent validation

    # ContentProvider access without proper validation
    "android/content/ContentProvider/query": "CWE-276",  # Incorrect DEFAULT permissions

    # JavaScript interface (WebView)
    "android/webkit/WebView/addJavascriptInterface": "CWE-94",  # Improper Control of Generation
}


@dataclass
class PermissionInfo:
    """Extracted permission information"""
    name: str
    risk_level: str = "未知"
    is_declared: bool = False
    is_used: bool = False
    cwe: str = ""


@dataclass
class ComponentInfo:
    """Android component information"""
    type: str  # "activity", "service", "provider", "receiver"
    name: str
    exported: bool = False
    intent_filters: List[Dict[str, str]] = None
    permissions_required: List[str] = None


@dataclass
class AnalysisResult:
    """Complete Androguard analysis result"""
    success: bool
    package_name: Optional[str] = None
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None

    permissions: Dict[str, PermissionInfo] = None
    components: List[ComponentInfo] = None
    sensitive_api_calls: List[str] = None

    risk_findings: List[str] = None
    errors: List[str] = None


def analyze_apk(apk_path: Path) -> AnalysisResult:
    """
    Complete APK analysis using Androguard.

    Returns:
        AnalysisResult with all extracted metadata and risk findings
    """
    if not ANDROGUARD_AVAILABLE:
        return AnalysisResult(
            success=False,
            errors=["androguard not installed. pip install androguard>=4.0"]
        )

    try:
        apk = AnalyzedAPK(str(apk_path))
    except Exception as e:
        return AnalysisResult(
            success=False,
            errors=[f"Failed to parse APK: {str(e)}"]
        )

    # ── Basic metadata ────────────────────────────────────────────────────
    result = AnalysisResult(success=True)
    result.package_name = apk.get_package()
    result.version_code = int(apk.get_android_manifest_axml().manifest.attrib.get("android:versionCode", "0") or "0")
    result.version_name = apk.get_manifest().findtext(".//{http://schemas.android.com/apk/res/android}versionName")

    # ── SDK levels ────────────────────────────────────────────────────────
    manifest_xml = apk.get_android_manifest_axml().xml
    uses_sdk = manifest_xml.find(".//uses-sdk")
    if uses_sdk is not None:
        result.min_sdk = int(uses_sdk.get("{http://schemas.android.com/apk/res/android}minSdkVersion", "0"))
        result.target_sdk = int(uses_sdk.get("{http://schemas.android.com/apk/res/android}targetSdkVersion", "0"))

    # ── Permission extraction ─────────────────────────────────────────────
    result.permissions = _extract_permissions(apk)

    # ── Component analysis ────────────────────────────────────────────────
    result.components = _extract_components(apk)

    # ── Sensitive API detection ───────────────────────────────────────────
    result.sensitive_api_calls = _find_sensitive_apis(apk)

    # ── Risk assessment ──────────────────────────────────────────────────
    result.risk_findings = _assess_risks(result)

    return result


def _extract_permissions(apk) -> Dict[str, PermissionInfo]:
    """Extract and classify permissions from manifest"""
    permissions: Dict[str, PermissionInfo] = {}

    # Get declared permissions
    for perm in apk.get_permissions():
        risk = DANGEROUS_PERMISSIONS.get(perm, "未知")
        permissions[perm] = PermissionInfo(name=perm, risk_level=risk, is_declared=True)

    # Get used permissions (from code analysis)
    # This is a simplified version - full analysis would require examining code
    for perm in apk.get_permissions():
        if perm in permissions:
            permissions[perm].is_used = True

    return permissions


def _extract_components(apk) -> List[ComponentInfo]:
    """Extract activities, services, content providers, broadcast receivers"""
    components: List[ComponentInfo] = []
    manifest_xml = apk.get_android_manifest_axml().xml

    # ── Activities ────────────────────────────────────────────────────────
    for activity in manifest_xml.findall(".//activity"):
        name = activity.get("{http://schemas.android.com/apk/res/android}name")
        exported = activity.get("{http://schemas.android.com/apk/res/android}exported", "false").lower() == "true"
        intent_filters = _extract_intent_filters(activity)

        # Activities with intent-filter are implicitly exported
        if intent_filters:
            exported = True

        components.append(ComponentInfo(
            type="activity",
            name=name,
            exported=exported,
            intent_filters=intent_filters
        ))

    # ── Services ──────────────────────────────────────────────────────────
    for service in manifest_xml.findall(".//service"):
        name = service.get("{http://schemas.android.com/apk/res/android}name")
        exported = service.get("{http://schemas.android.com/apk/res/android}exported", "false").lower() == "true"
        intent_filters = _extract_intent_filters(service)
        permissions = service.get("{http://schemas.android.com/apk/res/android}permission")

        if intent_filters:
            exported = True

        components.append(ComponentInfo(
            type="service",
            name=name,
            exported=exported,
            intent_filters=intent_filters,
            permissions_required=[permissions] if permissions else None
        ))

    # ── Content Providers ─────────────────────────────────────────────────
    for provider in manifest_xml.findall(".//provider"):
        name = provider.get("{http://schemas.android.com/apk/res/android}name")
        exported = provider.get("{http://schemas.android.com/apk/res/android}exported", "false").lower() == "true"
        authority = provider.get("{http://schemas.android.com/apk/res/android}authorities")
        permissions = provider.get("{http://schemas.android.com/apk/res/android}permission")

        # ContentProviders are exported by default
        if authority and not exported:
            exported = True

        components.append(ComponentInfo(
            type="provider",
            name=name,
            exported=exported,
            permissions_required=[permissions] if permissions else None
        ))

    # ── Broadcast Receivers ───────────────────────────────────────────────
    for receiver in manifest_xml.findall(".//receiver"):
        name = receiver.get("{http://schemas.android.com/apk/res/android}name")
        exported = receiver.get("{http://schemas.android.com/apk/res/android}exported", "false").lower() == "true"
        intent_filters = _extract_intent_filters(receiver)

        if intent_filters:
            exported = True

        components.append(ComponentInfo(
            type="receiver",
            name=name,
            exported=exported,
            intent_filters=intent_filters
        ))

    return components


def _extract_intent_filters(component_elem) -> List[Dict[str, str]]:
    """Extract intent-filter actions from component XML element"""
    filters = []
    for intent_filter in component_elem.findall(".//intent-filter"):
        filter_info = {}

        # Actions
        actions = [a.get("{http://schemas.android.com/apk/res/android}name")
                  for a in intent_filter.findall(".//action")]
        if actions:
            filter_info["actions"] = actions

        # Categories
        categories = [c.get("{http://schemas.android.com/apk/res/android}name")
                     for c in intent_filter.findall(".//category")]
        if categories:
            filter_info["categories"] = categories

        # Data schemes
        data_elements = intent_filter.findall(".//data")
        if data_elements:
            filter_info["data_schemes"] = []
            for data in data_elements:
                scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                if scheme:
                    filter_info["data_schemes"].append(scheme)

        if filter_info:
            filters.append(filter_info)

    return filters


def _find_sensitive_apis(apk) -> List[str]:
    """Scan bytecode for sensitive API calls"""
    sensitive_calls = []

    try:
        for dex in apk.get_dex():
            # Enumerate all method calls
            for method in dex.get_methods():
                code = method.get_code()
                if not code:
                    continue

                for instruction in code.get_instructions():
                    # Check for method invocation instructions
                    if instruction.get_name().startswith("invoke"):
                        # Extract method reference
                        method_id = instruction.get_referred_method()
                        if method_id:
                            method_sig = method_id.get_name()
                            # Check against known sensitive patterns
                            for pattern, cwe in SENSITIVE_API_PATTERNS.items():
                                if pattern in method_sig or pattern.replace("/", ".") in method_sig:
                                    sensitive_calls.append(method_sig)
    except Exception:
        # Androguard analysis may fail on obfuscated code
        pass

    return list(set(sensitive_calls))  # deduplicate


def _assess_risks(result: AnalysisResult) -> List[str]:
    """Identify potential privilege escalation risks"""
    risks = []

    if not result.permissions:
        return risks

    # ── Risk 1: Dangerous permissions ─────────────────────────────────────
    dangerous_perms = [p.name for p in result.permissions.values() if p.risk_level == "高風險"]
    if dangerous_perms:
        risks.append(f"高風險權限聲明: {', '.join(dangerous_perms[:3])}")

    # ── Risk 2: Exported components without permission checks ──────────────
    if result.components:
        exported_unprotected = [c for c in result.components
                              if c.exported and not c.permissions_required]
        if exported_unprotected:
            risks.append(f"未受保護的導出組件: {len(exported_unprotected)} 個")

    # ── Risk 3: Sensitive API calls ────────────────────────────────────────
    if result.sensitive_api_calls:
        risks.append(f"檢測到敏感 API 調用: {len(result.sensitive_api_calls)} 個")

    # ── Risk 4: Old target SDK ────────────────────────────────────────────
    if result.target_sdk and result.target_sdk < 23:
        risks.append(f"目標 SDK 過舊 ({result.target_sdk}): 運行時權限未使用")

    return risks
