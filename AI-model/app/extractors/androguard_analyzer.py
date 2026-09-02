"""
Androguard-based Android APK analysis.

Capabilities:
  1. Manifest parsing: extract permissions, components, intent filters
  2. Permission metadata extraction
  3. Sensitive API detection: find risky Android API calls in bytecode
  4. Component analysis: Activity, Service, ContentProvider, BroadcastReceiver
"""
from __future__ import annotations

import builtins
import locale

from pathlib import Path
from typing import Optional, Dict, List, Union
from dataclasses import dataclass

from .sensitive_api_callers import scan_sensitive_api_callers

# Androguard's bundled resource loaders call open(path, "r") without an
# explicit encoding. On non-UTF-8 locales (e.g. Windows cp950), JSON resources
# loaded later by api_specific_resources can therefore raise UnicodeDecodeError.
# Keep the locale shim before importing Androguard for import-time resources,
# then bind the explicit wrapper below to the later JSON loaders.
locale.getpreferredencoding = lambda do_setlocale=True: "utf-8"


def _open_androguard_text_resource(file, mode="r", *args, **kwargs):
    """Open Androguard's bundled text resources as UTF-8 on every locale."""
    if "b" not in mode:
        kwargs.setdefault("encoding", "utf-8")
    return builtins.open(file, mode, *args, **kwargs)

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core import api_specific_resources as _api_resources

    # These vendor functions call an unqualified module-global open(). Point
    # that name at a UTF-8 wrapper without replacing builtins.open globally.
    _api_resources.open = _open_androguard_text_resource  # type: ignore[attr-defined]
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
    name: Optional[str] = None   # 封裝過的 manifest 可能抓不到元件名稱
    exported: bool = False
    intent_filters: Optional[List[Dict[str, Union[str, List[str]]]]] = None
    permissions_required: Optional[List[str]] = None
    grant_uri_permissions: bool = False
    # Effective per-side permissions for ContentProviders only.
    # A generic android:permission covers both sides unless read/write-specific
    # permissions override that side.
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    # ContentProvider-only. Raw android:authorities value, kept as-is (not
    # split on ";" even though the platform allows multiple authorities in
    # one attribute) — splitting is a separate design decision left for when
    # a concrete consumer actually needs the individual authority strings.
    authorities: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete Androguard analysis result"""
    success: bool
    package_name: Optional[str] = None
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None

    permissions: Optional[Dict[str, PermissionInfo]] = None
    components: Optional[List[ComponentInfo]] = None
    sensitive_api_calls: Optional[List[str]] = None
    sensitive_api_callers: Optional[List[Dict[str, object]]] = None
    sensitive_api_scan_status: str = "not_attempted"
    sensitive_api_scan_error_count: int = 0
    sensitive_api_scan_error_message: Optional[str] = None

    errors: Optional[List[str]] = None


def analyze_apk(apk_path: Path) -> AnalysisResult:
    """
    Complete APK analysis using Androguard.

    Returns:
        AnalysisResult with extracted Android facts.
    """
    if not ANDROGUARD_AVAILABLE:
        return AnalysisResult(
            success=False,
            errors=["androguard not installed. pip install androguard>=4.0"]
        )

    try:
        apk, dexes, analysis = AnalyzeAPK(str(apk_path))
    except Exception as e:
        return AnalysisResult(
            success=False,
            errors=[f"Failed to parse APK: {str(e)}"]
        )

    # ── Basic metadata ────────────────────────────────────────────────────
    result = AnalysisResult(success=True)
    result.package_name = apk.get_package()
    _axml = apk.get_android_manifest_axml()
    assert _axml is not None, "APK has no AndroidManifest.xml"
    manifest_xml = _axml.get_xml_obj()
    _NS = "{http://schemas.android.com/apk/res/android}"
    result.version_name = manifest_xml.get(f"{_NS}versionName")
    try:
        result.version_code = int(manifest_xml.get(f"{_NS}versionCode", "0") or "0")
    except (ValueError, TypeError):
        result.version_code = 0

    # ── SDK levels ────────────────────────────────────────────────────────
    uses_sdk = manifest_xml.find(".//uses-sdk")
    if uses_sdk is not None:
        result.min_sdk = int(uses_sdk.get("{http://schemas.android.com/apk/res/android}minSdkVersion", "0"))
        result.target_sdk = int(uses_sdk.get("{http://schemas.android.com/apk/res/android}targetSdkVersion", "0"))

    # ── Permission extraction ─────────────────────────────────────────────
    result.permissions = _extract_permissions(apk)

    # ── Component analysis ────────────────────────────────────────────────
    result.components = _extract_components(apk)

    # ── Sensitive API detection ───────────────────────────────────────────
    caller_scan = scan_sensitive_api_callers(analysis)
    result.sensitive_api_callers = caller_scan.callers
    result.sensitive_api_scan_status = caller_scan.status
    result.sensitive_api_scan_error_count = caller_scan.error_count
    result.sensitive_api_scan_error_message = caller_scan.error_message
    result.sensitive_api_calls = sorted({
        f"{row['api_class']}.{row['api_method']}"
        for row in caller_scan.callers
    })

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
    _axml = apk.get_android_manifest_axml()
    assert _axml is not None, "APK has no AndroidManifest.xml"
    manifest_xml = _axml.get_xml_obj()

    def _get_android_attr(elem, attr_name: str, default=None):
        """讀取 android: namespace 的屬性值。部分惡意程式會產生「被封裝」的
        AndroidManifest.xml，讓某些屬性的 namespace 前綴消失。這裡在 namespace
        版本找不到時，回退嘗試沒有 namespace 的同名屬性。
        """
        value = elem.get(f"{{http://schemas.android.com/apk/res/android}}{attr_name}")
        if value is None:
            value = elem.get(attr_name)
        return value if value is not None else default

    # ── Activities ────────────────────────────────────────────────────────
    for activity in manifest_xml.findall(".//activity"):
        name = _get_android_attr(activity, "name")
        exported_attr = _get_android_attr(activity, "exported")
        intent_filters = _extract_intent_filters(activity)
        permissions = _get_android_attr(activity, "permission")

        if exported_attr is not None:
            exported = exported_attr.lower() == "true"
        else:
            exported = bool(intent_filters)

        components.append(ComponentInfo(
            type="activity",
            name=name,
            exported=exported,
            intent_filters=intent_filters,
            permissions_required=[permissions] if permissions else None
        ))

    # ── Services ──────────────────────────────────────────────────────────
    for service in manifest_xml.findall(".//service"):
        name = _get_android_attr(service, "name")
        exported_attr = _get_android_attr(service, "exported")
        intent_filters = _extract_intent_filters(service)
        permissions = _get_android_attr(service, "permission")

        if exported_attr is not None:
            exported = exported_attr.lower() == "true"
        else:
            exported = bool(intent_filters)

        components.append(ComponentInfo(
            type="service",
            name=name,
            exported=exported,
            intent_filters=intent_filters,
            permissions_required=[permissions] if permissions else None
        ))

    # ── Content Providers ─────────────────────────────────────────────────
    for provider in manifest_xml.findall(".//provider"):
        name = _get_android_attr(provider, "name")
        exported = _get_android_attr(provider, "exported", "false").lower() == "true"
        authority = _get_android_attr(provider, "authorities")
        permissions = _get_android_attr(provider, "permission")
        read_permission = _get_android_attr(provider, "readPermission")
        write_permission = _get_android_attr(provider, "writePermission")
        grant_uri_permissions = _get_android_attr(
            provider, "grantUriPermissions", "false"
        ).lower() == "true"
        permissions_required = [
            permission
            for permission in (permissions, read_permission, write_permission)
            if permission is not None
        ]
        effective_read_permission = read_permission or permissions
        effective_write_permission = write_permission or permissions

        components.append(ComponentInfo(
            type="provider",
            name=name,
            exported=exported,
            permissions_required=permissions_required or None,
            grant_uri_permissions=grant_uri_permissions,
            read_permission=effective_read_permission,
            write_permission=effective_write_permission,
            authorities=authority,
        ))

    # ── Broadcast Receivers ───────────────────────────────────────────────
    for receiver in manifest_xml.findall(".//receiver"):
        name = _get_android_attr(receiver, "name")
        exported_attr = _get_android_attr(receiver, "exported")
        intent_filters = _extract_intent_filters(receiver)
        permissions = _get_android_attr(receiver, "permission")

        if exported_attr is not None:
            exported = exported_attr.lower() == "true"
        else:
            exported = bool(intent_filters)

        components.append(ComponentInfo(
            type="receiver",
            name=name,
            exported=exported,
            intent_filters=intent_filters,
            permissions_required=[permissions] if permissions else None
        ))

    return components


def _extract_intent_filters(component_elem) -> List[Dict[str, Union[str, List[str]]]]:
    """Extract intent-filter metadata (actions, categories, data schemes,
    MIME types) from a component XML element.

    Schema per filter dict (Option A: parallel lists, not per-<data>-element
    pairing — matches the El-Zawawy & Hamdy 2025 feature vector consumed by
    parse_manifest.build_features):
        {"actions": [...], "categories": [...],
         "data_schemes": [...], "data_types": [...]}
    Empty lists are dropped — callers should use dict.get(key) or iterate
    only present keys.
    """
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

        # Data schemes + MIME types from <data> elements
        data_elements = intent_filter.findall(".//data")
        if data_elements:
            schemes: List[str] = []
            mime_types: List[str] = []
            for data in data_elements:
                scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                if scheme:
                    schemes.append(scheme)
                mime = data.get("{http://schemas.android.com/apk/res/android}mimeType")
                if mime:
                    mime_types.append(mime)
            if schemes:
                filter_info["data_schemes"] = schemes
            if mime_types:
                filter_info["data_types"] = mime_types

        if filter_info:
            filters.append(filter_info)

    return filters
