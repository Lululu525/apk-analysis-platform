"""
KAN-39: 提取敏感 API 使用行為

此模組負責：
1. 定義完整的敏感 API 列表（GPS、Contacts、Camera、SMS、Microphone 等）
2. 掃描 DEX bytecode，找出每個 API 的呼叫位置（caller class / method / offset）
3. 回傳結構化的 SensitiveApiCall 清單，供 pipeline 轉換為 Finding

掃描策略：
  - 使用 Androguard 的 dx.get_method_analysis() 取得 cross-reference（XREFs）
  - 若 Androguard 無法使用，則退回到 Smali 字串匹配
  - 每個 API 群組（GPS、Contacts…）獨立成一個 Finding，方便前端分類顯示
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..schemas import Finding, Severity


# ────────────────────────────────────────────────────────────────────────────────
# 1. 敏感 API 定義表
#    格式：
#      group_id      → 群組識別碼（對應一個 Finding）
#      group_label   → 中文顯示名稱
#      severity      → Finding 嚴重度
#      cwe           → 相關 CWE 清單
#      apis          → List[(class_path, method_name, description)]
#
#    class_path 使用 Smali 路徑格式（斜線分隔），方便同時比對 Smali 文字與
#    Androguard method reference。
# ────────────────────────────────────────────────────────────────────────────────

@dataclass
class SensitiveApiDef:
    class_path: str     # e.g. "android/location/LocationManager"
    method_name: str    # e.g. "requestLocationUpdates"
    description: str    # 中文說明


@dataclass
class ApiGroup:
    group_id: str
    group_label: str
    severity: Severity
    cwe: List[str]
    remediation: str
    apis: List[SensitiveApiDef]


SENSITIVE_API_GROUPS: List[ApiGroup] = [
    # ── GPS / Location ────────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_GPS",
        group_label="GPS / 位置 API",
        severity="high",
        cwe=["CWE-359", "CWE-200"],
        remediation=(
            "確認 App 確實需要精確位置；優先使用 ACCESS_COARSE_LOCATION。"
            "在取得位置前必須以 checkSelfPermission() 驗證權限，"
            "且不得在背景長時間持續追蹤使用者。"
        ),
        apis=[
            SensitiveApiDef("android/location/LocationManager", "requestLocationUpdates", "請求持續位置更新"),
            SensitiveApiDef("android/location/LocationManager", "requestSingleUpdate", "請求單次位置更新"),
            SensitiveApiDef("android/location/LocationManager", "getLastKnownLocation", "取得最後已知位置"),
            SensitiveApiDef("android/location/LocationManager", "addGpsStatusListener", "監聽 GPS 狀態"),
            SensitiveApiDef("android/location/LocationManager", "addNmeaListener", "監聽原始 NMEA 衛星訊號"),
            SensitiveApiDef("com/google/android/gms/location/FusedLocationProviderClient", "requestLocationUpdates", "Google Fused 位置持續更新"),
            SensitiveApiDef("com/google/android/gms/location/FusedLocationProviderClient", "getLastLocation", "Google Fused 最後位置"),
            SensitiveApiDef("com/google/android/gms/location/FusedLocationProviderClient", "getCurrentLocation", "Google Fused 即時位置"),
        ],
    ),

    # ── Contacts ──────────────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_CONTACTS",
        group_label="聯絡人 API",
        severity="high",
        cwe=["CWE-359", "CWE-200"],
        remediation=(
            "讀取聯絡人前需動態申請 READ_CONTACTS；"
            "避免一次載入全部聯絡人並傳送至遠端伺服器。"
        ),
        apis=[
            SensitiveApiDef("android/content/ContentResolver", "query", "查詢 ContentProvider（可能存取聯絡人）"),
            SensitiveApiDef("android/provider/ContactsContract$Contacts", "getLookupUri", "取得聯絡人 Lookup URI"),
            SensitiveApiDef("android/provider/ContactsContract$CommonDataKinds$Phone", "getTypeLabel", "取得電話號碼類型"),
            SensitiveApiDef("android/provider/ContactsContract$CommonDataKinds$Email", "getTypeLabel", "取得 Email 類型"),
            SensitiveApiDef("android/database/Cursor", "getString", "從 Cursor 取得聯絡人欄位值"),
        ],
    ),

    # ── Camera ────────────────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_CAMERA",
        group_label="相機 API",
        severity="high",
        cwe=["CWE-359"],
        remediation=(
            "使用相機前須動態申請 CAMERA 權限。"
            "使用 CameraX 或 Intent 方式拍照以降低敏感面；"
            "不得在使用者不知情的情況下拍攝。"
        ),
        apis=[
            SensitiveApiDef("android/hardware/Camera", "open", "開啟舊版相機（deprecated）"),
            SensitiveApiDef("android/hardware/Camera", "takePicture", "舊版相機拍照"),
            SensitiveApiDef("android/hardware/Camera", "startPreview", "開始相機預覽"),
            SensitiveApiDef("android/hardware/camera2/CameraManager", "openCamera", "開啟 Camera2 相機"),
            SensitiveApiDef("android/hardware/camera2/CameraDevice", "createCaptureRequest", "建立拍攝請求"),
            SensitiveApiDef("android/hardware/camera2/CameraCaptureSession", "capture", "執行拍攝"),
            SensitiveApiDef("android/hardware/camera2/CameraCaptureSession", "setRepeatingRequest", "持續拍攝（串流）"),
            SensitiveApiDef("androidx/camera/core/ImageCapture", "takePicture", "CameraX 拍照"),
        ],
    ),

    # ── Microphone / Audio ────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_MICROPHONE",
        group_label="麥克風 / 錄音 API",
        severity="high",
        cwe=["CWE-359"],
        remediation=(
            "錄音前須動態申請 RECORD_AUDIO；"
            "錄音完畢立即呼叫 release()，不得在背景靜默錄音。"
        ),
        apis=[
            SensitiveApiDef("android/media/MediaRecorder", "start", "開始錄音/錄影"),
            SensitiveApiDef("android/media/MediaRecorder", "setAudioSource", "設定音訊來源"),
            SensitiveApiDef("android/media/AudioRecord", "<init>", "初始化 AudioRecord（低層錄音）"),
            SensitiveApiDef("android/media/AudioRecord", "startRecording", "開始低層錄音"),
            SensitiveApiDef("android/media/AudioRecord", "read", "讀取錄音 buffer"),
        ],
    ),

    # ── SMS / 電話 ────────────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_SMS_PHONE",
        group_label="SMS / 電話 API",
        severity="high",
        cwe=["CWE-359", "CWE-862"],
        remediation=(
            "發送 SMS 前須動態申請 SEND_SMS；"
            "讀取通話紀錄須申請 READ_CALL_LOG。"
            "明確告知使用者發送對象與內容，防止惡意扣費行為。"
        ),
        apis=[
            SensitiveApiDef("android/telephony/SmsManager", "sendTextMessage", "傳送 SMS 文字訊息"),
            SensitiveApiDef("android/telephony/SmsManager", "sendMultipartTextMessage", "傳送多段 SMS"),
            SensitiveApiDef("android/telephony/SmsManager", "sendDataMessage", "傳送 SMS 資料訊息"),
            SensitiveApiDef("android/telephony/TelephonyManager", "getDeviceId", "取得裝置 IMEI（已 deprecated）"),
            SensitiveApiDef("android/telephony/TelephonyManager", "getImei", "取得 IMEI"),
            SensitiveApiDef("android/telephony/TelephonyManager", "getSubscriberId", "取得 IMSI"),
            SensitiveApiDef("android/telephony/TelephonyManager", "getLine1Number", "取得電話號碼"),
            SensitiveApiDef("android/telephony/TelephonyManager", "getSimSerialNumber", "取得 SIM 卡序號"),
            SensitiveApiDef("android/net/Uri", "withAppendedPath", "組合 CallLog URI（可能存取通話紀錄）"),
        ],
    ),

    # ── 裝置識別碼 / 追蹤 ─────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_DEVICE_ID",
        group_label="裝置識別碼 / 追蹤 API",
        severity="medium",
        cwe=["CWE-359", "CWE-200"],
        remediation=(
            "避免使用 IMEI、MAC、Android ID 作為持久追蹤識別碼。"
            "改用 Advertising ID，並遵守 Google Play 廣告政策。"
        ),
        apis=[
            SensitiveApiDef("android/provider/Settings$Secure", "getString", "取得 Android ID / 安全設定值"),
            SensitiveApiDef("android/net/wifi/WifiInfo", "getMacAddress", "取得 Wi-Fi MAC 位址"),
            SensitiveApiDef("android/bluetooth/BluetoothAdapter", "getAddress", "取得藍牙 MAC 位址"),
            SensitiveApiDef("com/google/android/gms/ads/identifier/AdvertisingIdClient", "getAdvertisingIdInfo", "取得廣告識別碼"),
            SensitiveApiDef("android/os/Build", "getSerial", "取得裝置序號"),
        ],
    ),

    # ── 檔案 / 儲存 ───────────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_STORAGE",
        group_label="外部儲存 / 檔案 API",
        severity="medium",
        cwe=["CWE-732", "CWE-200"],
        remediation=(
            "讀取/寫入外部儲存需申請 READ/WRITE_EXTERNAL_STORAGE（API < 29）"
            "或使用 MediaStore API（API ≥ 29）。"
            "避免將敏感資料寫入公開目錄。"
        ),
        apis=[
            SensitiveApiDef("android/os/Environment", "getExternalStorageDirectory", "取得外部儲存根目錄"),
            SensitiveApiDef("android/os/Environment", "getExternalStoragePublicDirectory", "取得外部公開目錄"),
            SensitiveApiDef("java/io/FileOutputStream", "<init>", "開啟檔案寫入串流"),
            SensitiveApiDef("java/io/FileInputStream", "<init>", "開啟檔案讀取串流"),
        ],
    ),

    # ── 網路 / 剪貼簿 ─────────────────────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_NETWORK_CLIPBOARD",
        group_label="網路傳輸 / 剪貼簿 API",
        severity="medium",
        cwe=["CWE-319", "CWE-311"],
        remediation=(
            "所有網路傳輸應使用 HTTPS；"
            "讀取剪貼簿需在前景且使用者明確操作後才執行，"
            "避免在背景靜默竊取剪貼簿內容。"
        ),
        apis=[
            SensitiveApiDef("java/net/URL", "openConnection", "開啟 HTTP/HTTPS 連線"),
            SensitiveApiDef("okhttp3/OkHttpClient", "newCall", "OkHttp 發起請求"),
            SensitiveApiDef("android/content/ClipboardManager", "getPrimaryClip", "讀取剪貼簿內容"),
            SensitiveApiDef("android/content/ClipboardManager", "setPrimaryClip", "寫入剪貼簿內容"),
        ],
    ),

    # ── 系統命令執行 / 反射 / 動態載入 ──────────────────────────────────────────
    ApiGroup(
        group_id="SENSITIVE_API_CODE_EXEC",
        group_label="命令執行 / 反射 / 動態載入 API",
        severity="critical",
        cwe=["CWE-78", "CWE-95", "CWE-502"],
        remediation=(
            "避免使用 Runtime.exec() 執行系統命令；"
            "動態載入程式碼（DexClassLoader）需嚴格驗證來源路徑與完整性（簽章驗證）。"
            "反射（Class.forName / Method.invoke）若接受外部輸入則會造成程式碼注入風險。"
        ),
        apis=[
            SensitiveApiDef("java/lang/Runtime", "exec", "執行系統命令"),
            SensitiveApiDef("java/lang/ProcessBuilder", "start", "啟動子行程"),
            SensitiveApiDef("java/lang/Class", "forName", "反射載入類別"),
            SensitiveApiDef("java/lang/reflect/Method", "invoke", "反射呼叫方法"),
            SensitiveApiDef("java/lang/System", "loadLibrary", "載入 Native Library"),
            SensitiveApiDef("java/lang/System", "load", "載入指定路徑 Native Library"),
            SensitiveApiDef("dalvik/system/DexClassLoader", "<init>", "動態載入 DEX/APK"),
            SensitiveApiDef("dalvik/system/PathClassLoader", "<init>", "從路徑載入 DEX"),
            SensitiveApiDef("android/webkit/WebView", "addJavascriptInterface", "WebView 注入 Java 介面（CVE 常見點）"),
            SensitiveApiDef("android/webkit/WebView", "loadUrl", "WebView 載入 URL"),
            SensitiveApiDef("android/webkit/WebView", "evaluateJavascript", "執行任意 JavaScript"),
        ],
    ),
]

# 建立快速查找字典：(class_path_lower, method_name_lower) → (ApiGroup, SensitiveApiDef)
_API_INDEX: Dict[Tuple[str, str], Tuple[ApiGroup, SensitiveApiDef]] = {}
for _group in SENSITIVE_API_GROUPS:
    for _api in _group.apis:
        _key = (_api.class_path.lower(), _api.method_name.lower())
        _API_INDEX[_key] = (_group, _api)


# ────────────────────────────────────────────────────────────────────────────────
# 2. 掃描結果資料結構
# ────────────────────────────────────────────────────────────────────────────────

@dataclass
class SensitiveApiCall:
    """一筆敏感 API 呼叫記錄"""
    group_id: str
    group_label: str
    api_class: str       # 被呼叫的 API class（Smali 格式）
    api_method: str      # 被呼叫的 API 方法名稱
    description: str     # 中文說明
    caller_class: str    # 呼叫者 class
    caller_method: str   # 呼叫者方法
    caller_descriptor: str = ""  # 方法描述子（參數/回傳型別）


# ────────────────────────────────────────────────────────────────────────────────
# 3. Androguard 深度掃描（使用 XREF cross-reference）
# ────────────────────────────────────────────────────────────────────────────────

def scan_with_androguard(dexes: Any) -> List[SensitiveApiCall]:
    """
    利用 Androguard 的 cross-reference 精確找出每個敏感 API 的呼叫位置。

    Androguard dx (Analysis) 提供 get_method_analysis() / find_methods()，
    可直接反查所有呼叫某方法的 caller，不需逐 instruction 遍歷。

    Args:
        dexes: androguard AnalyzeAPK 回傳的第三個元素（Analysis 物件），
               或 DEXs list（若傳入 list 則使用逐 instruction 模式作為備援）。

    Returns:
        List[SensitiveApiCall]
    """
    calls: List[SensitiveApiCall] = []
    seen: set = set()

    # dexes 可能是 Analysis 物件或 list，統一處理
    analysis_obj = dexes if not isinstance(dexes, list) else None
    dex_list = dexes if isinstance(dexes, list) else []

    if analysis_obj is not None:
        # 優先路徑：使用 Analysis.find_methods() + XREF
        calls.extend(_scan_via_analysis(analysis_obj, seen))
    else:
        # 備援路徑：逐 DEX 逐 instruction
        for dex in dex_list:
            calls.extend(_scan_via_instructions(dex, seen))

    return calls


def _smali_class_to_dotted(smali: str) -> str:
    """android/location/LocationManager → android.location.LocationManager"""
    return smali.replace("/", ".")


def _match_api(class_name: str, method_name: str) -> Optional[Tuple["ApiGroup", "SensitiveApiDef"]]:
    """
    比對一個 (class, method) 是否屬於任何敏感 API 定義。
    class_name 可以是 Smali 格式（斜線）或 Java 格式（點）。
    """
    normalized_class = class_name.lower().replace(".", "/").lstrip("l").rstrip(";")
    normalized_method = method_name.lower()
    return _API_INDEX.get((normalized_class, normalized_method))


def _scan_via_analysis(analysis, seen: set) -> List[SensitiveApiCall]:
    """使用 Androguard Analysis 物件的 XREF 做反向查詢"""
    calls: List[SensitiveApiCall] = []

    try:
        for group in SENSITIVE_API_GROUPS:
            for api_def in group.apis:
                # find_methods 接受 class_name, method_name 正規表示式
                class_pattern = api_def.class_path.replace("/", r"\/")
                method_pattern = f"^{api_def.method_name}$" if api_def.method_name != "<init>" else r"^<init>$"

                try:
                    for method_analysis in analysis.find_methods(
                        classname=f"L{api_def.class_path};",
                        methodname=api_def.method_name,
                    ):
                        # 取得所有呼叫此方法的 caller
                        for _, caller_method_analysis, _ in method_analysis.get_xref_from():
                            caller_class = caller_method_analysis.class_name
                            caller_method_name = caller_method_analysis.name
                            caller_desc = caller_method_analysis.descriptor

                            key = (group.group_id, api_def.class_path, api_def.method_name,
                                   caller_class, caller_method_name)
                            if key in seen:
                                continue
                            seen.add(key)

                            calls.append(SensitiveApiCall(
                                group_id=group.group_id,
                                group_label=group.group_label,
                                api_class=api_def.class_path,
                                api_method=api_def.method_name,
                                description=api_def.description,
                                caller_class=caller_class,
                                caller_method=caller_method_name,
                                caller_descriptor=caller_desc or "",
                            ))
                except Exception:
                    continue
    except Exception:
        pass

    return calls


def _scan_via_instructions(dex: Any, seen: set) -> List[SensitiveApiCall]:
    """
    備援路徑：逐 method 逐 instruction 掃描。
    適用於 Androguard 版本較舊或傳入的是 DEX list 的情況。
    """
    calls: List[SensitiveApiCall] = []

    try:
        for method in dex.get_methods():
            code = method.get_code()
            if not code:
                continue

            caller_class = method.get_class_name()
            caller_method_name = method.get_name()
            caller_desc = method.get_descriptor() or ""

            for instruction in code.get_instructions():
                if not instruction.get_name().startswith("invoke"):
                    continue

                try:
                    ref = instruction.get_referred_method()
                    if ref is None:
                        continue

                    # get_referred_method 回傳的格式因版本而異，統一取 class/name
                    ref_class = ref.get_class_name() if hasattr(ref, "get_class_name") else str(ref)
                    ref_method = ref.get_name() if hasattr(ref, "get_name") else ""

                    match = _match_api(ref_class, ref_method)
                    if match is None:
                        continue

                    matched_group, matched_api = match
                    key = (matched_group.group_id, matched_api.class_path, matched_api.method_name,
                           caller_class, caller_method_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    calls.append(SensitiveApiCall(
                        group_id=matched_group.group_id,
                        group_label=matched_group.group_label,
                        api_class=matched_api.class_path,
                        api_method=matched_api.method_name,
                        description=matched_api.description,
                        caller_class=caller_class,
                        caller_method=caller_method_name,
                        caller_descriptor=caller_desc,
                    ))
                except Exception:
                    continue
    except Exception:
        pass

    return calls


# ────────────────────────────────────────────────────────────────────────────────
# 4. Smali 文字掃描（純字串比對，適用於無 Androguard 場景）
# ────────────────────────────────────────────────────────────────────────────────

def scan_strings_for_sensitive_apis(strings: List[str]) -> List[SensitiveApiCall]:
    """
    對字串列表做簡單比對，找出含有敏感 API class/method 的字串。
    此為低精確度備援方案，不含 caller 資訊。
    """
    calls: List[SensitiveApiCall] = []
    seen: set = set()

    joined = "\n".join(strings).lower()

    for group in SENSITIVE_API_GROUPS:
        for api_def in group.apis:
            # 同時匹配 Smali 格式（斜線）與 Java 格式（點）
            smali_sig = f"{api_def.class_path}/{api_def.method_name}".lower()
            java_sig = f"{_smali_class_to_dotted(api_def.class_path)}.{api_def.method_name}".lower()

            if smali_sig in joined or java_sig in joined:
                key = (group.group_id, api_def.class_path, api_def.method_name)
                if key in seen:
                    continue
                seen.add(key)

                calls.append(SensitiveApiCall(
                    group_id=group.group_id,
                    group_label=group.group_label,
                    api_class=api_def.class_path,
                    api_method=api_def.method_name,
                    description=api_def.description,
                    caller_class="(字串掃描，無 caller 資訊)",
                    caller_method="",
                    caller_descriptor="",
                ))

    return calls


# ────────────────────────────────────────────────────────────────────────────────
# 5. 轉換為 Finding 清單
# ────────────────────────────────────────────────────────────────────────────────

def calls_to_findings(calls: List[SensitiveApiCall]) -> List[Finding]:
    """
    將 SensitiveApiCall 清單依 group_id 聚合，每個群組產生一個 Finding。
    Finding.evidence 結構：
      {
        "total_call_sites": int,
        "call_sites": [
          {
            "api": "android/location/LocationManager.requestLocationUpdates",
            "description": "請求持續位置更新",
            "callers": ["Lcom/example/MapActivity;->onCreate(...)V", ...]
          },
          ...
        ]
      }
    """
    if not calls:
        return []

    # group_id → {api_key → SensitiveApiCall 集合}
    by_group: Dict[str, Dict[str, List[SensitiveApiCall]]] = {}
    group_meta: Dict[str, ApiGroup] = {g.group_id: g for g in SENSITIVE_API_GROUPS}

    for call in calls:
        api_key = f"{call.api_class}.{call.api_method}"
        by_group.setdefault(call.group_id, {}).setdefault(api_key, []).append(call)

    findings: List[Finding] = []

    for group_id, api_map in by_group.items():
        meta = group_meta.get(group_id)
        if meta is None:
            continue

        call_sites = []
        total = 0
        for api_key, site_calls in api_map.items():
            callers = []
            for c in site_calls:
                if c.caller_class and c.caller_method:
                    sig = f"{c.caller_class}->{c.caller_method}{c.caller_descriptor}"
                    callers.append(sig)
                elif c.caller_class:
                    callers.append(c.caller_class)

            call_sites.append({
                "api": api_key,
                "description": site_calls[0].description,
                "callers": list(dict.fromkeys(callers))[:10],  # 去重，最多 10 筆
            })
            total += len(callers) if callers else 1

        call_sites.sort(key=lambda x: x["api"])

        findings.append(Finding(
            id=group_id,
            title=f"偵測到{meta.group_label}呼叫（{len(call_sites)} 種 API，{total} 個呼叫點）",
            severity=meta.severity,
            confidence=0.9,
            category="sensitive_api",
            cwe=meta.cwe,
            description=(
                f"App 程式碼中含有 {meta.group_label} 相關的敏感 API 呼叫。"
                f"共發現 {len(call_sites)} 種不同 API，{total} 個呼叫位置。"
            ),
            evidence={
                "total_call_sites": total,
                "call_sites": call_sites,
            },
            remediation=meta.remediation,
            tags=["sensitive_api", group_id.lower(), meta.group_label],
        ))

    # 依嚴重度排序
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))

    return findings
