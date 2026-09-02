"""以 Androguard XREF 擷取可稽核的敏感 API caller 證據。

此模組只做 caller/callee identity 擷取，不宣稱 component entry 可到達 caller、
輸入可受攻擊者控制，或路徑缺少有效的 runtime authorization guard。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SensitiveApiSpec:
    group_id: str
    group_label: str
    api_class: str
    api_method: str
    description: str


@dataclass
class SensitiveApiScanResult:
    status: str
    callers: List[Dict[str, Any]]
    error_count: int = 0
    error_message: Optional[str] = None


def _spec(
    group_id: str,
    group_label: str,
    api_class: str,
    api_method: str,
    description: str,
) -> SensitiveApiSpec:
    return SensitiveApiSpec(
        group_id=group_id,
        group_label=group_label,
        api_class=api_class,
        api_method=api_method,
        description=description,
    )


# 由 KAN-39 prototype 提升出的 pilot allowlist。類別與方法必須同時相符，
# 避免只用 method name（例如 start/query/read）造成大量誤判。
SENSITIVE_API_SPECS: Tuple[SensitiveApiSpec, ...] = (
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "android/location/LocationManager", "requestLocationUpdates", "請求持續位置更新"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "android/location/LocationManager", "requestSingleUpdate", "請求單次位置更新"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "android/location/LocationManager", "getLastKnownLocation", "取得最後已知位置"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "android/location/LocationManager", "addGpsStatusListener", "監聽 GPS 狀態"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "android/location/LocationManager", "addNmeaListener", "監聽原始 NMEA 衛星訊號"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "com/google/android/gms/location/FusedLocationProviderClient", "requestLocationUpdates", "Google Fused 位置持續更新"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "com/google/android/gms/location/FusedLocationProviderClient", "getLastLocation", "Google Fused 最後位置"),
    _spec("SENSITIVE_API_GPS", "GPS / 位置 API", "com/google/android/gms/location/FusedLocationProviderClient", "getCurrentLocation", "Google Fused 即時位置"),
    _spec("SENSITIVE_API_CONTACTS", "聯絡人 API", "android/content/ContentResolver", "query", "查詢 ContentProvider（可能存取聯絡人）"),
    _spec("SENSITIVE_API_CONTACTS", "聯絡人 API", "android/provider/ContactsContract$Contacts", "getLookupUri", "取得聯絡人 Lookup URI"),
    _spec("SENSITIVE_API_CONTACTS", "聯絡人 API", "android/provider/ContactsContract$CommonDataKinds$Phone", "getTypeLabel", "取得電話號碼類型"),
    _spec("SENSITIVE_API_CONTACTS", "聯絡人 API", "android/provider/ContactsContract$CommonDataKinds$Email", "getTypeLabel", "取得 Email 類型"),
    _spec("SENSITIVE_API_CONTACTS", "聯絡人 API", "android/database/Cursor", "getString", "從 Cursor 取得欄位值（需另行確認資料來源）"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/Camera", "open", "開啟舊版相機"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/Camera", "takePicture", "舊版相機拍照"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/Camera", "startPreview", "開始相機預覽"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/camera2/CameraManager", "openCamera", "開啟 Camera2 相機"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/camera2/CameraDevice", "createCaptureRequest", "建立拍攝請求"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/camera2/CameraCaptureSession", "capture", "執行拍攝"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "android/hardware/camera2/CameraCaptureSession", "setRepeatingRequest", "持續拍攝"),
    _spec("SENSITIVE_API_CAMERA", "相機 API", "androidx/camera/core/ImageCapture", "takePicture", "CameraX 拍照"),
    _spec("SENSITIVE_API_MICROPHONE", "麥克風 / 錄音 API", "android/media/MediaRecorder", "start", "開始錄音或錄影"),
    _spec("SENSITIVE_API_MICROPHONE", "麥克風 / 錄音 API", "android/media/MediaRecorder", "setAudioSource", "設定音訊來源"),
    _spec("SENSITIVE_API_MICROPHONE", "麥克風 / 錄音 API", "android/media/AudioRecord", "<init>", "初始化 AudioRecord"),
    _spec("SENSITIVE_API_MICROPHONE", "麥克風 / 錄音 API", "android/media/AudioRecord", "startRecording", "開始低層錄音"),
    _spec("SENSITIVE_API_MICROPHONE", "麥克風 / 錄音 API", "android/media/AudioRecord", "read", "讀取錄音 buffer"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/SmsManager", "sendTextMessage", "傳送 SMS 文字訊息"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/SmsManager", "sendMultipartTextMessage", "傳送多段 SMS"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/SmsManager", "sendDataMessage", "傳送 SMS 資料訊息"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/TelephonyManager", "getDeviceId", "取得裝置 IMEI"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/TelephonyManager", "getImei", "取得 IMEI"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/TelephonyManager", "getSubscriberId", "取得 IMSI"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/TelephonyManager", "getLine1Number", "取得電話號碼"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/telephony/TelephonyManager", "getSimSerialNumber", "取得 SIM 卡序號"),
    _spec("SENSITIVE_API_SMS_PHONE", "SMS / 電話 API", "android/net/Uri", "withAppendedPath", "組合可能指向通話紀錄的 URI"),
    _spec("SENSITIVE_API_DEVICE_ID", "裝置識別碼 / 追蹤 API", "android/provider/Settings$Secure", "getString", "取得 Android ID 或安全設定值"),
    _spec("SENSITIVE_API_DEVICE_ID", "裝置識別碼 / 追蹤 API", "android/net/wifi/WifiInfo", "getMacAddress", "取得 Wi-Fi MAC 位址"),
    _spec("SENSITIVE_API_DEVICE_ID", "裝置識別碼 / 追蹤 API", "android/bluetooth/BluetoothAdapter", "getAddress", "取得藍牙 MAC 位址"),
    _spec("SENSITIVE_API_DEVICE_ID", "裝置識別碼 / 追蹤 API", "com/google/android/gms/ads/identifier/AdvertisingIdClient", "getAdvertisingIdInfo", "取得廣告識別碼"),
    _spec("SENSITIVE_API_DEVICE_ID", "裝置識別碼 / 追蹤 API", "android/os/Build", "getSerial", "取得裝置序號"),
    _spec("SENSITIVE_API_STORAGE", "外部儲存 / 檔案 API", "android/os/Environment", "getExternalStorageDirectory", "取得外部儲存根目錄"),
    _spec("SENSITIVE_API_STORAGE", "外部儲存 / 檔案 API", "android/os/Environment", "getExternalStoragePublicDirectory", "取得外部公開目錄"),
    _spec("SENSITIVE_API_STORAGE", "外部儲存 / 檔案 API", "java/io/FileOutputStream", "<init>", "開啟檔案寫入串流"),
    _spec("SENSITIVE_API_STORAGE", "外部儲存 / 檔案 API", "java/io/FileInputStream", "<init>", "開啟檔案讀取串流"),
    _spec("SENSITIVE_API_NETWORK_CLIPBOARD", "網路傳輸 / 剪貼簿 API", "java/net/URL", "openConnection", "開啟 HTTP/HTTPS 連線"),
    _spec("SENSITIVE_API_NETWORK_CLIPBOARD", "網路傳輸 / 剪貼簿 API", "okhttp3/OkHttpClient", "newCall", "OkHttp 發起請求"),
    _spec("SENSITIVE_API_NETWORK_CLIPBOARD", "網路傳輸 / 剪貼簿 API", "android/content/ClipboardManager", "getPrimaryClip", "讀取剪貼簿內容"),
    _spec("SENSITIVE_API_NETWORK_CLIPBOARD", "網路傳輸 / 剪貼簿 API", "android/content/ClipboardManager", "setPrimaryClip", "寫入剪貼簿內容"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "java/lang/Runtime", "exec", "執行系統命令"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "java/lang/ProcessBuilder", "start", "啟動子行程"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "java/lang/Class", "forName", "反射載入類別"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "java/lang/reflect/Method", "invoke", "反射呼叫方法"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "java/lang/System", "loadLibrary", "載入 Native Library"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "java/lang/System", "load", "載入指定路徑 Native Library"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "dalvik/system/DexClassLoader", "<init>", "動態載入 DEX/APK"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "dalvik/system/PathClassLoader", "<init>", "從路徑載入 DEX"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "android/webkit/WebView", "addJavascriptInterface", "WebView 注入 Java 介面"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "android/webkit/WebView", "loadUrl", "WebView 載入 URL"),
    _spec("SENSITIVE_API_CODE_EXEC", "命令執行 / 反射 / 動態載入 API", "android/webkit/WebView", "evaluateJavascript", "執行 JavaScript"),
)


def _normalize_class_name(value: Any) -> str:
    normalized = str(value or "").strip().replace(".", "/")
    if normalized.startswith("L") and normalized.endswith(";"):
        normalized = normalized[1:-1]
    return normalized


_API_INDEX = {
    (_normalize_class_name(spec.api_class).lower(), spec.api_method.lower()): spec
    for spec in SENSITIVE_API_SPECS
}


def _method_value(method: Any, attribute: str, getter: str) -> str:
    value = getattr(method, attribute, None)
    if value is None and hasattr(method, getter):
        value = getattr(method, getter)()
    return str(value or "")


def scan_sensitive_api_callers(analysis: Any) -> SensitiveApiScanResult:
    """掃描 Analysis XREF，回傳敏感 callee 與 caller method/call offset。

    `complete` 表示 Androguard 提供的 XREF 已全數走訪；這仍不是 soundness
    保證，reflection、native code、runtime-loaded code 與 unresolved dispatch
    仍需標為未知。單一 method XREF 讀取失敗時回傳 `partial`。
    """
    if analysis is None:
        return SensitiveApiScanResult(
            status="unavailable",
            callers=[],
            error_count=1,
            error_message="Androguard Analysis 物件不存在",
        )

    try:
        methods = list(analysis.get_methods())
    except Exception as exc:
        return SensitiveApiScanResult(
            status="failed",
            callers=[],
            error_count=1,
            error_message=f"{type(exc).__name__}: {exc}"[:1000],
        )

    callers: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str, str, str, int]] = set()
    error_count = 0
    first_error: Optional[str] = None

    for caller in methods:
        try:
            caller_class = _method_value(caller, "class_name", "get_class_name")
            caller_method = _method_value(caller, "name", "get_name")
            caller_descriptor = _method_value(caller, "descriptor", "get_descriptor")
            xrefs = caller.get_xref_to()
        except Exception as exc:
            error_count += 1
            if first_error is None:
                first_error = f"{type(exc).__name__}: {exc}"[:1000]
            continue

        for _, callee, offset in xrefs:
            try:
                callee_class = _method_value(callee, "class_name", "get_class_name")
                callee_method = _method_value(callee, "name", "get_name")
                spec = _API_INDEX.get((
                    _normalize_class_name(callee_class).lower(),
                    callee_method.lower(),
                ))
                if spec is None:
                    continue
                call_offset = int(offset)
                key = (
                    spec.api_class,
                    spec.api_method,
                    caller_class,
                    caller_method,
                    caller_descriptor,
                    call_offset,
                )
                if key in seen:
                    continue
                seen.add(key)
                callers.append({
                    "group_id": spec.group_id,
                    "group_label": spec.group_label,
                    "api_class": spec.api_class,
                    "api_method": spec.api_method,
                    "description": spec.description,
                    "caller_class": caller_class,
                    "caller_method": caller_method,
                    "caller_descriptor": caller_descriptor,
                    "call_offset": call_offset,
                    "source": "androguard_xref",
                })
            except Exception as exc:
                error_count += 1
                if first_error is None:
                    first_error = f"{type(exc).__name__}: {exc}"[:1000]

    callers.sort(key=lambda row: (
        row["caller_class"],
        row["caller_method"],
        row["caller_descriptor"],
        row["call_offset"],
        row["api_class"],
        row["api_method"],
    ))
    return SensitiveApiScanResult(
        status="partial" if error_count else "complete",
        callers=callers,
        error_count=error_count,
        error_message=first_error,
    )
