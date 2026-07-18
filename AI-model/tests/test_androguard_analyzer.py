"""Regression tests for facts extracted from AndroidManifest.xml."""
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

from app.extractors.androguard_analyzer import _extract_components


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _extract_provider(attributes: str):
    manifest_xml = ET.fromstring(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">'
        f"  <application>"
        f'    <provider android:name="com.example.Provider" {attributes} />'
        f"  </application>"
        f"</manifest>"
    )
    mock_axml = MagicMock()
    mock_axml.get_xml_obj.return_value = manifest_xml
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_axml.return_value = mock_axml

    components = _extract_components(mock_apk)
    return next(component for component in components if component.type == "provider")


def _extract_component(component_type: str, attributes: str):
    intent_filter = (
        '      <intent-filter>'
        '        <action android:name="com.example.ACTION" />'
        '      </intent-filter>'
    )
    component_name = f"com.example.{component_type.title()}"
    manifest_xml = ET.fromstring(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">'
        f"  <application>"
        f'    <{component_type} android:name="{component_name}" {attributes}>'
        f"      {intent_filter}"
        f"    </{component_type}>"
        f"  </application>"
        f"</manifest>"
    )
    mock_axml = MagicMock()
    mock_axml.get_xml_obj.return_value = manifest_xml
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_axml.return_value = mock_axml

    components = _extract_components(mock_apk)
    return next(component for component in components if component.type == component_type)


def test_activity_explicit_exported_false_with_intent_filter_stays_false():
    activity = _extract_component("activity", 'android:exported="false"')

    assert activity.exported is False


def test_activity_implicit_exported_true_when_attribute_absent_with_intent_filter():
    activity = _extract_component("activity", "")

    assert activity.exported is True


def test_service_explicit_exported_false_with_intent_filter_stays_false():
    service = _extract_component("service", 'android:exported="false"')

    assert service.exported is False


def test_service_implicit_exported_true_when_attribute_absent_with_intent_filter():
    service = _extract_component("service", "")

    assert service.exported is True


def test_receiver_explicit_exported_false_with_intent_filter_stays_false():
    receiver = _extract_component("receiver", 'android:exported="false"')

    assert receiver.exported is False


def test_receiver_implicit_exported_true_when_attribute_absent_with_intent_filter():
    receiver = _extract_component("receiver", "")

    assert receiver.exported is True


def test_provider_read_permission_is_in_permissions_required():
    provider = _extract_provider(
        'android:readPermission="com.example.permission.READ_PROVIDER"'
    )

    assert provider.permissions_required == [
        "com.example.permission.READ_PROVIDER",
    ]
    assert provider.read_permission == "com.example.permission.READ_PROVIDER"
    assert provider.write_permission is None


def test_provider_write_permission_is_in_permissions_required():
    provider = _extract_provider(
        'android:writePermission="com.example.permission.WRITE_PROVIDER"'
    )

    assert provider.permissions_required == [
        "com.example.permission.WRITE_PROVIDER",
    ]
    assert provider.read_permission is None
    assert provider.write_permission == "com.example.permission.WRITE_PROVIDER"


def test_provider_general_and_read_permissions_are_both_required():
    provider = _extract_provider(
        'android:permission="com.example.permission.ACCESS_PROVIDER" '
        'android:readPermission="com.example.permission.READ_PROVIDER"'
    )

    assert provider.permissions_required == [
        "com.example.permission.ACCESS_PROVIDER",
        "com.example.permission.READ_PROVIDER",
    ]
    assert provider.read_permission == "com.example.permission.READ_PROVIDER"
    assert provider.write_permission == "com.example.permission.ACCESS_PROVIDER"


def test_provider_without_permissions_keeps_permissions_required_none():
    provider = _extract_provider("")

    assert provider.permissions_required is None
    assert provider.read_permission is None
    assert provider.write_permission is None


def test_provider_generic_permission_covers_both_sides():
    provider = _extract_provider(
        'android:permission="com.example.permission.ACCESS_PROVIDER"'
    )

    assert provider.read_permission == "com.example.permission.ACCESS_PROVIDER"
    assert provider.write_permission == "com.example.permission.ACCESS_PROVIDER"


def test_provider_read_permission_only_write_open():
    provider = _extract_provider('android:readPermission="com.example.READ"')

    assert provider.read_permission == "com.example.READ"
    assert provider.write_permission is None


def test_provider_read_permission_overrides_generic_for_that_side():
    provider = _extract_provider(
        'android:permission="com.example.ALL" '
        'android:readPermission="com.example.READ"'
    )

    assert provider.read_permission == "com.example.READ"
    assert provider.write_permission == "com.example.ALL"


def test_provider_grant_uri_permissions_true_is_extracted():
    provider = _extract_provider('android:grantUriPermissions="true"')

    assert provider.grant_uri_permissions is True


def test_provider_grant_uri_permissions_defaults_to_false():
    provider = _extract_provider("")

    assert provider.grant_uri_permissions is False

def test_provider_explicit_exported_false_with_authorities_stays_false():
    """authorities 存在時不應覆寫明確宣告的 exported=false（pre-API-17 legacy 行為，
    在 minSdk=23 場景下不適用；這正是 Scenario E-0 / AndroidX InitializationProvider
    誤判為 exported=true 的根因）"""
    provider = _extract_provider(
        'android:authorities="com.example.provider" '
        'android:exported="false"'
    )
    assert provider.exported is False


def test_provider_no_exported_attr_with_authorities_defaults_to_false():
    """未指定 exported 時，即使有 authorities，也應維持預設值 false（targetSdk>=17 的正確預設）"""
    provider = _extract_provider('android:authorities="com.example.provider"')
    assert provider.exported is False

# ── Namespace fallback regression tests (STATUS_2026-07-15.md Bug B) ───────
# 部分惡意程式會產生「被封裝」的 AndroidManifest.xml，讓某些屬性的 android:
# namespace 前綴消失。_get_android_attr() 在 namespace 版本找不到時會退回
# 嘗試裸屬性名，但這個 fallback 在修復當下（145+ 個既有測試皆通過）完全沒有
# 專屬測試覆蓋，只靠真實世界樣本（2f702269d243...）意外撞到才發現問題存在。
# 以下測試手動建構「無 android: 前綴」的屬性，鎖定這個情境不再無聲回歸——
# 如果之後 _get_android_attr() 的 fallback 分支被誤刪或改壞，這裡會直接紅燈，
# 而不是要等到某個真實惡意樣本再次意外撞到才發現。
 
def _extract_component_no_namespace(component_type: str, attributes: str):
    """跟 `_extract_component()` 相同，但屬性刻意不帶 `android:` 前綴，模擬
    「封裝過的 manifest」情境。intent-filter 內的 `<action>` 維持原本的
    `android:` 前綴，因為 `_extract_intent_filters()` 的 namespace 處理不在
    這次要驗證的範圍內（`_get_android_attr()` 只用在元件自身的屬性讀取）。
    """
    intent_filter = (
        '      <intent-filter>'
        '        <action android:name="com.example.ACTION" />'
        '      </intent-filter>'
    )
    component_name = f"com.example.{component_type.title()}"
    manifest_xml = ET.fromstring(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">'
        f"  <application>"
        f'    <{component_type} name="{component_name}" {attributes}>'
        f"      {intent_filter}"
        f"    </{component_type}>"
        f"  </application>"
        f"</manifest>"
    )
    mock_axml = MagicMock()
    mock_axml.get_xml_obj.return_value = manifest_xml
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_axml.return_value = mock_axml
 
    components = _extract_components(mock_apk)
    return next(component for component in components if component.type == component_type)
 
 
def _extract_provider_no_namespace(attributes: str):
    manifest_xml = ET.fromstring(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">'
        f"  <application>"
        f'    <provider name="com.example.Provider" {attributes} />'
        f"  </application>"
        f"</manifest>"
    )
    mock_axml = MagicMock()
    mock_axml.get_xml_obj.return_value = manifest_xml
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_axml.return_value = mock_axml
 
    components = _extract_components(mock_apk)
    return next(component for component in components if component.type == "provider")
 
 
def test_activity_name_and_exported_resolved_when_namespace_prefix_missing():
    activity = _extract_component_no_namespace("activity", 'exported="false"')
 
    assert activity.name == "com.example.Activity"
    assert activity.exported is False
 
 
def test_service_name_and_exported_resolved_when_namespace_prefix_missing():
    service = _extract_component_no_namespace("service", 'exported="false"')
 
    assert service.name == "com.example.Service"
    assert service.exported is False
 
 
def test_receiver_name_and_exported_resolved_when_namespace_prefix_missing():
    """對應真正觸發過本 bug 的樣本類型：真實世界 sms 樣本
    2f702269d243...（package: jyiaivi.ohduxbbylb）的 receiver 元件名稱
    修復前解析成 None，修復後正確解析為隨機字母組合的混淆名稱。"""
    receiver = _extract_component_no_namespace("receiver", 'exported="true"')
 
    assert receiver.name == "com.example.Receiver"
    assert receiver.exported is True
 
 
def test_activity_permission_resolved_when_namespace_prefix_missing():
    activity = _extract_component_no_namespace(
        "activity", 'permission="com.example.permission.ACCESS_PROTECTED"'
    )
 
    assert activity.permissions_required == ["com.example.permission.ACCESS_PROTECTED"]
 
 
def test_provider_name_and_exported_resolved_when_namespace_prefix_missing():
    provider = _extract_provider_no_namespace('exported="true"')
 
    assert provider.name == "com.example.Provider"
    assert provider.exported is True
 
 
def test_provider_read_write_permission_resolved_when_namespace_prefix_missing():
    provider = _extract_provider_no_namespace(
        'exported="true" readPermission="com.example.READ" '
        'writePermission="com.example.WRITE"'
    )
 
    assert provider.read_permission == "com.example.READ"
    assert provider.write_permission == "com.example.WRITE"
 
 
def test_provider_grant_uri_permissions_resolved_when_namespace_prefix_missing():
    provider = _extract_provider_no_namespace(
        'exported="true" readPermission="com.example.READ" '
        'writePermission="com.example.READ" grantUriPermissions="true"'
    )
 
    assert provider.grant_uri_permissions is True
 
 
def test_provider_mixed_namespace_and_bare_attributes_both_resolved():
    """真實世界的封裝 manifest 通常只有部分屬性掉了 namespace 前綴，不是
    整份文件一致地變成無 namespace。這裡刻意混用 android:name（有前綴）
    跟 exported/readPermission/writePermission（無前綴），確認
    _get_android_attr() 是逐一屬性各自 fallback，不是靠某種文件層級的
    全域開關才生效。"""
    manifest_xml = ET.fromstring(
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">'
        f"  <application>"
        f'    <provider android:name="com.example.MixedProvider" '
        f'      exported="true" readPermission="com.example.READ" '
        f'      writePermission="com.example.READ" />'
        f"  </application>"
        f"</manifest>"
    )
    mock_axml = MagicMock()
    mock_axml.get_xml_obj.return_value = manifest_xml
    mock_apk = MagicMock()
    mock_apk.get_android_manifest_axml.return_value = mock_axml
 
    components = _extract_components(mock_apk)
    provider = next(c for c in components if c.type == "provider")
 
    assert provider.name == "com.example.MixedProvider"
    assert provider.exported is True
    assert provider.read_permission == "com.example.READ"
    assert provider.write_permission == "com.example.READ"
 