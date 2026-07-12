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
