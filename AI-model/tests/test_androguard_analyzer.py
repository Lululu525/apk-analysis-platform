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


def test_provider_read_permission_is_in_permissions_required():
    provider = _extract_provider(
        'android:readPermission="com.example.permission.READ_PROVIDER"'
    )

    assert provider.permissions_required == [
        "com.example.permission.READ_PROVIDER",
    ]


def test_provider_write_permission_is_in_permissions_required():
    provider = _extract_provider(
        'android:writePermission="com.example.permission.WRITE_PROVIDER"'
    )

    assert provider.permissions_required == [
        "com.example.permission.WRITE_PROVIDER",
    ]


def test_provider_general_and_read_permissions_are_both_required():
    provider = _extract_provider(
        'android:permission="com.example.permission.ACCESS_PROVIDER" '
        'android:readPermission="com.example.permission.READ_PROVIDER"'
    )

    assert provider.permissions_required == [
        "com.example.permission.ACCESS_PROVIDER",
        "com.example.permission.READ_PROVIDER",
    ]


def test_provider_without_permissions_keeps_permissions_required_none():
    provider = _extract_provider("")

    assert provider.permissions_required is None


def test_provider_grant_uri_permissions_true_is_extracted():
    provider = _extract_provider('android:grantUriPermissions="true"')

    assert provider.grant_uri_permissions is True


def test_provider_grant_uri_permissions_defaults_to_false():
    provider = _extract_provider("")

    assert provider.grant_uri_permissions is False
