from __future__ import annotations

import hashlib
import json
import urllib.parse
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from app.tools import mobsf_poc as poc


def empty_manifest_root():
    return ElementTree.fromstring(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        "<application />"
        "</manifest>"
    )


def test_manifest_loader_skips_cp950_permission_resources(tmp_path, monkeypatch):
    from androguard.core import androconf, axml

    def fail_permission_resource(*args, **kwargs):
        raise UnicodeDecodeError("cp950", b"\xe2", 0, 1, "illegal multibyte sequence")

    monkeypatch.setattr(androconf, "load_api_specific_resource_module", fail_permission_resource)
    root = ElementTree.fromstring(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application><activity android:name=".Explicit" android:exported="false">'
        '<intent-filter /></activity><activity android:name=".Implicit">'
        '<intent-filter /></activity><activity android:name=".Private" />'
        '<activity android:name=".Public" android:exported="true" />'
        '</application></manifest>'
    )
    binary_manifest = b"\x03\x00\x08\x00\xe2\x00"

    class ManifestParser:
        def __init__(self, data):
            assert data == binary_manifest

        def get_xml_obj(self):
            return root

        def is_valid(self):
            return True

    monkeypatch.setattr(axml, "AXMLPrinter", ManifestParser)
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest)
    rows = poc._extract_manifest_activity_exposure(poc._load_apk_manifest_root(apk))
    assert [(r["name"], r["explicit_exported"], r["has_intent_filter"],
             r["effective_exported"]) for r in rows] == [
        (".Explicit", False, True, False),
        (".Implicit", None, True, True),
        (".Private", None, False, False),
        (".Public", True, False, True),
    ]


@pytest.mark.parametrize("manifest", [None, b"invalid binary manifest"])
def test_manifest_loader_rejects_missing_or_invalid_manifest(tmp_path, manifest):
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        if manifest is not None:
            archive.writestr("AndroidManifest.xml", manifest)
    with pytest.raises(ValueError, match="AndroidManifest.xml"):
        poc._load_apk_manifest_root(apk)


def test_rejects_plain_http_for_nonlocal_server():
    with pytest.raises(ValueError, match="HTTPS"):
        poc.validate_base_url("http://example.test:8000")


def test_candidate_summary_is_explicitly_not_a_label():
    summary = poc.extract_candidate_summary(
        {
            "sha256": "abc",
            "package_name": "com.example",
            "exported_activities": ["com.example.MainActivity"],
            "manifest_analysis": {
                "manifest_findings": [{"rule": "explicitly_exported"}],
            },
            "android_api": {
                "api_ipc": {"files": {"com/example/MainActivity.java": "12"}},
                "unrelated": {"files": {}},
            },
        }
    )

    assert summary["evidence_role"] == "candidate_evidence"
    assert summary["produces_ground_truth"] is False
    assert summary["absence_is_negative_label"] is False
    assert set(summary["selected_android_api_groups"]) == {"api_ipc"}
    assert summary["components"]["exported_activities"] == ["com.example.MainActivity"]
    assert summary["selected_android_api_groups"]["api_ipc"]["application_files"] == {
        "com/example/MainActivity.java": "12"
    }


def test_candidate_summary_derives_implicit_exported_activity_from_manifest():
    manifest_root = ElementTree.fromstring(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                  package="net.app.pokeholidaygift2017newguide">
          <uses-sdk android:targetSdkVersion="25" />
          <application>
            <activity android:name="net.app.pokeholidaygift2017newguide.FullScrn1">
              <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
              </intent-filter>
            </activity>
            <activity android:name="net.app.pokeholidaygift2017newguide.FullScrn2" />
          </application>
        </manifest>
        """
    )
    summary = poc.extract_candidate_summary(
        {
            "package_name": "net.app.pokeholidaygift2017newguide",
            "exported_activities": [],
            "exported_count": {"exported_activities": 0},
            "manifest_analysis": {"manifest_findings": []},
            "android_api": {},
        },
        manifest_root=manifest_root,
    )

    assert summary["components"]["exported_activities"] == [
        "net.app.pokeholidaygift2017newguide.FullScrn1"
    ]
    assert summary["components"]["exported_count"]["exported_activities"] == 1
    assert summary["components"]["manifest_activity_exposure"] == [
        {
            "name": "net.app.pokeholidaygift2017newguide.FullScrn1",
            "explicit_exported": None,
            "effective_exported": True,
            "exported_basis": "implicit_intent_filter",
            "has_intent_filter": True,
            "permission": None,
        },
        {
            "name": "net.app.pokeholidaygift2017newguide.FullScrn2",
            "explicit_exported": None,
            "effective_exported": False,
            "exported_basis": "implicit_no_intent_filter",
            "has_intent_filter": False,
            "permission": None,
        },
    ]
    assert summary["components"]["mobsf_reported_exported_activities"] == []


def test_run_mobsf_writes_raw_report_summary_and_redacted_metadata(tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"apk")
    digest = hashlib.sha256(b"apk").hexdigest()
    responses = [
        {
            "status": "success",
            "hash": "mob-sf-md5",
            "scan_type": "apk",
            "file_name": "fixture.apk",
        },
        {"title": "Static Analysis", "sha256": digest},
        {
            "version": "v4.4.6",
            "file_name": "fixture.apk",
            "package_name": "com.example",
            "sha256": digest,
            "exported_activities": ["com.example.MainActivity"],
            "manifest_analysis": {"manifest_findings": []},
            "android_api": {"api_os_command": {"files": {"com/example/Main.java": "25"}}},
        },
    ]
    calls = []

    def fake_requester(url, **kwargs):
        calls.append((url, kwargs))
        return 200, json.dumps(responses.pop(0)).encode("utf-8")

    output_dir = tmp_path / "output"
    metadata = poc.run_mobsf(
        apk=apk,
        output_dir=output_dir,
        api_key="do-not-persist",
        requester=fake_requester,
        manifest_loader=lambda _: empty_manifest_root(),
    )

    assert metadata["result"]["status"] == "success"
    assert metadata["started_at_utc"].endswith("+08:00")
    assert metadata["completed_at_utc"].endswith("+08:00")
    assert metadata["result"]["sha256_match"] is True
    assert metadata["tool"]["api_key_persisted"] is False
    assert "do-not-persist" not in (output_dir / "run_metadata.json").read_text(encoding="utf-8")
    assert (output_dir / "raw" / "upload_response.json").is_file()
    assert (output_dir / "raw" / "scan_response.json").is_file()
    assert (output_dir / "raw" / "report.json").is_file()
    summary = json.loads((output_dir / "candidate_summary.json").read_text(encoding="utf-8"))
    assert set(summary["selected_android_api_groups"]) == {"api_os_command"}
    assert summary["reported_version"] == "v4.4.6"
    assert summary["selected_android_api_groups"]["api_os_command"]["application_files"] == {
        "com/example/Main.java": "25"
    }
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["upload", "scan", "report_json"]
    scan_body = urllib.parse.parse_qs(calls[1][1]["body"].decode("ascii"))
    assert scan_body["re_scan"] == ["1"]


def test_full_scan_response_is_reused_without_report_json_call(tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"apk")
    digest = hashlib.sha256(b"apk").hexdigest()
    full_report = {
        "title": "Static Analysis",
        "version": "v4.4.6",
        "file_name": "fixture.apk",
        "package_name": "com.example",
        "sha256": digest,
        "exported_activities": ["com.example.MainActivity"],
        "manifest_analysis": {"manifest_findings": []},
        "android_api": {"api_ipc": {"files": {"com/example/MainActivity.java": "12"}}},
    }
    responses = [
        {
            "status": "success",
            "hash": "mob-sf-md5",
            "scan_type": "apk",
            "file_name": "fixture.apk",
        },
        full_report,
    ]
    calls = []

    def fake_requester(url, **kwargs):
        calls.append((url, kwargs))
        return 200, json.dumps(responses.pop(0)).encode("utf-8")

    output_dir = tmp_path / "output"
    metadata = poc.run_mobsf(
        apk=apk,
        output_dir=output_dir,
        api_key="do-not-persist",
        requester=fake_requester,
        manifest_loader=lambda _: empty_manifest_root(),
    )

    assert metadata["result"]["status"] == "success"
    assert metadata["result"]["report_source"] == "scan_response"
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["upload", "scan"]
    assert json.loads((output_dir / "raw" / "report.json").read_text(encoding="utf-8")) == full_report
    assert (output_dir / "candidate_summary.json").is_file()


def test_sha_mismatch_is_failure_and_keeps_raw_report(tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"apk")
    responses = [
        {"status": "success", "hash": "hash", "scan_type": "apk", "file_name": "fixture.apk"},
        {"title": "Static Analysis"},
        {"sha256": "wrong"},
    ]

    def fake_requester(url, **kwargs):
        return 200, json.dumps(responses.pop(0)).encode("utf-8")

    output_dir = tmp_path / "output"
    metadata = poc.run_mobsf(
        apk=apk,
        output_dir=output_dir,
        api_key="key",
        requester=fake_requester,
    )

    assert metadata["result"]["status"] == "analysis_failed"
    assert metadata["result"]["sha256_match"] is False
    assert (output_dir / "raw" / "report.json").is_file()


def test_api_failure_still_writes_attempt_and_metadata(tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"apk")

    def failing_requester(url, **kwargs):
        raise OSError("connection refused")

    output_dir = tmp_path / "output"
    metadata = poc.run_mobsf(
        apk=apk,
        output_dir=output_dir,
        api_key="key",
        requester=failing_requester,
    )

    assert metadata["result"]["status"] == "analysis_failed"
    assert metadata["result"]["error_type"] == "OSError"
    assert (output_dir / "attempts.csv").is_file()
    assert (output_dir / "run_metadata.json").is_file()


@pytest.mark.parametrize("source_name", ["report.json", "scan_response.json"])
def test_rebuild_summary_preserves_sources_and_records_provenance(tmp_path, source_name):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"apk")
    digest = hashlib.sha256(b"apk").hexdigest()
    raw = tmp_path / "raw"
    raw.mkdir()
    report_path = raw / source_name
    report_path.write_text(json.dumps({
        "version": "v4.4.6", "sha256": digest, "package_name": "com.example",
        "manifest_analysis": {}, "android_api": {}, "exported_activities": [],
    }), encoding="utf-8")
    original = tmp_path / "candidate_summary.json"
    original.write_bytes(b'{"old": true}\n')
    source_bytes = report_path.read_bytes()
    root = ElementTree.fromstring(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application><activity android:name=".OnBoardActivity">'
        '<intent-filter /></activity></application></manifest>'
    )
    summary = poc.rebuild_candidate_summary(
        apk=apk, report_path=report_path, output_dir=tmp_path,
        manifest_loader=lambda _: root,
    )
    assert summary["schema_version"] == "mobsf-candidate-summary-v2"
    components = summary["components"]
    assert components["mobsf_reported_exported_activities"] == []
    assert components["exported_activities"] == [".OnBoardActivity"]
    row = components["manifest_activity_exposure"][0]
    assert row["explicit_exported"] is None
    assert row["effective_exported"] is True
    assert row["effective_exported_basis"] == "implicit_intent_filter"
    provenance = summary["provenance"]
    assert provenance["source_report"] == {
        "reference": f"raw/{source_name}",
        "sha256": hashlib.sha256(source_bytes).hexdigest(),
    }
    assert provenance["original_raw_report"]["exists"] == (source_name == "report.json")
    assert provenance["apk_sha256"] == digest
    assert provenance["generated_at"].endswith("+08:00")
    assert len(provenance["generator_source_sha256"]) == 64
    assert len(provenance["config_sha256"]) == 64
    assert original.read_bytes() == b'{"old": true}\n'
    assert report_path.read_bytes() == source_bytes
    target = tmp_path / "candidate_summary.v2.json"
    assert json.loads(target.read_text(encoding="utf-8")) == summary
    frozen = target.read_bytes()
    with pytest.raises(FileExistsError):
        poc.rebuild_candidate_summary(apk=apk, report_path=report_path, output_dir=tmp_path)
    assert target.read_bytes() == frozen


@pytest.mark.parametrize("bad_report", [
    {"version": "v4.4.6", "sha256": "wrong", "package_name": "com.example",
     "manifest_analysis": {}, "android_api": {}},
    {"sha256": "wrong"},
])
def test_rebuild_rejects_wrong_identity_or_incomplete_report(tmp_path, bad_report):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"apk")
    report = tmp_path / "report.json"
    report.write_text(json.dumps(bad_report), encoding="utf-8")
    with pytest.raises(ValueError):
        poc.rebuild_candidate_summary(apk=apk, report_path=report, output_dir=tmp_path)
    assert not (tmp_path / "candidate_summary.v2.json").exists()


def test_rebuild_cli_does_not_call_mobsf(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(poc, "rebuild_candidate_summary", lambda **kwargs: (
        calls.append(kwargs) or {"schema_version": "v2", "identity": {"sha256": "abc"}}
    ))
    def forbid_api(**kwargs):
        pytest.fail("離線重建不應呼叫 MobSF")
    monkeypatch.setattr(poc, "run_mobsf", forbid_api)
    assert poc.main(["--apk", "fixture.apk", "--output-dir", str(tmp_path),
                     "--rebuild-report", "report.json"]) == 0
    assert len(calls) == 1
