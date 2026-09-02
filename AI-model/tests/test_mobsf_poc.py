from __future__ import annotations

import hashlib
import json
import urllib.parse
from pathlib import Path

import pytest

from app.tools import mobsf_poc as poc


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
    )

    assert metadata["result"]["status"] == "success"
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
