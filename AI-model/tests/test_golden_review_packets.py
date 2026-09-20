from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from app.tools import golden_review_packets as packets
from app.tools.golden_batch import MembershipEntry


def _manifest() -> ElementTree.Element:
    return ElementTree.fromstring(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                  package="com.example">
          <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28" />
          <uses-permission android:name="android.permission.SEND_SMS" />
          <permission android:name="com.example.SIGNATURE"
                      android:protectionLevel="signature" />
          <application android:permission="com.example.DEFAULT">
            <activity android:name=".PublicActivity">
              <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="example" android:host="open" />
              </intent-filter>
            </activity>
            <service android:name=".PrivateService" android:exported="false" />
            <provider android:name=".DocsProvider"
                      android:authorities="com.example.docs"
                      android:readPermission="com.example.READ"
                      android:grantUriPermissions="true">
              <path-permission android:pathPrefix="/private"
                               android:readPermission="com.example.SIGNATURE" />
            </provider>
          </application>
        </manifest>
        """
    )


def test_manifest_evidence_keeps_component_specific_guard_semantics():
    evidence = packets.extract_manifest_evidence(_manifest())

    assert evidence["package_name"] == "com.example"
    assert evidence["target_sdk"] == "28"
    assert evidence["uses_permissions"] == ["android.permission.SEND_SMS"]
    assert evidence["declared_permissions"] == [
        {"name": "com.example.SIGNATURE", "protection_level": "signature"}
    ]
    by_name = {row["manifest_name"]: row for row in evidence["components"]}
    public = by_name["com.example.PublicActivity"]
    assert public["explicit_exported"] is None
    assert public["static_exported_interpretation"]["value"] is True
    assert public["permission"] == "com.example.DEFAULT"
    provider = by_name["com.example.DocsProvider"]
    assert provider["static_exported_interpretation"]["value"] is False
    assert provider["grant_uri_permissions"] is True
    assert provider["path_permissions"][0]["pathPrefix"] == "/private"


def test_projected_callers_remove_coordinator_labels(tmp_path):
    sha256 = "a" * 64
    source = tmp_path / "callers.jsonl"
    source.write_text(
        json.dumps(
            {
                "binary_label": "non_benign",
                "original_label": "SMS",
                "source_dataset": "fixture",
                "risk_hint": "do-not-copy",
                "sha256": sha256,
                "evidence": {
                    "api_class": "android/telephony/SmsManager",
                    "api_method": "sendTextMessage",
                    "caller_class": "Lcom/example/PublicActivity;",
                    "caller_method": "onCreate",
                    "caller_descriptor": "(Landroid/os/Bundle;)V",
                    "call_offset": 12,
                    "caller_component_name": "com.example.PublicActivity",
                    "matched_component_type": "activity",
                    "matched_lifecycle_entry_method": True,
                    "matched_manifest_component": True,
                    "linkage_status": "direct_entry_caller",
                    "linkage_limit": "fixture limit",
                    "source": "androguard_xref",
                },
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    projected = packets.load_projected_callers(source, {sha256})[sha256][0]

    assert projected["api_method"] == "sendTextMessage"
    assert "binary_label" not in projected
    assert "original_label" not in projected
    assert "source_dataset" not in projected
    assert "risk_hint" not in projected
    assert projected["evidence_reference"].endswith("#1")


def test_projected_components_and_fallback_manifest_remove_labels(tmp_path):
    sha256 = "b" * 64
    source = tmp_path / "components.jsonl"
    source.write_text(
        json.dumps(
            {
                "binary_label": "non_benign",
                "original_label": "SMS",
                "source_dataset": "fixture",
                "sha256": sha256,
                "evidence": {
                    "component_name": "com.example.PublicActivity",
                    "component_type": "activity",
                    "exported": True,
                    "permission": None,
                    "protected": False,
                    "actions": ["android.intent.action.VIEW"],
                    "categories": ["android.intent.category.DEFAULT"],
                    "data_schemes": ["example"],
                    "data_types": [],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    entry = MembershipEntry(
        membership_id="golden-50-v1:" + sha256,
        sha256=sha256,
        source_path="unused.apk",
        package_name="com.example",
        selection_rank=1,
        membership_version="golden-50-v1",
    )

    rows = packets.load_projected_components(source, {sha256})[sha256]
    fallback = packets.fallback_manifest_evidence(
        entry=entry,
        report={
            "min_sdk": "21",
            "target_sdk": "28",
            "permissions": {"android.permission.SEND_SMS": {"status": "dangerous"}},
        },
        component_rows=rows,
        binary_manifest_error="OSError: blocked",
    )

    assert "protected" not in rows[0]
    assert fallback["extraction_status"] == "fallback_sha_bound_projected_evidence"
    assert fallback["components"][0]["manifest_name"] == "com.example.PublicActivity"
    assert fallback["components"][0]["static_exported_interpretation"]["value"] is True
    assert fallback["uses_permissions"] == ["android.permission.SEND_SMS"]
    packets._assert_no_forbidden_keys(fallback)


def test_direct_entry_xref_remains_candidate_not_concrete_path():
    entry = MembershipEntry(
        membership_id="golden-50-v1:" + "a" * 64,
        sha256="a" * 64,
        source_path="unused.apk",
        package_name="com.example",
        selection_rank=1,
        membership_version="golden-50-v1",
    )
    manifest = packets.extract_manifest_evidence(_manifest())
    caller = {
        "api_class": "android/telephony/SmsManager",
        "api_method": "sendTextMessage",
        "call_offset": 12,
        "caller_class": "Lcom/example/PublicActivity;",
        "caller_component_name": "com.example.PublicActivity",
        "caller_descriptor": "(Landroid/os/Bundle;)V",
        "caller_method": "onCreate",
        "linkage_status": "direct_entry_caller",
        "linkage_limit": "未建立 data-flow path",
        "matched_component_type": "activity",
        "matched_lifecycle_entry_method": True,
        "source": "androguard_xref",
    }

    unit = packets._caller_unit(entry=entry, manifest=manifest, caller=caller)

    assert unit is not None
    assert unit["row_kind"] == "candidate"
    assert unit["path_id"] is None
    assert "direct_entry_identity_without_full_path" in unit["coverage_limitations"]
    assert unit["attacker_input_evidence"]["status"] == "not_analyzed"


def test_flowdroid_lifecycle_trace_can_form_concrete_path():
    entry = MembershipEntry(
        membership_id="golden-50-v1:" + "a" * 64,
        sha256="a" * 64,
        source_path="unused.apk",
        package_name="com.example",
        selection_rank=1,
        membership_version="golden-50-v1",
    )
    manifest = packets.extract_manifest_evidence(_manifest())
    flow = {
        "source": {
            "statement": '$r1 = virtualinvoke $r0.getStringExtra("cmd")',
            "line_number": "10",
            "method": "<com.example.PrivateService: int onStartCommand(android.content.Intent,int,int)>",
            "definition": "<android.content.Intent: java.lang.String getStringExtra(java.lang.String)>",
        },
        "sink": {
            "statement": "virtualinvoke $r1.<java.lang.Runtime: java.lang.Process exec(java.lang.String)>",
            "line_number": "20",
            "method": "<com.example.PrivateService: void run(java.lang.String)>",
            "definition": "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>",
        },
        "taint_path": [
            {"statement": "source", "method": "onStartCommand"},
            {"statement": "sink", "method": "run"},
        ],
        "termination_state": "Success",
    }

    unit = packets._flow_unit(entry=entry, manifest=manifest, flow=flow)

    assert unit["row_kind"] == "concrete_path"
    assert unit["path_id"].startswith("path-v1:")
    assert unit["entry_evidence"]["entry_method"] == "onStartCommand"
    assert unit["authorization_guard_evidence"]["status"] == "not_analyzed"


def test_flowdroid_parser_preserves_source_sink_and_trace(tmp_path):
    xml = tmp_path / "flowdroid.xml"
    xml.write_text(
        """<?xml version="1.0"?>
        <DataFlowResults TerminationState="Success">
          <Results><Result>
            <Sink Statement="sink" LineNumber="20" Method="&lt;C: void send()&gt;"
                  MethodSourceSinkDefinition="&lt;S: void sink()&gt;" />
            <Sources><Source Statement="source" LineNumber="10"
                    Method="&lt;C: void onCreate()&gt;"
                    MethodSourceSinkDefinition="&lt;I: java.lang.String getStringExtra(java.lang.String)&gt;">
              <TaintPath><PathElement Statement="edge" Method="&lt;C: void onCreate()&gt;" /></TaintPath>
            </Source></Sources>
          </Result></Results>
        </DataFlowResults>""",
        encoding="utf-8",
    )

    result = packets.parse_flowdroid_results(xml)

    assert len(result) == 1
    assert result[0]["source"]["statement"] == "source"
    assert result[0]["sink"]["statement"] == "sink"
    assert result[0]["taint_path"] == [
        {"statement": "edge", "method": "<C: void onCreate()>"}
    ]


def test_duplicate_review_unit_ids_are_collapsed():
    first = {
        "review_unit_id": "review-unit-v1:same",
        "coordinator_evidence_reference": "source#1",
    }
    duplicate = {
        "review_unit_id": "review-unit-v1:same",
        "coordinator_evidence_reference": "source#2",
    }

    result = packets._deduplicate_units([first, duplicate])

    assert len(result) == 1
    assert result[0]["duplicate_evidence_references"] == ["source#2"]


def test_source_fetch_writes_relative_hashed_evidence_and_keyword_locators(tmp_path):
    packet_root = tmp_path / "packet"
    unit = {
        "component_identity": {
            "resolved_code_owner": "com.example.PublicActivity",
        },
        "entry_evidence": {"entry_method": "onCreate"},
        "sensitive_effect_candidate": {
            "caller_class": "Lcom/example/PublicActivity;",
            "api_method": "sendTextMessage",
        },
    }

    def fetch(scan_hash, relative_path, source_type):
        assert scan_hash == "f" * 32
        assert source_type == "apk"
        assert relative_path == "com/example/PublicActivity.java"
        return """class PublicActivity {
  void onCreate() {
    String value = getIntent().getStringExtra("message");
    sms.sendTextMessage(number, null, value, null, null);
  }
}"""

    files, failures = packets._fetch_unit_sources(
        packet_root=packet_root,
        scan_hash="f" * 32,
        units=[unit],
        fetch_source=fetch,
    )

    assert failures == []
    assert len(files) == 1
    source_path = packet_root / files[0]["reference"]
    assert source_path.is_file()
    assert files[0]["sha256"] == hashlib.sha256(source_path.read_bytes()).hexdigest()
    assert len(unit["source_locators"]) == 1
    locator = unit["source_locators"][0]
    assert locator["entry_method_name_hits"][0]["line"] == 2
    assert locator["sink_method_name_hits"][0]["line"] == 4
    assert locator["attacker_input_keyword_hits"][0]["line"] == 3


def test_blinding_gate_rejects_forbidden_structured_key():
    with pytest.raises(ValueError, match="blinding breach"):
        packets._assert_no_forbidden_keys(
            {"safe": {"rows": [{"source_dataset": "forbidden"}]}}
        )


def test_audit_collection_detects_artifact_tampering(tmp_path):
    root = tmp_path / "collection"
    packet_path = root / "packets" / ("a" * 64) / "packet.json"
    packet = {"identity": {"apk_sha256": "a" * 64}, "review_units": []}
    packets._write_json(packet_path, packet)
    packet_hash = packets.sha256_file(packet_path)
    inventory = {
        "membership_id": "golden-50-v1:" + "a" * 64,
        "apk_sha256": "a" * 64,
        "package_name": "com.example",
        "packet_reference": packet_path.relative_to(root).as_posix(),
        "packet_sha256": packet_hash,
        "review_unit_count": 0,
        "candidate_count": 0,
        "concrete_path_count": 0,
        "source_file_count": 0,
        "source_fetch_failure_count": 0,
        "mobsf_status": "success",
        "flowdroid_status": "no_result_artifact",
    }
    packets._write_csv(root / "packet_inventory.csv", packets.INVENTORY_FIELDS, [inventory])
    packets._write_csv(root / "review_units.csv", packets.REVIEW_UNIT_FIELDS, [])
    artifact_paths = [packet_path, root / "packet_inventory.csv", root / "review_units.csv"]
    artifacts = [
        {
            "reference": path.relative_to(root).as_posix(),
            "sha256": packets.sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(artifact_paths)
    ]
    manifest = {
        "schema_version": packets.COLLECTION_SCHEMA_VERSION,
        "packet_count": 1,
        "review_unit_count": 0,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "collection_fingerprint": packets.canonical_fingerprint(artifacts),
    }
    packets._write_json(root / "packet_collection_manifest.json", manifest)

    assert packets.audit_collection(root)["status"] == "PASS"
    packet_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact size|artifact SHA-256"):
        packets.audit_collection(root)


def test_class_to_source_requests_falls_back_from_inner_to_outer_class():
    requests = packets._class_to_source_requests("Lcom/example/Worker$1;")

    assert requests[:2] == [
        ("com/example/Worker$1.java", "apk"),
        ("com/example/Worker$1.smali", "smali"),
    ]
    assert ("com/example/Worker.java", "apk") in requests
