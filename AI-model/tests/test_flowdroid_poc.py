from __future__ import annotations

import csv
import hashlib
import subprocess
from pathlib import Path

import pytest

from app.tools import flowdroid_poc as poc


def _make_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    jar = tmp_path / "flowdroid.jar"
    apk = tmp_path / "fixture.apk"
    platforms = tmp_path / "platforms"
    sources_sinks = tmp_path / "sources-sinks.txt"
    jar.write_bytes(b"pinned-flowdroid")
    apk.write_bytes(b"apk")
    platform_dir = platforms / "android-37"
    platform_dir.mkdir(parents=True)
    (platform_dir / "android.jar").write_bytes(b"framework")
    sources_sinks.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(poc, "FLOWDROID_JAR_SHA256", hashlib.sha256(jar.read_bytes()).hexdigest())
    return jar, apk, platforms, sources_sinks


def test_build_command_uses_fixed_analysis_flags(tmp_path):
    command = poc.build_command(
        java="java",
        jar=tmp_path / "flowdroid.jar",
        apk=tmp_path / "fixture.apk",
        platforms_dir=tmp_path / "platforms",
        sources_sinks=tmp_path / "sources.txt",
        result_xml=tmp_path / "result.xml",
        callback_timeout_seconds=60,
        dataflow_timeout_seconds=120,
        result_timeout_seconds=30,
        max_threads=1,
    )

    assert command[:3] == ["java", "-jar", str(tmp_path / "flowdroid.jar")]
    assert command[command.index("-tw") + 1] == "NONE"
    assert {"-cp", "-ps", "-ol"}.issubset(command)
    assert command[command.index("-mt") + 1] == "1"


def test_rejects_wrong_jar_checksum_before_creating_output(tmp_path):
    jar = tmp_path / "flowdroid.jar"
    apk = tmp_path / "fixture.apk"
    platforms = tmp_path / "platforms"
    sources_sinks = tmp_path / "sources.txt"
    jar.write_bytes(b"wrong")
    apk.write_bytes(b"apk")
    platform_dir = platforms / "android-37"
    platform_dir.mkdir(parents=True)
    (platform_dir / "android.jar").write_bytes(b"framework")
    sources_sinks.write_text("fixture", encoding="utf-8")
    output_dir = tmp_path / "output"

    with pytest.raises(ValueError, match="SHA-256"):
        poc.run_flowdroid(
            jar=jar,
            apk=apk,
            platforms_dir=platforms,
            sources_sinks=sources_sinks,
            output_dir=output_dir,
        )

    assert not output_dir.exists()


def test_refuses_to_overwrite_nonempty_output(tmp_path, monkeypatch):
    jar, apk, platforms, sources_sinks = _make_inputs(tmp_path, monkeypatch)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError, match="拒絕覆寫"):
        poc.run_flowdroid(
            jar=jar,
            apk=apk,
            platforms_dir=platforms,
            sources_sinks=sources_sinks,
            output_dir=output_dir,
        )


def test_success_writes_provenance_and_candidate_evidence_semantics(tmp_path, monkeypatch):
    jar, apk, platforms, sources_sinks = _make_inputs(tmp_path, monkeypatch)
    output_dir = tmp_path / "output"

    def fake_runner(command, **kwargs):
        result_path = Path(command[command.index("-o") + 1])
        result_path.write_text(
            '<DataFlowResults TerminationState="Success"><Results><Result /></Results></DataFlowResults>',
            encoding="utf-8",
        )
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, 0, "stdout", "stderr")

    metadata = poc.run_flowdroid(
        jar=jar,
        apk=apk,
        platforms_dir=platforms,
        sources_sinks=sources_sinks,
        output_dir=output_dir,
        runner=fake_runner,
    )

    assert metadata["result"]["status"] == "success"
    assert metadata["result"]["termination_state"] == "Success"
    assert metadata["result"]["finding_count"] == 1
    assert metadata["semantics"] == {
        "output_role": "candidate_evidence",
        "absence_is_negative_label": False,
        "produces_ground_truth": False,
    }
    assert (output_dir / "raw" / "flowdroid.xml").is_file()
    assert (output_dir / "run_metadata.json").is_file()
    attempt = next(csv.DictReader((output_dir / "attempts.csv").open(encoding="utf-8-sig")))
    assert attempt["status"] == "success"
    assert attempt["apk_sha256"] == hashlib.sha256(b"apk").hexdigest()


def test_zero_exit_without_xml_is_not_negative(tmp_path, monkeypatch):
    jar, apk, platforms, sources_sinks = _make_inputs(tmp_path, monkeypatch)

    metadata = poc.run_flowdroid(
        jar=jar,
        apk=apk,
        platforms_dir=platforms,
        sources_sinks=sources_sinks,
        output_dir=tmp_path / "output",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert metadata["result"]["status"] == "no_result_artifact"
    assert metadata["semantics"]["absence_is_negative_label"] is False


def test_flowdroid_internal_failure_with_zero_exit_is_analysis_failed(tmp_path, monkeypatch):
    jar, apk, platforms, sources_sinks = _make_inputs(tmp_path, monkeypatch)

    metadata = poc.run_flowdroid(
        jar=jar,
        apk=apk,
        platforms_dir=platforms,
        sources_sinks=sources_sinks,
        output_dir=tmp_path / "output",
        runner=lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            0,
            "",
            "The data flow analysis has failed. Error message: missing android.jar",
        ),
    )

    assert metadata["result"]["status"] == "analysis_failed"
    assert metadata["result"]["error_type"] == "FlowDroidInternalFailure"


def test_accepts_a_single_android_jar_for_preview_sdk_layout(tmp_path):
    android_jar = tmp_path / "android.jar"
    android_jar.write_bytes(b"framework")

    assert poc.require_platforms_path(android_jar) == android_jar.resolve()


def test_timeout_is_recorded_and_does_not_abort_artifact_writes(tmp_path, monkeypatch):
    jar, apk, platforms, sources_sinks = _make_inputs(tmp_path, monkeypatch)

    def timeout_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial")

    output_dir = tmp_path / "output"
    metadata = poc.run_flowdroid(
        jar=jar,
        apk=apk,
        platforms_dir=platforms,
        sources_sinks=sources_sinks,
        output_dir=output_dir,
        process_timeout_seconds=7,
        runner=timeout_runner,
    )

    assert metadata["result"]["status"] == "timeout"
    assert "7 seconds" in metadata["result"]["error_message"]
    assert (output_dir / "attempts.csv").is_file()
    assert (output_dir / "stdout.log").read_text(encoding="utf-8") == "partial"
