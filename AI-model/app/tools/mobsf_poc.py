"""透過本機 MobSF sidecar API 產生可稽核的 APK 候選證據。

MobSF finding 僅供人工覆核定位，不會被轉換成 authorization label。
API key 只從參數／環境傳入，永不寫入 metadata 或 raw artifacts。
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .flowdroid_poc import prepare_output_dir, require_file, sha256_file


SCHEMA_VERSION = "mobsf-authz-poc-v1"
MOBSF_VERSION = "4.4.6"
MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:v4.4.6"
MOBSF_IMAGE_DIGEST = (
    "sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e"
)
ATTEMPT_FIELDS = (
    "apk_path",
    "apk_sha256",
    "status",
    "duration_seconds",
    "mobsf_hash",
    "reported_sha256",
    "sha256_match",
    "report_path",
    "candidate_summary_path",
    "error_type",
    "error_message",
)
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
TAIPEI_TIMEZONE = timezone(timedelta(hours=8), name="Asia/Taipei")
ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"


def _taipei_now() -> str:
    return datetime.now(TAIPEI_TIMEZONE).isoformat()


def validate_base_url(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urllib.parse.urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"無效的 MobSF base URL：{value}")
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
        raise ValueError("非本機 MobSF 必須使用 HTTPS，避免 API key 明文傳輸。")
    return normalized


def encode_multipart_file(path: Path, boundary: str) -> bytes:
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: application/vnd.android.package-archive\r\n\r\n"
    ).encode("utf-8")
    footer = f"\r\n--{boundary}--\r\n".encode("ascii")
    return header + path.read_bytes() + footer


def default_requester(
    url: str,
    *,
    headers: Mapping[str, str],
    body: bytes,
    timeout: int,
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=body,
        headers=dict(headers),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def _post_json(
    requester: Callable[..., tuple[int, bytes]],
    url: str,
    *,
    headers: Mapping[str, str],
    body: bytes,
    timeout: int,
) -> dict[str, Any]:
    status, payload = requester(
        url,
        headers=headers,
        body=body,
        timeout=timeout,
    )
    if status < 200 or status >= 300:
        raise RuntimeError(f"MobSF HTTP status={status}: {payload[:500]!r}")
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("MobSF response 不是 JSON object。")
    return decoded


def _android_attr(element: Any, name: str) -> str | None:
    value = element.get(f"{{{ANDROID_NAMESPACE}}}{name}")
    if value is None:
        value = element.get(name)
    return str(value) if value is not None else None


def _extract_manifest_activity_exposure(manifest_root: Any) -> list[dict[str, Any]]:
    activities: list[dict[str, Any]] = []
    for activity in manifest_root.findall(".//activity"):
        name = _android_attr(activity, "name")
        if not name:
            continue

        explicit_value = _android_attr(activity, "exported")
        has_intent_filter = bool(activity.findall("./intent-filter"))
        if explicit_value is None:
            explicit_exported = None
            effective_exported = has_intent_filter
            exported_basis = (
                "implicit_intent_filter"
                if has_intent_filter
                else "implicit_no_intent_filter"
            )
        else:
            explicit_exported = explicit_value.lower() == "true"
            effective_exported = explicit_exported
            exported_basis = (
                "explicit_true" if explicit_exported else "explicit_false"
            )

        activities.append(
            {
                "name": name,
                "explicit_exported": explicit_exported,
                "effective_exported": effective_exported,
                "exported_basis": exported_basis,
                "has_intent_filter": has_intent_filter,
                "permission": _android_attr(activity, "permission"),
            }
        )
    return activities


def _load_apk_manifest_root(apk_path: Path) -> Any:
    try:
        from androguard.core.apk import APK

        parsed_apk = APK(str(apk_path))
        manifest_axml = parsed_apk.get_android_manifest_axml()
        if manifest_axml is None:
            raise ValueError("APK 沒有 AndroidManifest.xml。")
        return manifest_axml.get_xml_obj()
    except Exception as exc:
        raise ValueError(f"無法解析 APK AndroidManifest.xml：{exc}") from exc


def extract_candidate_summary(
    report: Mapping[str, Any],
    *,
    manifest_root: Any | None = None,
) -> dict[str, Any]:
    """縮小人工需先查看的區域，但不推導 R/I/S/A 或 label。"""
    manifest_analysis = report.get("manifest_analysis") or {}
    android_api = report.get("android_api") or {}
    package_name = str(report.get("package_name") or "")
    package_path = package_name.replace(".", "/")
    selected_api_groups: dict[str, Any] = {}
    for key, value in android_api.items():
        if key not in {
            "api_ipc",
            "api_os_command",
            "api_sms",
            "api_content_provider",
            "api_network",
            "api_file_io",
            "api_local_file_io",
        } or not isinstance(value, Mapping):
            continue
        files = value.get("files") or {}
        application_files = {
            path: lines
            for path, lines in files.items()
            if package_path and path.startswith(package_path)
        }
        selected_api_groups[key] = {
            "application_files": application_files,
            "other_file_count": max(0, len(files) - len(application_files)),
            "metadata": value.get("metadata", {}),
        }

    def normalize_string_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str):
            try:
                parsed = ast.literal_eval(value)
            except (SyntaxError, ValueError):
                return [value] if value else []
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        return []

    mobsf_exported_activities = normalize_string_list(
        report.get("exported_activities", [])
    )
    reported_exported_count = report.get("exported_count", {})
    exported_count = (
        dict(reported_exported_count)
        if isinstance(reported_exported_count, Mapping)
        else {}
    )
    manifest_activity_exposure: list[dict[str, Any]] = []
    exported_activities = mobsf_exported_activities
    if manifest_root is not None:
        manifest_activity_exposure = _extract_manifest_activity_exposure(manifest_root)
        exported_activities = [
            row["name"]
            for row in manifest_activity_exposure
            if row["effective_exported"]
        ]
        exported_count["exported_activities"] = len(exported_activities)

    return {
        "schema_version": SCHEMA_VERSION,
        "reported_version": report.get("version"),
        "evidence_role": "candidate_evidence",
        "produces_ground_truth": False,
        "absence_is_negative_label": False,
        "identity": {
            "file_name": report.get("file_name"),
            "package_name": package_name,
            "sha256": report.get("sha256"),
        },
        "components": {
            "exported_activities": exported_activities,
            "manifest_activity_exposure": manifest_activity_exposure,
            "mobsf_reported_exported_activities": mobsf_exported_activities,
            "services": normalize_string_list(report.get("services", [])),
            "receivers": normalize_string_list(report.get("receivers", [])),
            "providers": normalize_string_list(report.get("providers", [])),
            "exported_count": exported_count,
        },
        "manifest_findings": manifest_analysis.get("manifest_findings", []),
        "selected_android_api_groups": selected_api_groups,
        "review_warning": (
            "MobSF finding 只能定位候選 component/API；仍須人工確認 entry reachability、"
            "attacker-controlled influence、entry-to-effect path 與 authorization guard。"
        ),
    }


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_attempt(path: Path, attempt: Mapping[str, Any]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ATTEMPT_FIELDS)
        writer.writeheader()
        writer.writerow({field: attempt.get(field, "") for field in ATTEMPT_FIELDS})


def _is_complete_static_report(value: Mapping[str, Any]) -> bool:
    """判斷 /scan 是否已直接回傳可供 evidence extraction 使用的完整報告。"""
    required_fields = {
        "version",
        "sha256",
        "package_name",
        "manifest_analysis",
        "android_api",
    }
    return required_fields.issubset(value)


def run_mobsf(
    *,
    apk: Path,
    output_dir: Path,
    api_key: str,
    base_url: str = "http://127.0.0.1:8000",
    request_timeout_seconds: int = 300,
    requester: Callable[..., tuple[int, bytes]] = default_requester,
    manifest_loader: Callable[[Path], Any] = _load_apk_manifest_root,
) -> dict[str, Any]:
    if not api_key:
        raise ValueError("缺少 MobSF API key。")
    apk = require_file(apk, "APK")
    base_url = validate_base_url(base_url)
    output_dir = prepare_output_dir(output_dir)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir()

    upload_path = raw_dir / "upload_response.json"
    scan_path = raw_dir / "scan_response.json"
    report_path = raw_dir / "report.json"
    summary_path = output_dir / "candidate_summary.json"
    attempts_path = output_dir / "attempts.csv"
    metadata_path = output_dir / "run_metadata.json"

    apk_sha256 = sha256_file(apk)
    common_headers = {"X-Mobsf-Api-Key": api_key}
    started_at = _taipei_now()
    start = time.perf_counter()
    status = "analysis_failed"
    error_type = ""
    error_message = ""
    mobsf_hash = ""
    reported_sha256 = ""
    report_source = ""
    summary: dict[str, Any] = {}

    try:
        boundary = f"mobsf-poc-{apk_sha256[:24]}"
        upload = _post_json(
            requester,
            f"{base_url}/api/v1/upload",
            headers={
                **common_headers,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            body=encode_multipart_file(apk, boundary),
            timeout=request_timeout_seconds,
        )
        _write_json(upload_path, upload)
        if upload.get("status") != "success":
            raise RuntimeError(f"MobSF upload failed: {upload}")
        mobsf_hash = str(upload.get("hash", ""))
        scan_form = urllib.parse.urlencode(
            {
                "scan_type": upload.get("scan_type", "apk"),
                "file_name": upload.get("file_name", apk.name),
                "hash": mobsf_hash,
                "re_scan": "1",
            }
        ).encode("ascii")
        scan = _post_json(
            requester,
            f"{base_url}/api/v1/scan",
            headers={**common_headers, "Content-Type": "application/x-www-form-urlencoded"},
            body=scan_form,
            timeout=request_timeout_seconds,
        )
        _write_json(scan_path, scan)

        if _is_complete_static_report(scan):
            report = scan
            report_source = "scan_response"
        else:
            report_form = urllib.parse.urlencode({"hash": mobsf_hash}).encode("ascii")
            report = _post_json(
                requester,
                f"{base_url}/api/v1/report_json",
                headers={
                    **common_headers,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body=report_form,
                timeout=request_timeout_seconds,
            )
            report_source = "report_json"
        _write_json(report_path, report)
        reported_sha256 = str(report.get("sha256", ""))
        if reported_sha256 != apk_sha256:
            raise ValueError(
                "MobSF report SHA-256 與輸入 APK 不符："
                f"expected={apk_sha256}, actual={reported_sha256}"
            )
        summary = extract_candidate_summary(
            report,
            manifest_root=manifest_loader(apk),
        )
        _write_json(summary_path, summary)
        status = "success"
    except (
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as exc:
        error_type = type(exc).__name__
        error_message = str(exc)

    duration = time.perf_counter() - start
    attempt = {
        "apk_path": str(apk),
        "apk_sha256": apk_sha256,
        "status": status,
        "duration_seconds": f"{duration:.6f}",
        "mobsf_hash": mobsf_hash,
        "reported_sha256": reported_sha256,
        "sha256_match": reported_sha256 == apk_sha256 if reported_sha256 else "",
        "report_path": str(report_path),
        "candidate_summary_path": str(summary_path),
        "error_type": error_type,
        "error_message": error_message,
    }
    _write_attempt(attempts_path, attempt)
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "started_at_utc": started_at,
        "completed_at_utc": _taipei_now(),
        "tool": {
            "name": "MobSF",
            "expected_version": MOBSF_VERSION,
            "image": MOBSF_IMAGE,
            "image_digest": MOBSF_IMAGE_DIGEST,
            "base_url": base_url,
            "api_key_persisted": False,
        },
        "input": {"apk_path": str(apk), "apk_sha256": apk_sha256},
        "execution": {
            "request_timeout_seconds": request_timeout_seconds,
            "force_rescan": True,
        },
        "result": {
            "status": status,
            "duration_seconds": duration,
            "mobsf_hash": mobsf_hash,
            "reported_sha256": reported_sha256,
            "sha256_match": reported_sha256 == apk_sha256 if reported_sha256 else None,
            "reported_version": summary.get("reported_version"),
            "report_source": report_source,
            "error_type": error_type,
            "error_message": error_message,
        },
        "semantics": {
            "output_role": "candidate_evidence",
            "absence_is_negative_label": False,
            "produces_ground_truth": False,
        },
    }
    _write_json(metadata_path, metadata)
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="透過本機 MobSF API 產生 authorization-review 候選證據。"
    )
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key-env", default="MOBSF_API_KEY")
    parser.add_argument("--request-timeout", type=int, default=300)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metadata = run_mobsf(
        apk=args.apk,
        output_dir=args.output_dir,
        api_key=os.environ.get(args.api_key_env, ""),
        base_url=args.base_url,
        request_timeout_seconds=args.request_timeout,
    )
    print(json.dumps(metadata["result"], ensure_ascii=False, indent=2))
    return 0 if metadata["result"]["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
