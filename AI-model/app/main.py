import argparse
import json
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


SUSPICIOUS_TOKENS = {
    "READ_SMS": 20,
    "SEND_SMS": 25,
    "RECEIVE_SMS": 20,
    "READ_CONTACTS": 12,
    "READ_CALL_LOG": 18,
    "RECORD_AUDIO": 15,
    "ACCESS_FINE_LOCATION": 15,
    "ACCESS_COARSE_LOCATION": 8,
    "READ_EXTERNAL_STORAGE": 6,
    "WRITE_EXTERNAL_STORAGE": 8,
    "REQUEST_INSTALL_PACKAGES": 20,
    "SYSTEM_ALERT_WINDOW": 22,
    "WRITE_SETTINGS": 18,
    "QUERY_ALL_PACKAGES": 18,
    "SmsManager": 20,
    "TelephonyManager": 10,
    "LocationManager": 10,
    "AccessibilityService": 25,
    "MediaRecorder": 12,
    "Runtime.exec": 20,
    "DexClassLoader": 15,
    "WebView.addJavascriptInterface": 10,
    "getDeviceId": 10,
    "getLastKnownLocation": 8,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def safe_read_zip_member(zf: zipfile.ZipFile, name: str) -> bytes:
    try:
        return zf.read(name)
    except Exception:
        return b""


def extract_features_from_apk(apk_path: Path) -> dict[str, Any]:
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    features: dict[str, Any] = {
        "apk_path": str(apk_path),
        "apk_size_bytes": apk_path.stat().st_size,
        "file_sha256": "",
        "zip_entries": [],
        "dex_files": [],
        "native_libs": [],
        "has_manifest": False,
        "string_hits": {},
        "matched_tokens": [],
    }

    raw_apk = apk_path.read_bytes()
    features["file_sha256"] = sha256_bytes(raw_apk)

    with zipfile.ZipFile(apk_path, "r") as zf:
        names = zf.namelist()
        features["zip_entries"] = names
        features["has_manifest"] = "AndroidManifest.xml" in names
        features["dex_files"] = [n for n in names if n.endswith(".dex")]
        features["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]

        searchable_blobs: list[bytes] = []
        for name in features["dex_files"]:
            searchable_blobs.append(safe_read_zip_member(zf, name))

        # 有些 token 也可能在 resources / assets 裡
        for name in names:
            if name.startswith("assets/") or name.startswith("res/"):
                data = safe_read_zip_member(zf, name)
                if len(data) <= 2_000_000:
                    searchable_blobs.append(data)

    merged = b"\n".join(searchable_blobs)

    hits: dict[str, int] = {}
    for token in SUSPICIOUS_TOKENS:
        count = merged.count(token.encode("utf-8"))
        if count > 0:
            hits[token] = count

    features["string_hits"] = hits
    features["matched_tokens"] = sorted(hits.keys())

    return features


def build_findings(features: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    hits = features.get("string_hits", {})
    for token, count in hits.items():
        weight = SUSPICIOUS_TOKENS.get(token, 0)

        if weight >= 20:
            severity = "high"
        elif weight >= 12:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "id": f"RULE-{token}",
                "severity": severity,
                "title": f"Suspicious token detected: {token}",
                "description": f"Detected token '{token}' {count} time(s) in APK content.",
                "evidence": {
                    "token": token,
                    "count": count,
                },
            }
        )

    if len(features.get("native_libs", [])) > 0:
        findings.append(
            {
                "id": "RULE-NATIVE-LIB",
                "severity": "info",
                "title": "Native library present",
                "description": "APK contains native .so libraries. Manual review may be needed.",
                "evidence": {
                    "native_libs": features["native_libs"],
                },
            }
        )

    if len(features.get("dex_files", [])) > 1:
        findings.append(
            {
                "id": "RULE-MULTI-DEX",
                "severity": "info",
                "title": "Multi-dex APK detected",
                "description": "APK contains multiple dex files.",
                "evidence": {
                    "dex_files": features["dex_files"],
                },
            }
        )

    return findings


def calculate_risk_score(features: dict[str, Any], findings: list[dict[str, Any]]) -> int:
    score = 0

    for token, count in features.get("string_hits", {}).items():
        score += SUSPICIOUS_TOKENS.get(token, 0) * min(count, 3)

    # 小幅加權
    if len(features.get("native_libs", [])) > 0:
        score += 5
    if len(features.get("dex_files", [])) > 1:
        score += 3

    return min(score, 100)


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = item.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    return counts


def run_analysis(request_obj: dict[str, Any], artifacts_dir: Path) -> dict[str, Any]:
    started_at = utc_now_iso()

    job_id = request_obj.get("job_id", "unknown-job")
    sample = request_obj.get("sample", {})
    apk_path = Path(sample.get("file_path", ""))

    features = extract_features_from_apk(apk_path)
    findings = build_findings(features)
    risk_score = calculate_risk_score(features, findings)
    counts = summarize_findings(findings)

    features_path = artifacts_dir / f"{job_id}.features.json"
    save_json(features_path, features)

    finished_at = utc_now_iso()

    report = {
        "schema_version": "1.0",
        "job_id": job_id,
        "status": "success",
        "started_at": started_at,
        "finished_at": finished_at,
        "summary": {
            "schema_version": "1.0",
            "risk_score": risk_score,
            "counts": counts,
        },
        "findings": findings,
        "artifacts": {
            "logs_path": None,
            "extracted_path": None,
            "features_path": str(features_path),
        },
        "errors": [],
    }

    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="APK rule-based analysis CLI")
    parser.add_argument("--in", dest="input_path", required=True, help="Path to request.json")
    parser.add_argument("--out", dest="output_path", required=True, help="Path to report.json")
    parser.add_argument("--artifacts", dest="artifacts_dir", required=True, help="Artifacts directory")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)
    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    try:
        request_obj = load_json(input_path)
        report = run_analysis(request_obj, artifacts_dir)
        save_json(output_path, report)
        print(f"[OK] report written to: {output_path}")
    except Exception as exc:
        error_report = {
            "schema_version": "1.0",
            "job_id": "unknown",
            "status": "failed",
            "started_at": utc_now_iso(),
            "finished_at": utc_now_iso(),
            "summary": {
                "schema_version": "1.0",
                "risk_score": 0,
                "counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
            },
            "findings": [],
            "artifacts": {
                "logs_path": None,
                "extracted_path": None,
                "features_path": None,
            },
            "errors": [
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            ],
        }
        save_json(output_path, error_report)
        print(f"[ERROR] {type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    main()