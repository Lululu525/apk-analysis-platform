from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.scoring import score_permissions


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="APK manifest parser + risk scoring pipeline"
    )
    parser.add_argument("--in", dest="input_json", required=True)
    parser.add_argument("--out", dest="output_json", required=True)
    parser.add_argument("--artifacts", dest="artifacts_dir", required=True)
    args = parser.parse_args()

    input_path = Path(args.input_json)
    output_path = Path(args.output_json)
    artifacts_dir = Path(args.artifacts_dir)

    request = json.loads(input_path.read_text(encoding="utf-8"))
    apk_path = request["sample"]["file_path"]
    job_id = request["job_id"]

    print(f"Analyzing APK: {apk_path}")

    started_at = utc_now_iso()

    from androguard.misc import AnalyzeAPK

    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    permissions = sorted(set(a.get_permissions()))
    activities = sorted(set(a.get_activities()))

    (
        risk_score,
        risk_level,
        counts,
        findings,
        filtered_permissions,
        features,
    ) = score_permissions(permissions)

    if not findings:
        findings.append(
            {
                "id": "SUMMARY",
                "severity": "info",
                "title": "Permission analysis summary",
                "description": (
                    "No meaningful risky permissions detected. "
                    f"Filtered potential false positives: {filtered_permissions or 'None'}."
                ),
                "remediation": "Review whether all requested permissions are necessary.",
            }
        )
        counts["info"] += 1

    finished_at = utc_now_iso()

    artifacts_dir.mkdir(parents=True, exist_ok=True)

    features_path = artifacts_dir / f"{job_id}.features.json"
    features_payload = {
        "job_id": job_id,
        "apk_path": apk_path,
        "apk_info": {
            "package_name": package_name,
            "permissions": permissions,
            "activities": activities,
        },
        "filtered_permissions": filtered_permissions,
        "features": features,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
    features_path.write_text(
        json.dumps(features_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    result = {
        "schema_version": "1.0",
        "job_id": job_id,
        "status": "success",
        "started_at": started_at,
        "finished_at": finished_at,
        "apk_info": {
            "package_name": package_name,
            "permissions": permissions,
            "activities": activities,
        },
        "summary": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "counts": counts,
            "formula": features.get("formula"),
            "rule_score": features.get("rule_score"),
            "final_score": features.get("final_score"),
        },
        "findings": findings,
        "filtered_permissions": filtered_permissions,
        "artifacts": {
            "features_path": str(features_path),
        },
        "errors": [],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"[OK] report written: {output_path}")
    print(
        f"[OK] package_name={package_name} "
        f"permissions={len(permissions)} "
        f"activities={len(activities)} "
        f"risk_score={risk_score} "
        f"risk_level={risk_level}"
    )


if __name__ == "__main__":
    main()