from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.schemas import AnalyzeRequest
from app.pipeline import run_pipeline


def normalize_request(raw: dict) -> dict:
    if "firmware" in raw:
        return raw

    if "sample" in raw:
        sample = raw.get("sample", {})
        apk_meta = raw.get("apk_meta", {})
        options = raw.get("options", {})

        return {
            "schema_version": raw.get("schema_version", "1.0"),
            "job_id": raw.get("job_id"),
            "submitted_at": raw.get("submitted_at"),
            "firmware": {
                "name": sample.get("name"),
                "file_path": sample.get("file_path"),
                "sha256": sample.get("sha256"),
            },
            "device_meta": {
                "vendor": apk_meta.get("vendor"),
                "model": apk_meta.get("package_name"),
                "firmware_version": apk_meta.get("version_name"),
                "arch_hint": apk_meta.get("arch_hint"),
            },
            "options": {
                "run_static_scan": options.get("run_static_scan", True),
                "run_behavior_analysis": options.get("run_behavior_analysis", False),
                "severity_threshold": options.get("severity_threshold", "medium"),
            },
        }

    raise ValueError("Unsupported request schema: expected 'firmware' or 'sample'")


def main():
    parser = argparse.ArgumentParser(description="AI-model CLI entrypoint")
    parser.add_argument("--in", dest="input_json", required=True)
    parser.add_argument("--out", dest="report_json", required=True)
    parser.add_argument("--artifacts", dest="artifacts_dir", default=None)
    args = parser.parse_args()

    input_json = Path(args.input_json)
    report_json = Path(args.report_json)
    artifacts_dir = Path(args.artifacts_dir) if args.artifacts_dir else None

    raw = json.loads(input_json.read_text(encoding="utf-8"))
    normalized = normalize_request(raw)

    req = AnalyzeRequest.model_validate(normalized)
    report = run_pipeline(req, output_dir=artifacts_dir)

    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    print(f"[OK] report written: {report_json}")
    print(
        f"status={report.status} "
        f"risk_score={report.summary.risk_score} "
        f"findings={len(report.findings)}"
    )


if __name__ == "__main__":
    main()