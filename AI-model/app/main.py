from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.schemas import AnalyzeRequest
from app.pipeline import run_pipeline


def normalize_request(raw: dict) -> dict:
    """
    將 backend 的 APK request schema
    轉成目前 AI-model pipeline 可接受的 firmware schema。
    """

    # 1. 已經是 firmware schema，直接回傳
    if "firmware" in raw:
        return raw

    # 2. backend 的 apk-platform schema
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


def parse_args():
    parser = argparse.ArgumentParser(description="AI-model CLI entrypoint")
    parser.add_argument("--in", dest="input_path", required=True, help="Path to request.json")
    parser.add_argument("--out", dest="output_path", required=True, help="Path to report.json")
    parser.add_argument("--artifacts", dest="artifacts_dir", required=True, help="Artifacts directory")
    return parser.parse_args()


def main():
    args = parse_args()

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)
    artifacts_dir = Path(args.artifacts_dir)

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    normalized = normalize_request(raw)

    req = AnalyzeRequest.model_validate(normalized)
    report = run_pipeline(req, output_dir=artifacts_dir)

    output_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8"
    )

    print(f"[OK] report written to: {output_path}")


if __name__ == "__main__":
    main()
