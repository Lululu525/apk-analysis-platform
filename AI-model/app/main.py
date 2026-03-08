import argparse
import json
from pathlib import Path

from app.pipeline import run_pipeline
from app.schemas import AnalyzeRequest


def normalize_request(raw: dict) -> dict:
    # 如果已經是 firmware schema，就直接回傳
    if "firmware" in raw:
        return raw

    # 如果是 backend 的 apk schema，就轉成 firmware-compatible schema
    if "sample" in raw:
        sample = raw.get("sample", {})
        options = raw.get("options", {})

        return {
            "job_id": raw.get("job_id"),
            "firmware": {
                "name": sample.get("name"),
                "file_path": sample.get("file_path"),
            },
            "device_meta": raw.get("apk_meta"),
            "options": {
                "run_static_scan": options.get("run_static_scan", True),
                "run_behavior_analysis": options.get("run_behavior_analysis", False),
                "severity_threshold": options.get("severity_threshold", "medium"),
            },
        }

    raise ValueError("Unsupported request schema")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    parser.add_argument("--artifacts", dest="artifacts_dir", required=True)
    args = parser.parse_args()

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)
    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    normalized = normalize_request(raw)

    req = AnalyzeRequest.model_validate(normalized)
    report = run_pipeline(req, output_dir=artifacts_dir)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    print(f"[OK] report written to: {output_path}")


if __name__ == "__main__":
    main()
