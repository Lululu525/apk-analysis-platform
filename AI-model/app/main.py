from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.schemas import AnalyzeRequest, FirmwareInfo, Options
from app.pipeline import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="APK analysis pipeline")
    parser.add_argument("--in", dest="input_json", required=True)
    parser.add_argument("--out", dest="output_json", required=True)
    parser.add_argument("--artifacts", dest="artifacts_dir", required=True)
    args = parser.parse_args()

    input_path = Path(args.input_json)
    output_path = Path(args.output_json)
    artifacts_dir = Path(args.artifacts_dir)

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    sample = raw.get("sample", {})
    opts = raw.get("options", {})

    req = AnalyzeRequest(
        job_id=raw["job_id"],
        firmware=FirmwareInfo(
            name=sample.get("name", "unknown.apk"),
            file_path=sample.get("file_path"),
            sha256=sample.get("sha256"),
            file_type="apk",
        ),
        options=Options(
            run_static_scan=opts.get("run_static_scan", True),
            run_behavior_analysis=opts.get("run_behavior_analysis", False),
            severity_threshold=opts.get("severity_threshold", "medium"),
        ),
    )

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    report = run_pipeline(req, output_dir=artifacts_dir)

    output = report.model_dump()

    # Backend reads finding.get("id") — map finding_id → id
    for finding in output.get("findings", []):
        finding["id"] = finding.get("finding_id", "")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    summary = output.get("summary", {})
    print(f"[OK] report written: {output_path}")
    print(
        f"[OK] job_id={req.job_id} "
        f"risk_score={summary.get('risk_score')} "
        f"risk_level={summary.get('risk_level')} "
        f"findings={len(output.get('findings', []))}"
    )


if __name__ == "__main__":
    main()
