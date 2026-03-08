from __future__ import annotations
import argparse
from pathlib import Path
from .pipeline import run_cli

def main():
    parser = argparse.ArgumentParser(description="AI Firmware Analyzer (CLI)")
    parser.add_argument("--in", dest="input_json", required=True, help="Path to analyze request JSON")
    parser.add_argument("--out", dest="report_json", required=True, help="Path to output report JSON")
    parser.add_argument("--artifacts", dest="artifacts_dir", default=None, help="Directory to store artifacts/features")
    args = parser.parse_args()

    input_json = Path(args.input_json)
    report_json = Path(args.report_json)
    artifacts_dir = Path(args.artifacts_dir) if args.artifacts_dir else None

    report, out_path = run_cli(input_json, report_json, output_dir=artifacts_dir)
    print(f"[OK] report written: {out_path}")
    print(f"status={report.status} risk_score={report.summary.risk_score} findings={len(report.findings)}")

if __name__ == "__main__":
    main()