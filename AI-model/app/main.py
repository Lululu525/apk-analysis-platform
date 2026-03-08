import argparse
import json
from pathlib import Path

from app.pipeline import run_pipeline


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

    # 讀 request.json
    with open(input_path, "r", encoding="utf-8") as f:
        request_data = json.load(f)

    # 執行 pipeline
    report = run_pipeline(
        request_data=request_data,
        artifacts_dir=artifacts_dir
    )

    # 寫 report.json
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
