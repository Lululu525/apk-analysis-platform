"""
build_training_data.py

Task 6 的 dataset builder：讀取 ground_truth.csv（須已含 split_dataset.py
產生的 split 欄位），對每個 APK 呼叫 build_model_features()，套用
training_data_spec.md §3 的 label 公式，寫出 filter_row 的 JSONL 訓練資料。

label 公式（filter_row）：
    label = 1 if (exported == True and protected == False) else 0

用法：
    python build_training_data.py \
        --ground-truth dataset/labels/ground_truth_with_split.csv \
        --toy-apk-root dataset/toy_apks \
        --real-world-root dataset/real_world_apks \
        --out dataset/training/filter_rows.jsonl

    python build_training_data.py --ground-truth dataset/labels/ground_truth_with_split.csv --toy-apk-root dataset/toy_apks --real-world-root dataset/real_world_apks --out dataset/training/filter_rows.jsonl  

--toy-apk-root 與 --real-world-root 請換成你實際的 toy/真實世界 APK 根目錄
（腳本會在底下遞迴搜尋 apk_filename，兩個根目錄都會搜）。
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Optional

from app.tools.parse_manifest import build_model_features

# filter_row 裡不屬於 features 的識別欄位，寫入 JSONL 的 features 時要排除
NON_FEATURE_KEYS = {"sample_id", "package_name", "component_name", "row_type"}


def find_apk(filename: str, sha256: Optional[str], search_roots: list[Path]) -> Optional[Path]:
    """優先用 apk_filename 精確比對；找不到才退回用 sha256 前綴搜尋。
    apk_filename 優先，是因為部分真實世界樣本的檔名跟目前算出來的 apk_sha256
    對不上（下載/解壓過程可能有落差，但檔名本身仍是磁碟上真實存在的檔案）。
    """
    for root in search_roots:
        if not root.exists():
            continue
        matches = list(root.rglob(filename))
        if matches:
            return matches[0]

    if sha256:
        for root in search_roots:
            if not root.exists():
                continue
            matches = list(root.rglob(f"{sha256}*.apk"))
            if matches:
                return matches[0]

    return None


def compute_label(filter_row: dict) -> int:
    return 1 if (filter_row.get("exported") is True and filter_row.get("protected") is False) else 0


def to_features(filter_row: dict) -> dict:
    return {k: v for k, v in filter_row.items() if k not in NON_FEATURE_KEYS}


def main() -> None:
    parser = argparse.ArgumentParser(description="產生 filter_row 訓練資料 JSONL")
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--toy-apk-root", type=Path, required=True)
    parser.add_argument("--real-world-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("dataset/training/filter_rows.jsonl"))
    args = parser.parse_args()

    if not args.ground_truth.exists():
        print(f"[FAIL] 找不到 {args.ground_truth}", file=sys.stderr)
        raise SystemExit(1)

    with args.ground_truth.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[FAIL] ground_truth.csv 沒有任何列", file=sys.stderr)
        raise SystemExit(1)

    if "split" not in rows[0]:
        print("[FAIL] ground_truth.csv 缺少 split 欄位，請先跑 split_dataset.py", file=sys.stderr)
        raise SystemExit(1)

    search_roots = [args.real_world_root, args.toy_apk_root]

    out_records: list[dict] = []
    skipped: list[str] = []
    label_counts = {"train": [0, 0], "val": [0, 0], "test": [0, 0]}  # [label0, label1]

    for row in rows:
        filename = row.get("apk_filename", "")
        sha256 = row.get("apk_sha256") or None
        split = row.get("split")

        apk_path = find_apk(filename, sha256, search_roots)
        if apk_path is None:
            skipped.append(f"{filename}（找不到檔案）")
            continue

        pkg = row.get("package_name") or "<UNKNOWN>"
        version = row.get("version_name") or "<UNKNOWN>"
        sha_prefix = (sha256 or "")[:8]
        sample_id = f"{pkg}__{version}__{sha_prefix}"

        try:
            model_features = build_model_features(apk_path, sample_id=sample_id)
        except (RuntimeError, ValueError) as exc:
            skipped.append(f"{filename}（解析失敗: {exc}）")
            continue

        for filter_row in model_features["filter_rows"]:
            label = compute_label(filter_row)
            record = {
                "sample_id": filter_row.get("sample_id", sample_id),
                "row_type": "filter",
                "features": to_features(filter_row),
                "label": label,
                "label_source": "rule_weak_label",
                "split": split,
            }
            out_records.append(record)
            if split in label_counts:
                label_counts[split][label] += 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for rec in out_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"[OK] 寫入 {len(out_records)} 筆 filter_row 訓練樣本 -> {args.out}")
    print("\n各 split 的 label 分布：")
    for split_name in ("train", "val", "test"):
        n0, n1 = label_counts[split_name]
        print(f"  {split_name}: label=0 -> {n0}, label=1 -> {n1}")

    if skipped:
        print(f"\n[WARN] {len(skipped)} 個 APK 被跳過：", file=sys.stderr)
        for s in skipped:
            print(f"  - {s}", file=sys.stderr)


if __name__ == "__main__":
    main()
