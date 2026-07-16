#!/usr/bin/env python3
"""
split_dataset.py

依 training_data_spec.md 第 4 節「切分規則」，在 APK 層級將 ground_truth.csv
的每一列（每列已對應一個 APK）切分為 train/val/test，並寫回 `split` 欄位。

規則（對齊 training_data_spec.md §4）：
- 切分單位是整個 APK。ground_truth.csv 每列即一個 APK（不是 component-level
  row），因此可以直接對列做切分——不需要另外 group by，但腳本仍會主動檢查
  apk_filename 是否有重複，避免未來 schema 變動後不小心違反這個假設。
- 比例：train 70% / val 15% / test 15%。
- 方法：先將 APK 清單 shuffle，再依比例切分。
- random_state 固定為 42，確保可重現。
- 這裡刻意不做 stratified split（label 分層抽樣），因為 spec 只寫「shuffle
  後依比例切分」，沒有提到分層。若之後發現切分後某個 split 的正負樣本比例
  過於懸殊，屬於「是否要改用 stratified split」的獨立實作決策，可以再討論；
  這個腳本會印出每個 split 的 label 分布，方便你自己判斷要不要調整。

用法：
    python split_dataset.py --ground-truth ground_truth.csv
    python split_dataset.py --ground-truth dataset/labels/ground_truth.csv --output dataset/labels/ground_truth_with_split.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15
RANDOM_STATE = 42


def assign_splits(df: pd.DataFrame, stratify: bool = False) -> pd.DataFrame:
    """對 df 的列（每列一個 APK）指定 train/val/test，回傳新增 split 欄位的 df。

    stratify=True 時，依 label 欄位做分層抽樣，確保每個 split 的正負樣本
    比例跟整體資料集接近一致——這是實作層級的調整（不影響 label 定義本身），
    用來處理小資料集下單純 shuffle 可能切出「某個 split 幾乎沒有負樣本」
    這種評估上不具意義的極端情況。
    """
    if abs((TRAIN_RATIO + VAL_RATIO + TEST_RATIO) - 1.0) > 1e-9:
        raise ValueError("split ratios 必須加總為 1.0")

    n = len(df)
    if n == 0:
        raise ValueError("ground_truth.csv 沒有任何列可供切分")
    if n < 10:
        print(
            f"[WARN] 只有 {n} 個 APK，切分後每個 split 的樣本數會很少，"
            "統計上不具代表性，僅供 pipeline 流程驗證用",
            file=sys.stderr,
        )

    stratify_col = df["label"] if stratify else None

    # 先切 train / temp（val+test 合併）
    train_df, temp_df = train_test_split(
        df,
        train_size=TRAIN_RATIO,
        random_state=RANDOM_STATE,
        shuffle=True,
        stratify=stratify_col,
    )

    # 再把 temp 對半切成 val / test（15% / 15%）
    temp_stratify_col = temp_df["label"] if stratify else None
    val_df, test_df = train_test_split(
        temp_df,
        train_size=VAL_RATIO / (VAL_RATIO + TEST_RATIO),
        random_state=RANDOM_STATE,
        shuffle=True,
        stratify=temp_stratify_col,
    )

    df = df.copy()
    df.loc[train_df.index, "split"] = "train"
    df.loc[val_df.index, "split"] = "val"
    df.loc[test_df.index, "split"] = "test"
    return df


def print_label_balance(df: pd.DataFrame) -> None:
    if "label" not in df.columns:
        return
    print("\n各 split 的 label 分布（供你自行判斷是否需要 stratified split）：")
    for split_name in ("train", "val", "test"):
        sub = df[df["split"] == split_name]
        if len(sub) == 0:
            continue
        pos = int((sub["label"] == 1).sum())
        neg = int((sub["label"] == 0).sum())
        print(f"  {split_name}: label=1 -> {pos}, label=0 -> {neg}")


def main() -> None:
    parser = argparse.ArgumentParser(description="APK 層級 train/val/test 切分")
    parser.add_argument("--ground-truth", required=True, type=Path, help="ground_truth.csv 路徑")
    parser.add_argument("--output", type=Path, default=None, help="輸出路徑，預設覆寫原檔")
    parser.add_argument(
        "--stratify",
        action="store_true",
        help="依 label 做分層抽樣，確保每個 split 的正負樣本比例接近整體資料集"
        "（建議在正負樣本比例懸殊、且發現某個 split 少數類別樣本數過少時使用）",
    )
    args = parser.parse_args()

    if not args.ground_truth.exists():
        print(f"[FAIL] 找不到檔案: {args.ground_truth}", file=sys.stderr)
        raise SystemExit(1)

    df = pd.read_csv(args.ground_truth)

    if "apk_filename" not in df.columns:
        print("[FAIL] ground_truth.csv 缺少 apk_filename 欄位，無法確認 APK 唯一性", file=sys.stderr)
        raise SystemExit(1)

    dup_mask = df["apk_filename"].duplicated()
    if dup_mask.any():
        dup_names = df.loc[dup_mask, "apk_filename"].tolist()
        print(
            f"[FAIL] 發現重複的 apk_filename，違反「一列即一個 APK」的切分假設: {dup_names}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    result = assign_splits(df, stratify=args.stratify)

    out_path = args.output or args.ground_truth
    result.to_csv(out_path, index=False)

    counts = result["split"].value_counts()
    total = len(result)
    print(f"[OK] 切分完成，共 {total} 個 APK")
    for split_name in ("train", "val", "test"):
        c = int(counts.get(split_name, 0))
        pct = c / total * 100 if total else 0
        print(f"  {split_name}: {c} ({pct:.1f}%)")

    print_label_balance(result)
    print(f"\n寫入: {out_path}")


if __name__ == "__main__":
    main()
