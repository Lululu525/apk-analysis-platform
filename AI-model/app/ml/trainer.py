"""
trainer.py

filter_row 的 v1 Random Forest 訓練腳本。讀取 filter_rows.jsonl（須含
build_training_data.py 產生的 split 欄位），用 encoder.py 轉換特徵，
訓練 RandomForestClassifier，輸出：
  - model.joblib（訓練好的模型）
  - encoder.joblib（fit 好的 encoder，推論時需要用同一份）
  - metrics.json（val/test 的 precision/recall/f1/confusion matrix，
    以及 feature importance 排名）

v1 定位：模型是輔助工具、不是主要判斷者，本階段目標是驗證 pipeline
架構跑得通、feature importance 是否符合直覺，而非追求最高準確率
（呼應 training_data_spec.md 的整體定位）。因此這裡刻意不做大規模
hyperparameter search，只用合理的預設值。

用法：
    python trainer.py --data dataset/training/filter_rows.jsonl --out-dir dataset/training/model_v1
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

from encoder import FilterRowEncoder, load_jsonl

RANDOM_STATE = 42
N_ESTIMATORS = 200


def split_records(records: list[dict]) -> dict[str, list[dict]]:
    result = {"train": [], "val": [], "test": []}
    unknown_split_count = 0
    for r in records:
        split = r.get("split")
        if split in result:
            result[split].append(r)
        else:
            unknown_split_count += 1
    if unknown_split_count:
        print(f"[WARN] {unknown_split_count} 筆 record 的 split 欄位不是 train/val/test，已忽略", file=sys.stderr)
    return result


def evaluate(model: RandomForestClassifier, X: np.ndarray, y: list[int], split_name: str) -> dict:
    y_pred = model.predict(X)
    report = classification_report(y, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y, y_pred).tolist()

    print(f"\n===== {split_name} 評估結果（共 {len(y)} 筆，label=1: {sum(y)}，label=0: {len(y) - sum(y)}）=====")
    print(classification_report(y, y_pred, zero_division=0))
    print(f"confusion matrix (rows=實際, cols=預測, 順序=[0,1]): {cm}")

    if (len(y) - sum(y)) < 5:
        print(f"[NOTE] {split_name} 的 label=0 樣本數過少（{len(y) - sum(y)} 筆），"
              f"label=0 的 precision/recall 數字統計上不穩定，解讀時需謹慎", file=sys.stderr)

    return {
        "n_samples": len(y),
        "n_positive": int(sum(y)),
        "n_negative": int(len(y) - sum(y)),
        "precision": precision_score(y, y_pred, zero_division=0),
        "recall": recall_score(y, y_pred, zero_division=0),
        "f1": f1_score(y, y_pred, zero_division=0),
        "classification_report": report,
        "confusion_matrix": cm,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="訓練 filter_row 的 v1 Random Forest 模型")
    parser.add_argument("--data", type=Path, required=True, help="filter_rows.jsonl 路徑")
    parser.add_argument("--out-dir", type=Path, required=True, help="輸出模型/encoder/metrics 的資料夾")
    args = parser.parse_args()

    if not args.data.exists():
        print(f"[FAIL] 找不到 {args.data}", file=sys.stderr)
        raise SystemExit(1)

    records = load_jsonl(args.data)
    by_split = split_records(records)

    if not by_split["train"]:
        print("[FAIL] train split 沒有任何資料，無法訓練", file=sys.stderr)
        raise SystemExit(1)

    print(f"資料筆數 -> train: {len(by_split['train'])}, val: {len(by_split['val'])}, test: {len(by_split['test'])}")

    encoder = FilterRowEncoder()
    X_train = encoder.fit_transform(by_split["train"])
    y_train = [r["label"] for r in by_split["train"]]

    print(f"編碼後特徵維度: {X_train.shape[1]}")

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )
    model.fit(X_train, y_train)

    metrics: dict = {
        "model": "RandomForestClassifier",
        "n_estimators": N_ESTIMATORS,
        "class_weight": "balanced",
        "random_state": RANDOM_STATE,
        "n_features": int(X_train.shape[1]),
        "train": evaluate(model, X_train, y_train, "train"),
    }

    if by_split["val"]:
        X_val = encoder.transform(by_split["val"])
        y_val = [r["label"] for r in by_split["val"]]
        metrics["val"] = evaluate(model, X_val, y_val, "val")

    if by_split["test"]:
        X_test = encoder.transform(by_split["test"])
        y_test = [r["label"] for r in by_split["test"]]
        metrics["test"] = evaluate(model, X_test, y_test, "test")

    importances = model.feature_importances_
    ranked = sorted(zip(encoder.feature_names_, importances), key=lambda x: x[1], reverse=True)
    metrics["feature_importance"] = [{"feature": name, "importance": float(imp)} for name, imp in ranked]

    print("\n===== Feature importance（前 15 名） =====")
    for name, imp in ranked[:15]:
        print(f"  {name}: {imp:.4f}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.out_dir / "model.joblib"
    encoder_path = args.out_dir / "encoder.joblib"
    metrics_path = args.out_dir / "metrics.json"

    import joblib
    joblib.dump(model, model_path)
    encoder.save(encoder_path)
    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    print(f"\n[OK] 模型輸出至 {model_path}")
    print(f"[OK] encoder 輸出至 {encoder_path}")
    print(f"[OK] metrics 輸出至 {metrics_path}")


if __name__ == "__main__":
    main()
