"""
encoder.py

依 feature_schema.json 的 filter_row 規格，把 filter_rows.jsonl 的原始
features 轉成訓練用的數值特徵矩陣。

處理方式：
  - categorical_columns（component_type, permission）：OneHotEncoder，
    permission 的 null 先映射成字串 "<NONE>" 再編碼（訓練資料規格文件裡
    的慣例）。fit 只用 train split，val/test 用 handle_unknown="ignore"
    （沒看過的類別會變成全 0，這是已知的、可接受的限制）。
  - boolean_columns（exported, protected）：直接轉成 0/1，不需要編碼器。
  - multi_hot_prefixes（has_action_/has_category_/has_data_type_）：
    對應到原始的 actions/categories/data_types 三個 list 欄位，用
    MultiLabelBinarizer 各自獨立 fit（同樣只用 train split）。
    ⚠ data_schemes 目前依 feature_schema.json 現有規格排除，未列入
    multi_hot_prefixes，若之後確認這是遺漏而非刻意排除，需要另外加一組
    MultiLabelBinarizer 處理，這個腳本目前尚未支援。

用法（通常由 trainer.py 呼叫，也可以單獨測試）：
    from encoder import FilterRowEncoder
    encoder = FilterRowEncoder()
    X_train = encoder.fit_transform(train_records)
    X_val = encoder.transform(val_records)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.preprocessing import MultiLabelBinarizer, OneHotEncoder

CATEGORICAL_COLUMNS = ["component_type", "permission"]
BOOLEAN_COLUMNS = ["exported", "protected"]
MULTI_HOT_FIELDS = {
    "actions": "has_action_",
    "categories": "has_category_",
    "data_types": "has_data_type_",
}
NONE_SENTINEL = "<NONE>"


def _normalize_permission(value: Any) -> str:
    if value is None:
        return NONE_SENTINEL
    return str(value)


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


class FilterRowEncoder:
    def __init__(self) -> None:
        self.onehot = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        self.mlbs: dict[str, MultiLabelBinarizer] = {
            field: MultiLabelBinarizer() for field in MULTI_HOT_FIELDS
        }
        self.feature_names_: list[str] = []
        self._fitted = False

    def _categorical_matrix(self, records: list[dict], fit: bool) -> np.ndarray:
        rows = []
        for r in records:
            f = r["features"]
            rows.append([
                str(f.get("component_type")),
                _normalize_permission(f.get("permission")),
            ])
        arr = np.array(rows, dtype=object)
        if fit:
            return np.asarray(self.onehot.fit_transform(arr))
        return np.asarray(self.onehot.transform(arr))

    def _boolean_matrix(self, records: list[dict]) -> np.ndarray:
        rows = []
        for r in records:
            f = r["features"]
            rows.append([int(bool(f.get(col))) for col in BOOLEAN_COLUMNS])
        return np.array(rows, dtype=float)

    def _multi_hot_matrix(self, records: list[dict], field: str, fit: bool) -> np.ndarray:
        mlb = self.mlbs[field]
        value_lists = [r["features"].get(field) or [] for r in records]
        if fit:
            return np.asarray(mlb.fit_transform(value_lists))
        # transform 前先過濾掉 fit 階段沒看過的標籤，避免 MultiLabelBinarizer
        # 對未知標籤直接丟 KeyError（它跟 OneHotEncoder 不同，沒有
        # handle_unknown 這個選項）
        known = set(mlb.classes_)
        filtered = [[v for v in vs if v in known] for vs in value_lists]
        return np.asarray(mlb.transform(filtered))

    def fit_transform(self, records: list[dict]) -> np.ndarray:
        cat = self._categorical_matrix(records, fit=True)
        boo = self._boolean_matrix(records)
        multi_parts = [self._multi_hot_matrix(records, field, fit=True) for field in MULTI_HOT_FIELDS]

        self.feature_names_ = (
            list(self.onehot.get_feature_names_out(CATEGORICAL_COLUMNS))
            + BOOLEAN_COLUMNS
            + [
                f"{MULTI_HOT_FIELDS[field]}{cls}"
                for field in MULTI_HOT_FIELDS
                for cls in self.mlbs[field].classes_
            ]
        )
        self._fitted = True
        return np.hstack([cat, boo] + multi_parts)

    def transform(self, records: list[dict]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("encoder 尚未 fit，請先呼叫 fit_transform() 對 train split 做一次")
        cat = self._categorical_matrix(records, fit=False)
        boo = self._boolean_matrix(records)
        multi_parts = [self._multi_hot_matrix(records, field, fit=False) for field in MULTI_HOT_FIELDS]
        return np.hstack([cat, boo] + multi_parts)

    def save(self, path: Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path) -> "FilterRowEncoder":
        return joblib.load(path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("用法: python encoder.py <filter_rows.jsonl 路徑>（單獨測試用）", file=sys.stderr)
        raise SystemExit(1)

    records = load_jsonl(Path(sys.argv[1]))
    train_records = [r for r in records if r["split"] == "train"]
    other_records = [r for r in records if r["split"] != "train"]

    encoder = FilterRowEncoder()
    X_train = encoder.fit_transform(train_records)
    print(f"train 特徵矩陣形狀: {X_train.shape}")
    print(f"特徵欄位數: {len(encoder.feature_names_)}")

    if other_records:
        X_other = encoder.transform(other_records)
        print(f"val+test 特徵矩陣形狀: {X_other.shape}")
