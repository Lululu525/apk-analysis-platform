"""
predictor.py

Task 6 最後一塊：對 filter_row 做推論，輸出符合
`docs/inference_data_spec.md` §2 的 row-level prediction 格式。

讀取 trainer.py 產生的 model.joblib + encoder.joblib，支援三種輸入來源：
  1. 直接對一個 APK 呼叫 build_model_features()，取得 filter_rows 後推論
     （對應 Task 7 未來 pipeline_apk.py 會用的呼叫方式）。
  2. 對一份既有的 raw filter_rows JSONL（跟 build_training_data.py 讀進來、
     還沒被 to_features() 拆解前的那種格式：sample_id/component_name/
     row_type + 攤平的 feature 欄位）做推論，離線測試不用每次都解壓 APK。
  3. 對一份既有的 training_data_spec.md 格式 JSONL（例如
     dataset/training/filter_rows.jsonl 本身）做離線批次 sanity check。
     ⚠ 這不是第 2 種格式：頂層是 sample_id/row_type/features/label/
     label_source/split，且刻意不含 component_name（見下方已知限制）。
     不要把這種檔案餵給 --filter-rows-jsonl，請用 --training-rows-jsonl。

⚠ 已知限制（top_features 是全域排名，不是 per-row 解釋）：
inference_data_spec.md §2 的 top_features 語意讀起來像是「這筆 row 的
重要特徵」，但 RandomForestClassifier 只提供全域 feature_importances_，
沒有 per-instance 貢獻度（要做到那個程度需要 SHAP 之類的方法，v1 沒有
導入）。這裡對所有 row 回傳同一份全域重要性前 5 名，不是 local
explanation。Task 8 實驗報告需要把這點寫清楚，避免被誤讀成逐筆解釋。

⚠ 已知限制（training-format 離線測試路徑的 row_id 會整批退化，且會碰撞）：
training_data_spec.md 格式的 record 在設計上就不含 component_name——
build_training_data.py 用 NON_FEATURE_KEYS 排除它是刻意的，理由是訓練
樣本不需要 row_id（見 STATUS_2026-07-18.md §2.4：「訓練資料的
NON_FEATURE_KEYS 排除 component_name 的邏輯本來就是對的……無需回頭改
訓練規格文件」）。predict_training_format_rows() 對這批資料一律把
component_name 補成 TRAINING_DATA_UNKNOWN_COMPONENT 佔位字串，換來的
代價是：同一支 APK 若有多個 filter_row（多個元件），這些 row 的
row_id 會完全相同、彼此無法區分。這條路徑只適合「predicted_label 跟
weak label 是否合理一致」的批次 sanity check，不能拿它的 row_id 做
人工抽查追溯；需要可追溯 row_id 請改用 predict_apk() 或
predict_raw_rows()（見上方已知落差 2）。這跟 07-18 決議「呼叫端沒照
inference_data_spec.md §1 提供 component_name 就該噴錯」是不同性質的
判斷——training_data_spec.md 從來就不承諾提供 component_name，不是
呼叫端違反 spec，是這條路徑本來就只能做到這個精細度，因此這裡選擇
明確標註限制、而不是套用同一套嚴格驗證。

【2026-07-18 決議】component_name 已補進 inference_data_spec.md §1，
正式成為 inference input 的必要頂層欄位（不算在 features 裡，跟訓練端
NON_FEATURE_KEYS 的排除邏輯一致）。row_id 組不出來時（component_name
缺失）視為輸入不合法，直接丟 ValueError，不再靜默退化成
`<UNKNOWN_COMPONENT>`——理由跟本專案「explicit 宣告不可被隱性邏輯覆蓋」
的一貫原則一致：這是呼叫端沒有照 spec 產生輸入的錯誤，應該讓它在推論
階段就爆出來，而不是產生一筆 row_id 不可追溯的預測結果、把問題留到報告
階段才發現。

用法：
    # 對 APK 直接推論
    python app/ml/predictor.py --apk path/to/app.apk --model-dir dataset/training/model_v1 \\
        --sample-id com.example.app__v1.0__abc123

    # 對既有 raw filter_rows JSONL 推論（跟 build_model_features() 輸出格式一樣，
    # 攤平欄位＋component_name；不是 dataset/training/filter_rows.jsonl）
    python app/ml/predictor.py --filter-rows-jsonl path/to/raw_filter_rows.jsonl \\
        --model-dir dataset/training/model_v1

    # 對 training_data_spec.md 格式的既有訓練資料做離線 sanity check
    # （例如 dataset/training/filter_rows.jsonl 本身）
    python app/ml/predictor.py --training-rows-jsonl dataset/training/filter_rows.jsonl \\
        --model-dir dataset/training/model_v1

    # 輸出寫檔（不指定則印到 stdout）
    python app/ml/predictor.py --apk path/to/app.apk --model-dir dataset/training/model_v1 \\
        --sample-id com.example.app__v1.0__abc123 --out predictions.json

也可以被其他模組直接 import（Task 7 的 pipeline_apk.py 未來會這樣用）：
    from predictor import FilterRowPredictor
    predictor = FilterRowPredictor.load(Path("dataset/training/model_v1"))
    predictions = predictor.predict_apk(apk_path, sample_id=sample_id)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import joblib

from encoder import FilterRowEncoder, load_jsonl

SCHEMA_VERSION = "1.0"
ENCODER_VERSION = "1.0"
MODEL_VERSION = "rf_filter_v1"
TOP_FEATURES_K = 5

AI_MODEL_ROOT = Path(__file__).resolve().parent.parent.parent  # app/ml/predictor.py → AI-model 根目錄
sys.path.insert(0, str(AI_MODEL_ROOT))

# 跟 build_training_data.py 的 NON_FEATURE_KEYS 保持同步；這裡刻意不 import
# build_training_data（它是一支帶 argparse main 的腳本，不適合當 library 依賴），
# 兩處各自維護時如果其中一邊改了欄位，要記得同步改另一邊。
NON_FEATURE_KEYS = {"sample_id", "package_name", "component_name", "row_type"}

# training_data_spec.md 格式的 record 本來就不含 component_name（見檔頭
# 已知限制段落）。predict_training_format_rows() 用這個佔位字串頂替，
# 讓 row_id 組得出來但無法定位到具體元件；不要跟 07-18 決議之前舊行為的
# <UNKNOWN_COMPONENT> 混淆——那是「呼叫端違反 spec」的退化，這裡是
#「這個格式本來就沒有這個資訊」的已知限制，兩者性質不同但字串沿用一致
# 方便辨識。
TRAINING_DATA_UNKNOWN_COMPONENT = "<UNKNOWN_COMPONENT>"


def to_features(filter_row: dict) -> dict:
    return {k: v for k, v in filter_row.items() if k not in NON_FEATURE_KEYS}


class FilterRowPredictor:
    """載入 trainer.py 輸出的 model.joblib + encoder.joblib，對 filter_row 做推論。"""

    def __init__(self, model, encoder: FilterRowEncoder) -> None:
        self.model = model
        self.encoder = encoder
        # top_features 是全域 feature_importances_ 排名，所有 row 共用同一份
        # （見檔頭已知限制 1），預先算好避免每筆 row 重算一次
        ranked = sorted(
            zip(encoder.feature_names_, model.feature_importances_),
            key=lambda x: x[1],
            reverse=True,
        )
        self._top_features_global = [
            {"feature": name, "importance": float(imp)} for name, imp in ranked[:TOP_FEATURES_K]
        ]

    @classmethod
    def load(cls, model_dir: Path) -> "FilterRowPredictor":
        model_path = model_dir / "model.joblib"
        encoder_path = model_dir / "encoder.joblib"
        if not model_path.exists() or not encoder_path.exists():
            raise FileNotFoundError(
                f"找不到 {model_path} 或 {encoder_path}，請先跑 trainer.py 產生模型"
            )
        model = joblib.load(model_path)
        encoder = FilterRowEncoder.load(encoder_path)
        return cls(model, encoder)

    def predict_raw_rows(self, raw_filter_rows: list[dict]) -> list[dict]:
        """對 build_model_features()["filter_rows"] 這種 raw record
        （含 sample_id/component_name/row_type + 攤平 feature 欄位）做推論。
        這是 Task 7 pipeline_apk.py 之後會用到的主要入口。
        """
        if not raw_filter_rows:
            return []

        inference_records = [
            {
                "schema_version": SCHEMA_VERSION,
                "encoder_version": ENCODER_VERSION,
                "sample_id": row.get("sample_id"),
                "row_type": row.get("row_type", "filter"),
                "component_name": row.get("component_name"),
                "features": to_features(row),
            }
            for row in raw_filter_rows
        ]
        return self._predict_records(inference_records)

    def predict_inference_records(self, records: list[dict]) -> list[dict]:
        """對已經是 inference_data_spec.md §1 格式的 record 做推論。
        §1 現在把 component_name 列為必要頂層欄位，缺少時視為輸入不合法
        （見檔頭 2026-07-18 決議），會直接丟 ValueError。
        """
        return self._predict_records(records)

    def predict_training_format_rows(self, training_rows: list[dict]) -> list[dict]:
        """對 training_data_spec.md 格式的既有 record 做離線批次
        推論／sanity check（例如直接讀 dataset/training/filter_rows.jsonl
        本身）。

        跟 predict_raw_rows() 的差異：這種格式的 features 已經是攤平好
        的模型輸入（放在 row["features"] 這個 key 底下），不需要再跑
        to_features() 拆解一次；component_name 則因為這批資料本來就沒有
        （見檔頭已知限制），一律補成 TRAINING_DATA_UNKNOWN_COMPONENT，
        代價是同一支 APK 多個元件的 row_id 會碰撞，詳見檔頭說明，不要
        拿這條路徑的 row_id 做人工抽查追溯。

        為了方便 sanity check，若 record 本身帶 label（訓練資料通常都
        有），輸出會多帶 known_label／matches_known_label 兩個欄位；這
        兩個欄位不屬於 inference_data_spec.md §2 的正式輸出格式，只在
        這條離線驗證路徑出現，串接到其他系統前記得先過濾掉。
        """
        if not training_rows:
            return []

        inference_records = []
        known_labels = []
        for row in training_rows:
            inference_records.append({
                "schema_version": row.get("schema_version", SCHEMA_VERSION),
                "encoder_version": row.get("encoder_version", ENCODER_VERSION),
                "sample_id": row.get("sample_id"),
                "row_type": row.get("row_type", "filter"),
                "component_name": TRAINING_DATA_UNKNOWN_COMPONENT,
                "features": row.get("features", {}),
            })
            known_labels.append(row.get("label"))

        predictions = self._predict_records(inference_records)
        for pred, known_label in zip(predictions, known_labels):
            if known_label is not None:
                pred["known_label"] = known_label
                pred["matches_known_label"] = (pred["predicted_label"] == known_label)
        return predictions

    def _predict_records(self, inference_records: list[dict]) -> list[dict]:
        for i, record in enumerate(inference_records):
            missing = [
                name for name in ("sample_id", "component_name")
                if not record.get(name)
            ]
            if missing:
                raise ValueError(
                    f"inference record #{i} 缺少必要欄位 {missing}，無法組出 row_id"
                    f"（inference_data_spec.md §1，2026-07-18 決議已將 component_name"
                    f" 列為必要欄位）。record 內容: {record}"
                )

        X = self.encoder.transform(inference_records)
        probabilities = self.model.predict_proba(X)[:, 1]
        predicted_labels = self.model.predict(X)

        outputs = []
        for record, prob, pred_label in zip(inference_records, probabilities, predicted_labels):
            outputs.append({
                "row_id": f"{record['sample_id']}__{record.get('row_type', 'filter')}__{record['component_name']}",
                "row_type": record.get("row_type", "filter"),
                "risk_probability": float(prob),
                "predicted_label": int(pred_label),
                "top_features": self._top_features_global,
                "model_version": MODEL_VERSION,
            })
        return outputs

    def predict_apk(self, apk_path: Path, sample_id: str) -> list[dict]:
        """對單一 APK 直接跑推論。延遲 import build_model_features，
        讓只想用既有 filter_rows JSONL 測 predictor 邏輯本身的情境，
        不需要完整 app/ 套件環境也能跑。
        """
        from app.tools.parse_manifest import build_model_features

        model_features = build_model_features(apk_path, sample_id=sample_id)
        return self.predict_raw_rows(model_features["filter_rows"])


def app_level_risk(predictions: list[dict]) -> Optional[float]:
    """inference_data_spec.md §3：app_risk_probability = max(filter_row 機率)。"""
    if not predictions:
        return None
    return max(p["risk_probability"] for p in predictions)


def main() -> None:
    parser = argparse.ArgumentParser(description="對 filter_row 做推論（Task 6 predictor）")
    parser.add_argument("--model-dir", type=Path, required=True, help="model.joblib + encoder.joblib 所在資料夾")
    parser.add_argument("--apk", type=Path, help="要推論的 APK 路徑")
    parser.add_argument("--sample-id", type=str, help="--apk 模式下的 sample_id（package__version__sha256前8碼）")
    parser.add_argument("--filter-rows-jsonl", type=Path, help="既有 raw filter_rows JSONL（跟 build_model_features() 輸出格式一樣，攤平欄位＋component_name）")
    parser.add_argument("--training-rows-jsonl", type=Path, help="既有 training_data_spec.md 格式 JSONL（例如 dataset/training/filter_rows.jsonl 本身），做離線 sanity check 用，row_id 會整批退化，見檔頭已知限制")
    parser.add_argument("--out", type=Path, help="輸出 JSON 路徑；不指定則印到 stdout")
    args = parser.parse_args()

    input_modes = [bool(args.apk), bool(args.filter_rows_jsonl), bool(args.training_rows_jsonl)]
    if sum(input_modes) != 1:
        print(
            "[FAIL] 需要指定 --apk、--filter-rows-jsonl、--training-rows-jsonl 三者之一，且只能指定一個",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.apk and not args.sample_id:
        print("[FAIL] --apk 模式需要同時指定 --sample-id", file=sys.stderr)
        raise SystemExit(1)

    try:
        predictor = FilterRowPredictor.load(args.model_dir)
    except FileNotFoundError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)

    if args.apk:
        if not args.apk.exists():
            print(f"[FAIL] 找不到 {args.apk}", file=sys.stderr)
            raise SystemExit(1)
        predictions = predictor.predict_apk(args.apk, sample_id=args.sample_id)
    elif args.filter_rows_jsonl:
        if not args.filter_rows_jsonl.exists():
            print(f"[FAIL] 找不到 {args.filter_rows_jsonl}", file=sys.stderr)
            raise SystemExit(1)
        raw_rows = load_jsonl(args.filter_rows_jsonl)
        predictions = predictor.predict_raw_rows(raw_rows)
    else:
        if not args.training_rows_jsonl.exists():
            print(f"[FAIL] 找不到 {args.training_rows_jsonl}", file=sys.stderr)
            raise SystemExit(1)
        training_rows = load_jsonl(args.training_rows_jsonl)
        predictions = predictor.predict_training_format_rows(training_rows)
        print(
            "[WARN] --training-rows-jsonl 路徑的 row_id 一律退化為 "
            f"{TRAINING_DATA_UNKNOWN_COMPONENT}，同一支 APK 的多筆 row 會共用同一個 "
            "row_id，僅適合批次 sanity check、不適合人工抽查追溯（見檔頭已知限制）",
            file=sys.stderr,
        )

    print(f"[OK] 產生 {len(predictions)} 筆 row-level 推論結果", file=sys.stderr)
    risk = app_level_risk(predictions)
    if risk is not None:
        print(f"[OK] app-level risk_probability (max): {risk:.4f}", file=sys.stderr)

    output_json = json.dumps(predictions, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output_json, encoding="utf-8")
        print(f"[OK] 推論結果寫入 {args.out}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
