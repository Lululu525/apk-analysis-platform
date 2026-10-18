# Component risk baseline — retrained 2026-10-19

## 這是什麼

這是專案自行訓練的元件層級 Random Forest baseline。網站的 APK pipeline
會先從 AndroidManifest 產生每個 component / intent-filter 的特徵列，再由
`FilterRowPredictor` 載入 `model.joblib` 與 `encoder.joblib` 進行推論。

這個候選版本未自動取代正式的 `model_v1`。若要測試它，可設定：

```bash
FILTER_ROW_MODEL_DIR=dataset/training/model_v1_retrained_20261019
```

## 資料如何產生

1. `ground_truth_with_split.csv` 列出 68 個 APK：30 個 toy APK、38 個
   CICMalDroid2020 真實世界樣本。
2. `build_training_data.py` 解析 manifest，產生 256 筆 component-level rows。
3. 每列的弱標籤由固定規則產生：
   `label = 1 iff exported == true and protected == false`。
4. 資料依既有 split 分成 train 184、validation 31、test 41。
5. `trainer.py` 以 train split fit encoder 與 200 棵樹的 Random Forest；
   `class_weight=balanced`、`random_state=42`。

精確的輸入雜湊、套件版本、參數、輸出雜湊與 split 分布記錄在
`training_manifest.json`。

## 結果與限制

train、validation、test 的 F1 都是 1.0，但不能把它解讀為真實世界漏洞偵測
準確率 100%。標籤直接由 `exported`、`protected` 計算，而這兩欄同時也是模型
輸入；256 列中有 0 列偏離這條規則。因此這個實驗只證明模型能重建規則，
存在明確 target leakage，尚未證明能泛化到人工標註的授權漏洞。

這個模型適合作為 pipeline 串接 baseline，不適合作為論文中的最終效能模型。
後續應改用獨立人工 Gold label，並以 APK/group 為單位切分，避免同一應用的元件
跨 split；也應加入不含 `exported`、`protected` 的 ablation baseline 做比較。

## 重現指令

在 repository 根目錄、已安裝 Python requirements 的環境執行：

```bash
python AI-model/app/ml/trainer.py \
  --data AI-model/dataset/training/filter_rows.jsonl \
  --out-dir AI-model/dataset/training/model_v1_retrained_20261019
```
