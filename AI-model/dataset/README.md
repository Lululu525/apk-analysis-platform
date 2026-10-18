# Dataset

本資料夾為 NSTC 大專生研究計畫（越權行為分析）的訓練資料集。

## 資料夾說明

| 資料夾 | 說明 |
|---|---|
| `toy_apks/` | 手工設計的 Toy APK，覆蓋 5 種漏洞場景（A–E） |
| `opensource_apks/` | 從 GitHub 開源 Android 專案 build 出的 APK |
| `public_apks/` | 從 F-Droid / AndroZoo 下載的公開 APK |
| `labels/ground_truth.csv` | 所有 APK 的 ground truth 標籤表 |
| `authz_v2/gold_review_log.jsonl` | Golden-50 append-only 人工審查權威紀錄 |
| `authz_v2/golden_50_labels_materialized.csv` | 由 review log 物化的每個 review unit 最新 Gold label；只供評估 |
| `authz_v2/golden_50_labels_summary.json` | 物化來源雜湊、label/confidence 分布與評估資格摘要 |

## 標籤說明

- `label = 1`：有越權風險（手動標記或 rule engine 確認）
- `label = 0`：正常（對照組）
- `label_source = manual`：手工標記的 ground truth
- `label_source = rule_weak_label`：由 `privilege_rules.py` 生成的弱標籤

## 場景對照

| 場景 | 偵測目標 |
|---|---|
| A | OVER_PRIVILEGE（過度宣告危險權限） |
| B | IPC_SERVICE_HIJACK（未保護的 exported Service） |
| C | IPC_CONFUSED_DEPUTY（Intent Spoofing） |
| D | IPC_BROADCAST_THEFT（未保護的敏感廣播接收器） |
| E | IPC_PROVIDER_REDELEGATION（未保護的 ContentProvider） |

## APK 總數上限

100–150 個 APK（4 個月內可完成標記的現實限制）。

## 注意事項

- `toy_apk_sources/` 資料夾存放 Android Studio 原始碼，不進 git
- 只有 build 出來的 `.apk` 檔案進 git（存放在本資料夾下）
- 研究指標進入簡報或前端前，應使用 [`research_evidence_audit`](../docs/research_evidence_audit.md)
  綁定母體、評估設計、Gold 角色、原始 JSON pointer 與 SHA-256。
- `authz_v2` Golden-50 與早期 `labels/ground_truth.csv` 是不同任務與不同
  標籤定義，不得混用。Golden-50 固定為 `untouched_evaluation_only`，不可加入
  Vanilla／SLB／Random Forest 訓練、特徵選擇、threshold 或規則設計。
- `gold_authz_label=unknown` 不可轉成 negative；二元評估時必須排除並另外報告數量。

## 重新物化 Golden-50 最新標籤

在 `AI-model/` 目錄執行：

```powershell
..\.venv\Scripts\python.exe -m app.tools.materialize_gold_labels
```

工具會驗證 event ID、supersession chain、每個 review unit 只有一個最新版事件，
並在摘要中記錄 authority log 與輸出 CSV 的 SHA-256。它不修改人工 review log。

## 對 Golden-50 做 held-out 評估

預測檔可為 CSV、JSONL 或 JSON，每筆至少包含 `review_unit_id` 與
`predicted_label`；若有連續分數則放在 `score`。多 seed／模型可另帶
`model_id`、`seed`：

```powershell
..\.venv\Scripts\python.exe -m app.tools.evaluate_gold_predictions `
  --predictions path\to\predictions.csv `
  --out output\gold_evaluation.json
```

預設要求覆蓋全部 361 筆 binary Gold，遇到未知 identity 或缺漏會失敗。
只有預先定義的子母體分析才可明確加入 `--allow-partial`，且報告必須同時呈現
coverage。評估器不訓練模型、不用 Gold 選 threshold，也不把 24 筆 human
unknown 轉成 negative。
