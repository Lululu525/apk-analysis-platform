# Research evidence audit

研究結果在進入簡報、論文或前端前，先用 claims CSV 將每個數值綁定到不可變的原始 JSON。
這個步驟不重算模型，而是阻止母體混用、Gold 資料洩漏與靜態 linkage 的過度解讀。

## 為什麼需要

目前實驗同時包含 candidate、training、完整 Gold、reachable Gold 與排除設計 APK 後的 Gold。
這些母體不能只用「Gold 結果」統稱。`same_batch_fit`、訓練 accuracy，或規則形成時已參考
Gold 的結果，也不得標成獨立泛化成績。`linked` 只能表示靜態呼叫圖找到可能控制流路徑，
不能自動代表資料流成立、runtime guard 缺失或漏洞可利用。

## Claims CSV

必要欄位：

| 欄位 | 用途 |
| --- | --- |
| `claim_id` | 穩定且唯一的指標 ID |
| `population_id` | 明確區分 candidate/training/Gold/reachable/excluded-design 等母體 |
| `unit_count`, `apk_count` | 指標分母；同一 population ID 必須一致 |
| `metric_name`, `metric_value` | 對外報告的名稱與數值 |
| `evaluation_design` | `independent_holdout`, `group_cross_validation`, `leave_one_apk_out`, `same_batch_fit`, `training_only`, `descriptive` |
| `gold_role` | `untouched_evaluation_only`, `tuning_or_rule_design`, `training_labels`, `not_applicable` |
| `claim_scope` | `generalization`, `internal_validation`, `descriptive`, `static_possible_path` |
| `artifact_path`, `artifact_sha256` | 相對於 artifact root 的原始 JSON 與固定 SHA-256 |
| `json_pointer` | 指向 JSON 內實際數值的 RFC 6901 pointer，例如 `/layers/reachable_subset/classification/macro_f1` |

泛化主張會被嚴格限制為 `independent_holdout` 且 Gold 只能是
`untouched_evaluation_only`。同批擬合與 training-only 結果只能用於描述或內部驗證。

## 執行

`dataset/authz_v2/research_claims_20261019.csv` 已把 10/19 進度包中的九項主要結果轉成
可稽核宣告。它保留原始完整精度，不使用簡報四捨五入後的 `0.519`、`0.695`、`0.797`
取代 JSON 原值。將 Drive 附件完整下載／解壓後，資料夾應保留以下相對位置：

```text
<artifact-root>/
  原始結果/
    候選與特徵/training_pool_summary.json
    規則與瓶頸/rule_baselines.json
    規則與瓶頸/bottleneck_analysis.json
    模型/model_eval_gold.json
    Linkage/linkage_eval.json
```

對 10/19 證據包執行：

```powershell
python -m app.tools.research_evidence_audit `
  --claims dataset/authz_v2/research_claims_20261019.csv `
  --artifact-root C:\path\to\1019-evidence-package `
  --checksums C:\path\to\1019-evidence-package\檔案校驗_SHA256.csv `
  --out C:\path\to\1019-evidence-package\research_claims_audit.json
```

`--checksums` 會先逐檔驗證附件包的 SHA-256，包含原始 JSONL、模型 run manifests、
衍生 CSV 與 README；遺失、被修改、重複或跳出 evidence root 的路徑都會使指令失敗。

一般用途則可從 `dataset/authz_v2/research_claims_template.csv` 建立新的 manifest：

在 `AI-model` 目錄執行：

```powershell
python -m app.tools.research_evidence_audit `
  --claims dataset/authz_v2/experiments/research_claims.csv `
  --artifact-root dataset/authz_v2 `
  --out dataset/authz_v2/experiments/research_claims_audit.json
```

成功時 exit code 為 0；任何證據、SHA、JSON pointer 或研究邊界錯誤時為 2。
產出的 JSON 可直接交給 CI、前端或簡報資料產生器判斷是否允許發布。
