# MobSF／FlowDroid 6-APK operational calibration

> **狀態：執行中（2026-09-04）。** 固定 membership、ledger、reviewer blinding 與既有產物繼續使用，但本階段只執行 6 個 APK × 2 個工具的 operational calibration，不做 baseline-manual vs tool-assisted paired timing。通過後依 [`SLB越權偵測實作時程.md`](SLB越權偵測實作時程.md) 進入 50-APK Golden Set。

## 與 50-APK Golden Set 的關係

本 calibration 不是 Golden Set，也不產生 authorization labels。它只在擴大人工覆核前回答三個問題：

1. MobSF／FlowDroid 能否對真實 APK 穩定批次執行？
2. 每個 attempt 能否留下完整 status、identity、version/config provenance 與原始輸出？
3. 工具提供的 Component、API 與 path candidates 是否能被 Reviewer 定位與回查？

50-APK Golden Set 仍依會議決定，以 clustering 後分層抽樣建立；本 6-APK calibration 的 low／medium／high 分層只用來觀察工具在不同複雜度下的運作情形，不能替代 clustering。

## 固定 membership

輸入只能是既有 `sample_results.csv`。Selector 先移除非 `valid`、非 `parse success`、或 SHA-256 不一致的 rows，再依下列五項 APK-level features 計算全體 percentile rank 的平均值：

- APK size
- component count
- component evidence row count
- sensitive API call-site count
- sensitive API caller count

全體分成 low／medium／high thirds。最後在以下限制下尋找距離各 tier median 最近的全域組合：

- 六個既有 source strata 各 1 筆。
- low／medium／high 各 2 筆。
- tie-break 使用固定 salt 與 `sample_id` 的 SHA-256。

這裡的 MalDroid／F-Droid label 只用來維持來源情境多樣性，明確不是 authorization label。

```powershell
python -m app.tools.framework_benchmark `
  --pilot-csv output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/sample_results.csv `
  --output-dir output/framework_poc/benchmark_6_v1
```

產物：

- `benchmark_membership.csv`：固定 6 APK、真實來源路徑、來源 label、SHA-256 與 complexity provenance；只供 coordinator／抽樣稽核使用，不是 reviewer input。
- `review_inputs/`：依 `benchmark_rank` 與 SHA-256 前 12 碼中性命名的 6 個 APK 副本；每個副本在產生時重新驗證 SHA-256。
- `execution_ledger.csv`：6 APK × 2 tools，共 12 個 pending executions。
- `manual_review_ledger.csv`：保留的 reviewer-facing ledger；以 `review_apk_path` 直接指向 `review_inputs/`。本次 operational calibration 不填純人工／工具輔助時間，也不要求固定 review-unit 數；此檔仍不得包含 `stratum`、真實 `source_path`、`source_dataset`、`original_label` 或 `binary_label`。
- `selection_metadata.json`：輸入 CSV hash、選樣演算法、coverage counts 與 membership fingerprint。

### Reviewer blinding 與 APK 定位

Reviewer 只使用 `manual_review_ledger.csv` 的 `review_apk_path` 開啟 APK；review 期間不得以 `benchmark_membership.csv` 查找檔案。中性路徑格式固定為：

```text
review_inputs/<兩位數 benchmark_rank>_<SHA-256 前 12 碼>.apk
```

不能把 canonical／pilot 的真實 `source_path` 直接放進 reviewer-facing ledger，因為來源目錄可能包含 `Benign`、`Banking`、`SMS`、`Adware`、`Riskware` 或 `F-Droid` 等 dataset/family hint。這些是來源資料集 label，不是 authorization label，但仍會造成 reviewer-context leakage。

產生器不修改原始 APK，只建立中性命名副本。若目的地已有同名檔案，產生器會先驗證 SHA-256；不一致時立即停止且不覆寫，避免 reviewer 分析錯誤樣本。

## 執行順序

依 `execution_ledger.csv` 對 6 個固定 APK 分別執行 FlowDroid 與 MobSF，並回填 status、時間、finding count、錯誤與 artifact reference。工具完成後只做輸出可定位性的 spot-check；不先執行純人工流程，也不計算 without-tools baseline。

Spot-check 只能確認 evidence 是否可供後續 Reviewer 使用，不能在本 calibration 直接產生 Gold。若 APK 沒有具體 candidate unit，必須如實記錄，不能任意把其他 Component 當成 positive。

## Decision gate

完成 12 個 tool attempts 與輸出可定位性 spot-check 後，判斷是否進入 50-APK Golden Set。至少報告：

- tool success／timeout／failure counts 與耗時分布。
- FlowDroid finding count 與 MobSF candidate groups。
- APK/tool/config identity 與 artifact completeness。
- Component、method、source／sink 或 Manifest/API evidence 是否可回查。
- 會阻止 50-APK batch 的系統性問題，以及可保留為 per-APK unknown／limitation 的個別失敗。

工具沒有 finding、分析失敗或 timeout 都不得直接寫成 authorization negative。
