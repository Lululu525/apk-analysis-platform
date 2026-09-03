# MobSF／FlowDroid 6-APK paired benchmark

> **狀態：已暫停（2026-09-03）。** 本 benchmark 的 membership、ledger、reviewer blinding 與既有產物保留，但目前不得繼續 tool runs 或人工 review。依 [`ADR-0001`](adr/0001-single-target-apk-authorization-risk.md)，先完成 controlled toy cases 的 single-target-APK Component-path validation；只有該驗證指出明確 evidence gap，且 bounded framework PoC 能回答該缺口時，才重新啟動本 benchmark。

## 與 50-APK Golden Set 的關係

本 benchmark 不是 Golden Set，也不產生 authorization labels。它只在擴大人工覆核前回答兩個問題：

1. MobSF／FlowDroid 能否對真實 APK 穩定批次執行？
2. 工具提供的 component、API 與 path candidates 是否真的降低人工時間？

50-APK Golden Set 仍依會議決定，以 clustering 後分層抽樣建立；本 6-APK benchmark 的 low／medium／high 分層只是工具工作量測試，不能替代 clustering。

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
- `manual_review_ledger.csv`：reviewer-facing ledger；以 `review_apk_path` 直接指向 `review_inputs/`，並記錄純人工／工具輔助時間、R/I/S/A completeness 與 remaining checks。此檔不得包含 `stratum`、真實 `source_path`、`source_dataset`、`original_label` 或 `binary_label`。
- `selection_metadata.json`：輸入 CSV hash、選樣演算法、coverage counts 與 membership fingerprint。

### Reviewer blinding 與 APK 定位

Reviewer 只使用 `manual_review_ledger.csv` 的 `review_apk_path` 開啟 APK；review 期間不得以 `benchmark_membership.csv` 查找檔案。中性路徑格式固定為：

```text
review_inputs/<兩位數 benchmark_rank>_<SHA-256 前 12 碼>.apk
```

不能把 canonical／pilot 的真實 `source_path` 直接放進 reviewer-facing ledger，因為來源目錄可能包含 `Benign`、`Banking`、`SMS`、`Adware`、`Riskware` 或 `F-Droid` 等 dataset/family hint。這些是來源資料集 label，不是 authorization label，但仍會造成 reviewer-context leakage。

產生器不修改原始 APK，只建立中性命名副本。若目的地已有同名檔案，產生器會先驗證 SHA-256；不一致時立即停止且不覆寫，避免 reviewer 分析錯誤樣本。

## 執行順序

每個 APK 先依 `manual_review_ledger.csv` 與 `review_inputs/` 做不看工具輸出的純人工流程並記錄時間，再執行 FlowDroid 與 MobSF，最後做工具輔助覆核。若先看工具結果，會污染 without-tools baseline；若先看 `benchmark_membership.csv`，則會污染 reviewer blinding。

每個 APK 至少取 2 個 review units；若 APK 沒有足夠候選 unit，必須如實記錄，不能任意把其他 component 當成 positive。

## Decision gate

本節是 benchmark **重新啟動後**的 decision gate；暫停期間不填寫 `manual_review_ledger.csv`，也不以 pending／未執行結果決定是否進入 Golden Set。

完成 12 個 tool runs 與 6 個 paired manual reviews 後才判斷是否進入 50-APK Golden Set。至少報告：

- tool success／timeout／failure counts 與耗時分布。
- FlowDroid finding count 與 MobSF candidate groups。
- 有／無工具的人工時間差。
- 每個 R/I/S/A 條件仍需人工補查的比例。
- false-positive workload。

工具沒有 finding、分析失敗或 timeout 都不得直接寫成 authorization negative。
