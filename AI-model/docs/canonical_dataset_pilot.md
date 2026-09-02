# Canonical APK dataset 唯讀 consumer 與 300 筆 pilot

## 目的與資料邊界

`app/tools/canonical_dataset_pilot.py` 只把 `canonical_balanced_dataset.csv` 視為樣本成員權威（membership authority）。它不會掃描 `E:\MalDroid-2020\APKs`、F-Droid 儲存目錄或其他資料夾來新增、替換或補足樣本。

每個選中樣本依序執行：

1. 讀取 CSV 的 `source_path`。
2. 確認路徑存在且為一般檔案。
3. 以 binary mode 唯讀開啟 APK，重新計算 SHA-256。
4. 只有重算值等於 CSV `sha256` 時，才呼叫現有 `app.tools.parse_manifest.build_model_features()`。
5. 單筆失敗寫入 `sample_results.csv` 後繼續，不中止整批。

Consumer 不會寫入 canonical CSV 或 APK。輸出目錄若不是空的會直接拒絕執行，避免覆蓋先前 pilot 證據。

## 固定抽樣規則

預設依來源與原始標籤抽取六層、每層 50 筆：

- F-Droid Benign；
- MalDroid-2020 Benign；
- MalDroid-2020 Adware；
- MalDroid-2020 Banking；
- MalDroid-2020 Riskware；
- MalDroid-2020 SMS。

每層的排序鍵為：

```text
sha256(seed + "\0" + stratum_name + "\0" + apk_sha256)
```

每層取 selection score 排序最前面的 50 筆；合併後再依同一分數排序，產生全體的 `selection_rank`。因此同一份 canonical CSV、相同 seed 與 strata 定義會得到同一份選樣，且不受 CSV 列順序影響。`selected_samples.csv` 保留 canonical 原始欄位、CSV row number、`stratum_reason`、分層 rank 與 selection score；`summary.json` 另記錄選樣 manifest fingerprint。`binary_label` 僅保留為 malware metadata，不是 authorization ground truth。

## 執行方式

PowerShell：

```powershell
$canonicalCsv = 'C:\Users\s1002\Documents\ChatGPT\資料集處理\maldroid_pipeline\outputs\final\canonical_balanced_dataset.csv'
$outputDir = 'output\canonical_pilot\pilot_300_six_strata_seed_20260823_v3'

.\.venv\Scripts\python.exe -m app.tools.canonical_dataset_pilot `
  --canonical-csv $canonicalCsv `
  --output-dir $outputDir `
  --sample-size 300 `
  --seed 20260823 `
  --progress-every 10
```

若資料集移動後舊的絕對 `source_path` 已失效，本 consumer 會忠實記錄 `source_missing`，不會猜測或掃描替代路徑。應先另外產生經審核、仍以 SHA-256 鎖定的 canonical path relocation mapping，再明確擴充 consumer；不可靜默 fallback。

## 輸出檔案地圖

| 檔案 | 回答的問題 |
|---|---|
| `run_metadata.json` | 本次輸入、seed、run status 是什麼？中途中斷時是否只完成 partial artifacts？ |
| `selected_samples.csv` | 究竟選了哪 300 筆？各筆來自 canonical CSV 哪一列、哪一層、排序分數為何？ |
| `sample_results.csv` | 每筆 `source_path`、SHA-256、耗時、解析狀態、錯誤與證據量為何？ |
| `component_evidence.jsonl` | 成功解析後實際產生哪些 component-level `filter_rows`？ |
| `manifest_path_evidence.jsonl` | 成功解析後實際產生哪些 manifest-only resolution candidates？ |
| `sensitive_api_callers.jsonl` | 哪些 sensitive API allowlist call sites 有 XREF caller class/method/descriptor/offset？哪些只能直接對到 component class 或 lifecycle entry？ |
| `summary.json` | 成功率、時間分布、錯誤分類、證據總量及 input fingerprint 為何？ |
| `REPORT.md` | 給人工閱讀的繁體中文結果摘要與解讀限制。 |

## 成功率與時間定義

- `sha256_match_rate_selected`：SHA-256 相符筆數 / 300 筆選樣。
- `success_rate_selected`：解析成功筆數 / 300 筆選樣。缺檔、hash mismatch 與 parser failure 都會反映在這個較嚴格分母。
- `success_rate_hash_verified`：解析成功筆數 / SHA-256 驗證通過筆數，用來分離來源可用性與解析器可用性。
- `hash_seconds`：單一 APK 以 1 MiB chunks 重算 SHA-256 的 wall-clock time。
- `parse_seconds`：`build_model_features()` 的 wall-clock time。現行 analyzer 使用 Androguard `AnalyzeAPK`，時間包含其 APK/Manifest/DEX 分析與現有 sensitive API 掃描流程。
- Pilot 執行時會停用 Androguard 自身逐 AXML/DEX 指令的 DEBUG/INFO console log，只保留 consumer 每 N 筆的進度訊息，避免大量 terminal I/O 污染 `parse_seconds`。
- Parser failure 會再以 `parse_encoding_error`、`parse_invalid_bytecode` 或一般 `parse_error` 分類；分類不會把失敗樣本排除或重新抽樣。
- mean、p50、p95 與 max 以成功或 attempted 樣本的逐筆 wall-clock seconds 計算；`summary.json` 明列分母與最慢樣本身分。

## Component/path 證據定義與限制

- `component_total_count`：`app_summary.components` 中 activity、service、provider、receiver 的總數，代表成功解析出的全部 Manifest components。
- `component_evidence_row_count`：現有 `_build_filter_rows()` 產生的 component-level rows。具有 intent filter 的 component 會產生一列；沒有 intent filter 時，只有 exported component 會產生一列。因此它通常不等於全部 component 數。
- `exported_component_count`：`component_evidence.jsonl` 中 `exported=true` 的列數；`unique_exported_component_name_count` 另以 `(APK, component_name)` 去除 Manifest 重複宣告。兩者分母不可混用。
- `manifest_resolution_path_count`：現有 `_build_resolution_rows()` 的 1:1 manifest-only candidates。現階段 `intent_component_name` 與 type 是 `<UNKNOWN>`，而且不是 DEX caller-to-callee tracing。
- `sensitive_api_call_site_count`：Androguard XREF 命中 production allowlist 的 call sites；`sensitive_api_caller_count` 是同一 APK 內依 caller class/method/descriptor 去重後的 callers。
- `sensitive_api_direct_component_caller_count`：caller class 名稱可直接對到 Manifest component；`sensitive_api_direct_entry_caller_count` 進一步要求 caller method 是固定 lifecycle entry。這是直接 identity match，不是跨方法 call graph。

所以 `manifest_resolution_path_count` 只能回答「目前 manifest-only pipeline 能產生多少候選 resolution evidence」，不能宣稱為實際 IPC 呼叫路徑、可被攻擊者控制的路徑、或已確認越權漏洞。Sensitive API 計數也只是 allowlist XREF candidates；部分廣泛 API（例如 `Cursor.getString`、`FileInputStream`）需要額外資料流脈絡，不能直接視為已確認 sensitive sink。

Reflection、native code、runtime-loaded code、unresolved dynamic dispatch、跨方法 entry-to-caller reachability、attacker-controlled input 與 runtime authorization guard 都不在本 pilot 的完整證明範圍。找不到證據時不得自動標成 negative；對 component-path authorization label 應保留 `unknown/abstain`。
