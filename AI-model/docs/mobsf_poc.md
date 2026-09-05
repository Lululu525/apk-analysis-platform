# MobSF authorization review sidecar PoC

## 目的與限制

MobSF 用來集中呈現 APK identity、components、Manifest findings 與敏感 API 位置，降低 reviewer 搜尋程式碼與 component 的時間。它不負責建立 Golden Set label，也不能單獨證明完整 R/I/S/A：

- `exported` finding 可作為 R 的候選提示，但不是 external reachability 的完整證明。
- IPC/API category 可協助定位 I 與 S，但 MobSF 沒有證明外部輸入一路影響 sensitive effect。
- 一般 security finding 不等於 A；authorization guard 的位置、約束對象與可繞過性仍需人工判讀。
- 無 finding 不等於 `negative`。

FlowDroid 用來補充 source-to-sink path candidate；MobSF 與 FlowDroid 的結果都只是人工覆核輔助。

## 固定版本

- Image tag：`opensecurity/mobile-security-framework-mobsf:v4.4.6`
- Image digest：`sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e`
- Container name：`mobsf-authz-poc`
- Local endpoint：`http://127.0.0.1:8000`

不要使用 `latest` 執行正式 benchmark，否則工具內容會在不同日期漂移。

## 啟動 sidecar

以下範例只將 port 綁定到 localhost。API key 是本機 PoC 值，不應提交到 Git；正式執行時請改用工作階段環境變數。

```powershell
$env:MOBSF_API_KEY = '<local-session-key>'

docker pull opensecurity/mobile-security-framework-mobsf:v4.4.6
docker run -d --name mobsf-authz-poc `
  -p 127.0.0.1:8000:8000 `
  -e MOBSF_API_KEY=$env:MOBSF_API_KEY `
  opensecurity/mobile-security-framework-mobsf:v4.4.6
```

確認實際 digest：

```powershell
docker image inspect opensecurity/mobile-security-framework-mobsf:v4.4.6 `
  --format '{{index .RepoDigests 0}}'
```

## 單一 APK 執行

```powershell
$env:MOBSF_API_KEY = '<same-local-session-key>'

python -m app.tools.mobsf_poc `
  --apk tests/fixtures/flowdroid_activity_exec/app/build/outputs/apk/debug/app-debug.apk `
  --output-dir output/framework_poc/mobsf/activity_exec_smoke_v1
```

輸出目錄必須不存在或為空白，產物包括：

- `run_metadata.json`：版本、image digest、APK SHA-256、時間與 evidence semantics；不含 API key。
- `attempts.csv`：成功／失敗、MobSF hash 與 SHA-256 identity check。
- `raw/upload_response.json`、`raw/scan_response.json`、`raw/report.json`：未轉成 label 的原始 API response。
- `candidate_summary.json`：僅保留 exported components、Manifest findings 與 reviewer 優先查看的 API groups。

## 離線重建 Activity summary v2

既有報告可用下列模式產生 `candidate_summary.v2.json`，不需 API key、不重跑 MobSF，也不覆蓋原始 summary 或 raw artifacts：

```powershell
.\.venv\Scripts\python.exe -m app.tools.mobsf_poc `
  --apk output/framework_poc/benchmark_6_v1/review_inputs/04_a6c3cd55bae8.apk `
  --output-dir output/framework_poc/benchmark_6_v1/runs/04_a6c3cd55bae8/mobsf `
  --rebuild-report output/framework_poc/benchmark_6_v1/runs/04_a6c3cd55bae8/mobsf/raw/report.json
```

重建前驗證報告 SHA-256 與 APK 相符，直接從 ZIP 讀取 binary Manifest，不依賴 `-X utf8`。v2 保留 `mobsf_reported_exported_activities`，由 Manifest 重建 `manifest_activity_exposure`，並使用 `effective_exported_basis` 記錄 explicit／implicit 依據。此 inventory 範圍為 `<activity>`；未擴充至 `<activity-alias>`，也不產生 authorization label。

每份 v2 記錄來源報告 reference／SHA-256、APK SHA-256、schema version、帶時區的產生時間、前版 summary hash（若存在）、修正原因、generator source hash、Androguard version 及 config fingerprint。若 v2 已存在，指令拒絕覆蓋。

本次 6-APK 修正中，第 1 個 APK 的舊 `/report_json` request 回傳 404，沒有 `raw/report.json`；改以其既有且完整的 `raw/scan_response.json` 作為 `--rebuild-report`。v2 明記實際來源及原始 report 缺失狀態，不補造 `raw/report.json`。第 2～6 個使用既有 `raw/report.json`。

本批稽核索引為 `output/framework_poc/benchmark_6_v1/candidate_summary_correction_audit.v2.json`，包含六份 v2 的 fingerprint、各 APK Activity counts、指定案例驗證結果，以及產生前後保持不變的既有檔案 SHA-256。

## 6 APK operational calibration

FlowDroid 與 MobSF smoke test 都通過後，使用已固定的 6 個 APK（低、中、高複雜度各 2 個）完成 tool-only calibration：

1. 記錄 6 次 MobSF 與 6 次 FlowDroid attempts 的 success／partial／timeout／failure。
2. 保存 APK、工具版本、設定與輸出 artifacts 的 provenance。
3. Spot-check Component、method、source／sink、Manifest／API evidence 是否可供 Reviewer 定位。
4. 不做 baseline-manual vs tool-assisted paired timing，也不要求每個 APK 固定產生 2 個 review units。

若出現系統性啟動／設定失敗、artifact 無法稽核，或輸出不能定位 Component／method，先修正後再擴大；個別 APK 的 no finding、timeout 或 failure 保留 limitation，不得直接轉成 authorization negative。Operational gate 通過後進入固定 50-APK Golden Set。
