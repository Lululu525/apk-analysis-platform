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

## 6 APK paired benchmark

FlowDroid 與 MobSF smoke test 都通過後，才從候選資料中選 6 個 APK（低、中、高複雜度各 2 個）比較：

1. 不用工具的純人工時間與判讀結果。
2. 使用 MobSF + FlowDroid 後的人工時間與判讀結果。
3. 每個 APK 至少記錄 2 個 review units 的 R/I/S/A evidence completeness。
4. 工具啟動、timeout、false-positive 與人工仍需補查的項目分開計時。

若工具無法穩定重現、輸出不能定位 component/method，或整理 false positives 的時間高於純人工流程，就先停止擴大，不進入 50 APK Golden Set。
