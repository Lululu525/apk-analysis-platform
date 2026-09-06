# Golden-50 靜態工具批次

`app/tools/golden_batch.py` 只讀取已凍結的 `dataset/authz_v2/golden_50_membership.csv`，依 `selection_rank` 串行執行 MobSF 與 FlowDroid。它不重新 clustering、不抽樣、不替換 APK，也不產生人工 review event、R/I/S/A、Gold label、weak label 或 SLB training data。

## 固定 membership gate

執行前同時核對：

- 50 個唯一 membership IDs、APK SHA-256 與 package；
- membership version `golden-50-v1`；
- canonical membership fingerprint `7382f4d5e0434c8b7b37fa81269f88e32fe5d2fadc119301b56d512f9768f6e4`；
- membership CSV bytes SHA-256 `0d50029142e5ac8ee567fd72a732782723eb1d57588026b0860ea00fb9694ada`；
- selection metadata 內相同的 version 與 fingerprints。

Batch 不執行 Golden generator；任何工具 failure、no finding、缺少 path 或未來 `unknown` 都不會改變 membership。

## 輸出與歷史

預設輸出：

```text
output/framework_poc/golden_50_v1/
  batch_metadata.json
  execution_ledger.csv
  batch_events.jsonl
  review_inputs/<SHA-256>.apk
  runs/<SHA-256>/mobsf/attempt_001/
  runs/<SHA-256>/flowdroid/attempt_001/
  BATCH_EXECUTION_REPORT.md
```

每個 source APK 先依 membership 驗證 SHA-256，再複製為中性 SHA 檔名並重新驗證。既有中性副本相符時重用；不符時停止該 APK 的工作並保留副本，絕不覆寫。原始 APK 只讀取，不安裝、不啟動，也不觸發動態行為。

`batch_events.jsonl` 是 append-only 執行歷史；`execution_ledger.csv` 與 `BATCH_EXECUTION_REPORT.md` 是可重建的 current view。每個 attempt 另有 `attempt_metadata.json`，保存 membership identity、帶時區時間、duration、去密設定 fingerprint、狀態／錯誤、raw artifacts 的存在狀態與 SHA-256、stdout/stderr、candidate summary version，以及 resume/retry 原因。新 attempt 永遠使用下一個 `attempt_NNN` 目錄，不覆寫舊 metadata、raw reports、logs 或 summaries。

續跑只略過 APK identity、tool config fingerprint 與已記錄 artifact existence/hash 全部相符的 terminal attempt。暫時性 MobSF 連線錯誤最多多跑一次；跨 APK 連續兩次相同的啟動／設定失敗會暫停該工具，其餘工具仍可繼續。

## 正式執行

MobSF key 只從環境變數讀取，不寫入 metadata、events、ledger 或 logs：

```powershell
$env:MOBSF_API_KEY = '<existing-local-key>'
```

第一個正式 APK 的兩個工作項目整合驗證（attempt 直接計入正式 batch）：

```powershell
.\.venv\Scripts\python.exe -m app.tools.golden_batch --max-work-items 2
```

確認 provenance 後直接續跑其餘固定工作項目：

```powershell
.\.venv\Scripts\python.exe -m app.tools.golden_batch
```

預設 FlowDroid 設定為版本 2.15.1、固定 JAR hash、`config/flowdroid/authz-v1-sources-sinks.txt`、單一 `android.jar`、`-Xmx6g`、`max_threads=1` 與 process timeout 600 秒；MobSF 為固定 image 4.4.6、localhost API 與 request timeout 600 秒。實際 Java version、JAR／sources-sinks／android.jar hashes、timeouts 與 credential-free config fingerprints 會寫入 `batch_metadata.json`。

若目前工作階段未設定 MobSF key，MobSF rows 會保持 `blocked_preflight`，FlowDroid 仍可執行；注入 key 後用相同指令即可安全續跑。Coordinator raw outputs 與 ledger 不等於已盲化的 reviewer packet，正式 allowlist packet 留待後續工作。
