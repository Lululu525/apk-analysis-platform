# FlowDroid authorization evidence PoC

## 目的與邊界

本 PoC 只驗證 FlowDroid 是否能穩定提供 `Intent`／`Bundle`／`Uri` 外部輸入到高信心 sensitive effect 的候選路徑，藉此減少人工追蹤資料流的工作量。

- FlowDroid finding 是 `candidate_evidence`，不是 `gold_label` 或 ground truth。
- 沒有 finding 不等於 `negative`，可能是 sources/sinks 定義、callback 建模、timeout 或工具限制造成。
- v1 entry scope 僅涵蓋 Activity、Receiver 與 started Service；Binder、Provider entry semantics 與完整 control dependence 延後。
- 先跑一個可預期命中的 toy APK；通過後才擴充 bounded toy cases，再執行 6 個真實 APK 的 paired benchmark。
- 此階段不直接跑 50 個 Golden Set APK、300 APK pilot 或完整資料集。

## 固定版本與檔案

- FlowDroid：`2.15.1`
- Uber JAR SHA-256：`51dadead47a173c494c2fa4855b1e8bd3b54e702a2c4b5ed58e60153009ae218`
- 本機 JAR（不進 Git）：`.external-tools/flowdroid/2.15.1/soot-infoflow-cmd-2.15.1-jar-with-dependencies.jar`
- Sources/Sinks：`config/flowdroid/authz-v1-sources-sinks.txt`
- Runner：`python -m app.tools.flowdroid_poc`
- 輸出根目錄（不進 Git）：`output/framework_poc/flowdroid/`

`authz-v1-sources-sinks.txt` 的 v1 sensitive effects 刻意保持小範圍：命令執行、簡訊傳送與 `ContentResolver` 寫入。這些項目仍只代表候選 S 證據；是否存在 R、I、A，以及路徑是否可實際利用，仍由人工依 annotation guide 覆核。

## 單一 APK 執行

```powershell
python -m app.tools.flowdroid_poc `
  --jar .external-tools/flowdroid/2.15.1/soot-infoflow-cmd-2.15.1-jar-with-dependencies.jar `
  --apk tests/fixtures/flowdroid_activity_exec/app/build/outputs/apk/debug/app-debug.apk `
  --platforms-dir C:/Users/s1002/AppData/Local/Android/Sdk/platforms/android-37.1/android.jar `
  --sources-sinks config/flowdroid/authz-v1-sources-sinks.txt `
  --output-dir output/framework_poc/flowdroid/activity_exec
```

每次執行必須使用不存在或空白的輸出目錄，以避免新結果覆蓋舊 evidence。產物包括：

`--platforms-dir` 接受 Android SDK 的 `platforms` 目錄或單一 `android.jar`。若 APK target SDK 為 37，但 SDK 使用 `android-37.0`／`android-37.1` 這類目錄名稱，FlowDroid 2.15.1 會尋找不存在的 `android-37/android.jar`；此時應明確傳入已安裝版本的單一 `android.jar`，並由 metadata 保留實際路徑。

- `run_metadata.json`：工具版本、JAR/APK/config SHA-256、完整參數與語意限制。
- `attempts.csv`：`success`、`incomplete`、`invalid_result_artifact`、`no_result_artifact`、`timeout`、`analysis_failed` 或 `launch_failed`，以及 XML 的 `TerminationState` 與 finding count。
- `raw/flowdroid.xml`：FlowDroid 原始結果，不直接轉成 label。
- `stdout.log`、`stderr.log`：除錯與人工稽核依據。

## Stop conditions

出現以下任一情況時，先停止擴大樣本，修正 PoC：

1. 固定 toy APK 的已知 source-to-sink path 無法重現。
2. 同一 APK 與設定重跑產生互相矛盾的結果。
3. 常態性 timeout、JVM crash 或記憶體不足。
4. 輸出無法定位 component、method 或 source/sink，不能實際節省人工時間。
5. Sources/Sinks 擴張後 false-positive workload 高於純人工流程。
