# 授權風險模型 Feature 規格 v1

狀態：**草案，尚未鎖定**。依 `SLB越權偵測實作時程.md` 執行順序第 5 項，本規格經確認後才寫入
`app/tools/build_authz_features.py`；實作並產出 feature 之後即進入 configuration lock，不得再更動。

適用對象：M2（Vanilla MLP）與 M3（MLP + SLB）。M1（Random Forest）是 leakage diagnostic，
沿用舊 feature，不受本規格拘束。

## 0. 與既有 R0／M1 產物的區隔

M1 已有一套 feature 管線，其中刻意包含 `exported`、`protected`、`permission`，是報告用來
展示「答案藏在題目裡」的展示品，**不得修改、不得與本規格混用**。兩套命名必須可一眼分辨：

| | R0 / M1（既有，不動） | 本規格（新增） |
|---|---|---|
| 程式 | `app/ml/encoder.py`、`trainer.py`、`predictor.py` | `app/tools/build_authz_features.py` |
| 規格文件 | `app/ml/feature_schema.json`（`schema_version` 1.0） | 本文件 |
| 詞彙表產物 | `dataset/training/model_v1/encoder.joblib` | `dataset/authz_v2/authz_feature_config_v1.json` |
| 欄位前綴 | `has_action_`、`has_category_`、`has_data_type_` | `if_action_`、`sink_`、`authz_` |
| schema 版本字串 | `1.0` | `authz-feature-v1` |

刻意避開 `build_features.py` 與 `feature_config_v1.json` 這兩個檔名，且新增檔案一律歸在
`app/tools/` 與 `dataset/authz_v2/`，與其他 authz_v2 工具一致，不放進 `app/ml/`。

## 1. 依據與範圍

- 禁用清單依 `authz_label_spec.md` §8.3、weak evidence 依 §8.2。
- 模型只負責 I 與 S；R 由 `app/tools/r_gate.py` 在流程最前面以確定性規則判定（ADR-0002）。
  因此 `exported`、`permission`、`protection level` 既不進 feature，也不參與產生訓練 label。
- 依 §10 與時程表 `:453`，**Gold 授權標籤不得用於 feature 的納入、排除或詞彙表統計**。
  本規格所有基數與覆蓋率數字一律取自訓練池 `dataset/authz_v2/training_units.jsonl`
  （1,685 units / 164 APK），未觸及 Gold。
- Manifest 證據來源為 `golden_review_packets.extract_manifest_evidence`，經
  `r_gate.ManifestCache` 讀取 APK binary manifest。訓練池 164 個 APK 全部讀取成功，0 失敗。

## 2. 禁用欄位

沿用第七節盤點，不變：

- `explicit_exported`、`static_exported_interpretation`、component 的 `permission`
  有無值、`application_permission`、`has_intent_filter`
- provider 的 `read_permission`、`write_permission`、`grant_uri_permissions`、`path_permissions`
- 自訂 permission 的 `protection_level`
- `sha256`、`package_name`、`component_name`、`caller_class`、`caller_method`、`caller_descriptor`
- `binary_label`、`original_label`、`source_dataset`（僅得作為 metadata，§8.1）
- `linkage_status`（§8.2 weak evidence，且描述的是工具分析涵蓋程度而非 App 性質）
- `matched_lifecycle_entry_method`（同上）
- `call_offset`（bytecode 位置，無語意）
- `risk_hint`、finding severity、人工 notes

## 3. 兩個對第七節的修訂（2026-09-25 決定）

### 3.1 intent filter 的 action / category：採用，但 MAIN 與 LAUNCHER 整個排除

第七節同時寫了「禁用 `has_intent_filter`」與「可用 action / category multi-hot（排除
MAIN + LAUNCHER 那個組合）」，兩者字面上衝突：action multi-hot 全為 0 即等同
`has_intent_filter = false`。訓練池中 1,685 筆有 710 筆（42%）對應的 component 沒有任何
intent filter，所以這個重建是實質存在的，不是理論疑慮。

**決定：採用 action / category，但把 `android.intent.action.MAIN` 與
`android.intent.category.LAUNCHER` 兩個名稱整個排除**（而非僅排除兩者的組合——各自保留即可
重建該組合，訓練池中 MAIN 出現 580 次、LAUNCHER 542 次）。

依據：

1. ADR-0002 之後 R 改由規則把關，LF 只看 I/S，**`exported` 已完全不參與訓練 label**。
   §8.3 禁 exported proxy 的原始動機是 label 洩漏，該迴路已斷。
2. action 語意是目前唯一可得的 I 證據：`SMS_RECEIVED`、`PHONE_STATE`、
   `NEW_OUTGOING_CALL`、`VIEW`、`SEND` 描述的正是「外部送什麼進來」，而 I predicate
   問的就是這件事。第九節已量化模型目前最缺的就是這類訊號。
3. MAIN 與 LAUNCHER 本身是 §8.2 明列的 weak evidence，排除後不影響上述理由。

**報告須揭露**：本組特徵蘊含 `has_intent_filter`，屬對第七節的已知放寬，理由如上。

範圍註記：本項決定同時涵蓋 action 與 category，但 category 與 data scheme / type 在後續的
維度縮減中已因訓練池普及率過低而全部排除（§4.1 B、C），與本項的 §8.3 論證無關。
最終保留的只有 action。

### 3.2 APK 層級特徵：排除，只保留 sink 對應 permission 的兩個布林值

`uses_permissions`、`min_sdk`、`target_sdk`、同 APK component 數在單一 APK 內為常數，
等同 APK 指紋。實測：

- `uses_permissions` 集合唯一識別 **110 / 164** 個 APK（67%）
- 連最粗的 `(permission 數, min_sdk, target_sdk)` 三元組都唯一識別 **102 / 164**

訓練池平均每個 APK 約 10 筆 unit，模型可藉此認出 APK 並背下該 APK 的多數 label。
第九節已證實可分辨的訊號本來就是 app-specific、negative 集中在 2 個 APK，在此分布下
提供 APK 指紋只會惡化跨 APK 泛化，並使第九節 0.519 的跨 APK 基準線失去可比性。
此外 335 種 `uses_permission` 中有 222 種是自訂 permission（出現 638 次），名稱直接內嵌
package 字串，本身即 §8.3 禁止的身分欄位。

**決定：APK 層級特徵全部排除，改以兩個布林值取代**（見 §4 第 7 組）：該 unit 的 sink 是否
有平台 permission 管轄、以及該 APK 是否宣告了該 permission。這是 unit 層級的語意，
不構成指紋。

## 4. Feature 清單（共 31 維）

初版草案為 62 維，經 2026-09-26 討論以過擬合為由縮減至 33 維，再於 2026-09-27 移除 2 個
計數維度後為 31 維。縮減依據一律是**訓練池普及率、結構冗餘與 APK 指紋效果**，
不涉及 Gold label，理由見 §4.1。

全部 31 維皆為布林或 one-hot / multi-hot，**沒有任何連續特徵**，因此無需標準化統計量。

| # | 群組 | 維度 | 編碼 | 納入理由 |
|--:|---|--:|---|---|
| 1 | `component_type` | 4 | one-hot（activity / receiver / service / provider） | 決定 entry method 與可用 IPC 形式，是 R/I 的結構前提 |
| 2 | `sink_group_id` | 9 | one-hot | S 的直接證據（敏感效果的類別）；也是罕見 sink 的泛化依靠 |
| 3 | `sink_class` + `sink_method` | 9 | one-hot，訓練池 ≥50 次的 8 種 + 1 OOV | S 的最細粒度證據；8 種涵蓋 1,454 / 1,685（86%） |
| 4 | intent filter action | 7 | multi-hot，5 個語意桶 + 1 平台 OOV + 1 `has_custom_action` | I 的直接證據：外部送什麼進來 |
| 5 | sink 對應 permission | 2 | `sink_permission_applicable`、`sink_permission_declared` 兩個布林 | 見 §5 |

第 3 組納入的 8 個 sink（訓練池次數）：

```
Method.invoke 598    Class.forName 228    Cursor.getString 180    WebView.loadUrl 173
Environment.getExternalStorageDirectory 92    ContentResolver.query 66
SmsManager.sendTextMessage 62    FileOutputStream.<init> 55
```

第 4 組的 5 個語意桶。分桶依據是 Android 對各 action 的投遞語意（外部送進來的是什麼），
屬先驗知識，與 §5 的 sink → permission 對應同一種標準，不由 Gold 或普及率排序決定：

| 維度 | 組成 action | 訓練池筆數 |
|---|---|--:|
| `if_action_sms_telephony` | `SMS_RECEIVED`、`PHONE_STATE`、`NEW_OUTGOING_CALL`、`START_SMS_SERVICE` | ~164 |
| `if_action_boot_power_net` | `BOOT_COMPLETED`、`ACTION_POWER_CONNECTED`、`CONNECTIVITY_CHANGE` | ~80 |
| `if_action_camera_media` | `IMAGE_CAPTURE`、`STILL_IMAGE_CAMERA`、`VIDEO_CAPTURE`、`VIDEO_CAMERA` | ~46 |
| `if_action_widget_wallpaper` | `APPWIDGET_UPDATE`、`WallpaperService` | ~39 |
| `if_action_implicit_content` | `VIEW`、`SEND` | ~27 |

`INSTALL_REFERRER`（8 筆）不屬上述任一語意，落入平台 OOV 維度。

### 4.1 由 62 維縮減至 31 維的五個依據

**A. `sink_group_id` 與 `sink_class+method` 結構冗餘（30 維 → 18 維）。**
實測訓練池 30 個 `sink_class+method` **每一個都只對應到 1 個 `sink_group_id`**，細粒度完全
決定粗粒度，同時放是純冗餘。但不可只留細的：Gold 384 筆中有 **32 筆的 sink 不在訓練池
≥5 的詞彙表內**（`Camera.*` 4、`AudioRecord.*` 3、`Settings$Secure.getString` 5、
`TelephonyManager.getSimSerialNumber` 5、`ClipboardManager.setPrimaryClip` 4 等），
只留細的會使這 32 筆塌進單一 OOV 維度並失去全部 sink 語意。因此保留 group 全部 9 維，
並把細粒度門檻由 ≥5 拉到 ≥50：粗粒度給全體語意，細粒度只給樣本數足以估計的。

**B. intent filter category 全部排除（4 維 → 0）。** 訓練池普及率
DEFAULT 7.2%、HOME 2.8%、MONKEY 0.8%、ALTERNATIVE 0.2%、BROWSABLE 0.1%，皆過低；
且 category 不描述「外部送什麼資料進來」（`MONKEY` 為測試自動化用），對 I 無語意貢獻。

**C. intent filter data 全部排除（2 維 → 0）。** `has_data_scheme` 1.2%（21 筆）、
`has_data_mimetype` 1.4%（23 筆），樣本數撐不起獨立維度。

**D. action 改為語意分桶（18 維 → 7 維）。** 16 個平台 action 中僅 4 個普及率 ≥1.4%，
但普及率低的數個（`NEW_OUTGOING_CALL` 7 筆、`START_SMS_SERVICE` 8 筆）語意上恰為最強的
I 證據，以次數門檻篩選會砍掉語意而保留雜訊。改按投遞語意分 5 桶，每桶皆有 ≥27 筆。

**E. unit 層級計數維度全部移除（2 維 → 0，2026-09-27）。** 原本放入「同 component 的
sink 數」與「同 component 的 distinct sink group 數」以描述敏感行為密度。實測這兩維構成
**APK 指紋**：兩者的組合共 37 種，其中 14 種只出現在單一 APK（涵蓋 286 筆），
例如 `(45 個 sink, 1 個 group)` 只存在於一個 APK 並貢獻該 APK 的 45 筆。
小數值由大量 APK 共用（`(1,1)` 出現在 97 個 APK），大數值則等同該 APK 的名牌。

以完整 feature vector 衡量「落在僅含單一 APK 的格子」的樣本比例：

| 版本 | 相異 feature vector | 單一 APK 專屬格涵蓋樣本 | 格子橫跨 APK 數中位數 |
|---|--:|--:|--:|
| 含原始計數（33 維） | 293 | 35.4% | 1 |
| 計數改分箱 | ~222 | 16.4% | 2 |
| **移除計數（31 維，採用）** | **119** | **9.1%** | **2** |

移除而非分箱的理由是研究目標：本專題的主要主張是量化自動化證據的瓶頸，模型必須是一把
乾淨的量尺，只承載 R/I/S/A 的證據。「某 component 有幾個 sink」描述的是 app 規模，
不屬於 R/I/S/A 任一 predicate，留著只會讓模型分數因不相關的理由變動，並使
「自動化證據不足」的結論可被質疑為「模型只是背了 APK」。第九章已顯示天花板（0.695）
由特徵本身決定，移除這兩維不影響該上限。

移除後 1,685 筆只落在 119 個相異 feature vector，模型的有效容量遠小於參數量，
記憶訓練樣本在結構上不可行。

此項列為 future work：component 層級的敏感行為密度本身是合理訊號，
但需要遠大於 164 個 APK 的規模才不會退化成 APK 指紋。

## 5. sink → permission 對應表

對應建在 **API 層級而非 sink group 層級**，因為多個 group 內部混用不同 permission
（例如 `SMS_PHONE` 同時含 `SmsManager.sendTextMessage` → `SEND_SMS` 與
`TelephonyManager.getDeviceId` → `READ_PHONE_STATE`）。

來源為 AOSP 對各 API 的 permission 要求，屬先驗知識，不由 Gold 或訓練池分布估計。

紀錄一項與 sink 先驗權重（`e40bb10`，先 commit 再計算）不同的程序差異：本對應表的覆蓋率
數字（下方 405 / 348 / 57）是在 commit 之前先算出來的，目的是判斷這兩個維度是否值得保留。
計算只使用訓練池，**未觸及 Gold**，因此不構成用評估集調整先驗；但順序與先例相反，在此明載。

| sink API | 所需平台 permission |
|---|---|
| `SmsManager.sendTextMessage` / `sendMultipartTextMessage` / `sendDataMessage` | `SEND_SMS` |
| `TelephonyManager.getDeviceId` / `getImei` / `getSubscriberId` / `getLine1Number` / `getSimSerialNumber` | `READ_PHONE_STATE` |
| `LocationManager.requestLocationUpdates` / `getLastKnownLocation` / `requestSingleUpdate` | `ACCESS_FINE_LOCATION` 或 `ACCESS_COARSE_LOCATION` |
| `MediaRecorder.start` / `setAudioSource`、`AudioRecord.<init>` / `startRecording` | `RECORD_AUDIO` |
| `Camera.open` / `startPreview` / `takePicture` | `CAMERA` |
| `URL.openConnection`、`OkHttpClient.newCall` | `INTERNET` |
| `Environment.getExternalStorageDirectory` / `getExternalStoragePublicDirectory` | `WRITE_EXTERNAL_STORAGE` 或 `READ_EXTERNAL_STORAGE` |
| `FileOutputStream.<init>` | `WRITE_EXTERNAL_STORAGE` |
| `FileInputStream.<init>` | `READ_EXTERNAL_STORAGE` |
| `ContentResolver.query` | `READ_CONTACTS` |
| `WifiInfo.getMacAddress` | `ACCESS_WIFI_STATE` |
| `BluetoothAdapter.getAddress` | `BLUETOOTH` |
| 其餘（全部 `CODE_EXEC`、`Cursor.getString`、`ClipboardManager.*`、`Settings$Secure.getString`、`Uri.withAppendedPath`） | **無 permission 管轄** |

需要兩個維度而非一個，因為單一布林值的 0 無法區分「無 permission 管轄」與
「有管轄但 APK 未宣告」：

- `sink_permission_applicable`：該 sink 是否有平台 permission 管轄
- `sink_permission_declared`：APK 的 `uses-permission` 是否包含其中之一（applicable = 0 時恆為 0）

訓練池實測：

```
有 permission 管轄        405 / 1,685  (24.0%)
  其中 APK 已宣告          348 / 405   (85.9%)
  其中 APK 未宣告           57 / 405   (14.1%)
無 permission 管轄      1,280 / 1,685  (76.0%)   ← 其中 CODE_EXEC 佔 1,065
```

語意上，「呼叫了需要 permission 的 sink，但 APK 從未宣告該 permission」是 S 的弱反證
（該呼叫在 runtime 很可能失敗）。這是本規格中唯一直接指向 S linkage 的自動化訊號，
但只對 57 / 1,685 筆（3.4%）產生區別。

## 6. 詞彙表凍結規則

- 詞彙表**只由訓練池 1,685 筆統計**，任何情況下不得參考 Gold。Gold 評估時出現的新名稱
  一律落入該群組的 OOV 維度。
- 只收平台前綴（`android.*`、`com.android.*`）的名稱。自訂字串內嵌 package，屬 §8.3
  身分欄位，一律不進詞彙表，改由 `has_custom_action` 單一旗標表示（影響 168 筆）。
- 納入門檻依群組而異，均以訓練池次數為準：`sink_class+method` 為 ≥50 次，
  未達者併入該組 OOV（但仍由 `sink_group_id` 表達）。action 不用次數門檻，改用 §4 的
  5 個語意桶，桶外的平台 action 併入平台 OOV 維度。
- 全部 31 維皆為布林或 one-hot / multi-hot，**沒有連續特徵，因此不需要任何標準化統計量**。
  這也意味著 config 中不存在需由訓練池估計的數值參數，只有詞彙表與對應表。
- 詞彙表、語意桶定義與 sink → permission 對應表隨 feature 一併寫入
  `dataset/authz_v2/authz_feature_config_v1.json` 並 commit，即為 configuration lock 的內容。

## 7. 已知限制

- 第 4 組特徵蘊含 `has_intent_filter`，見 §3.1。
- 模型完全沒有 A（授權控制）的特徵；`coverage_limitations` 每筆皆含
  `runtime_guard_not_analyzed`。A 列為已知限制，見第七節。
- 沒有任何 entry-to-sink linkage 的證據（`linkage_status` 依 §8.2 禁用），
  所以 S 只能由 sink 身分間接表達。這正是 ADR-0002 指出的瓶頸。
- 訓練池 `sink_group_id` 分布與 Gold 不同（CODE_EXEC 在訓練池佔 63%、在 Gold 佔 32%），
  解讀評估結果時須一併說明。
- Gold 有 32 / 384 筆的 sink 落在第 3 組的 OOV 維度，只能由 `sink_group_id` 表達。
- 沒有 component 層級的敏感行為密度特徵，理由與 future work 見 §4.1 E。
- 若訓練時出現明顯過擬合，處理方式為調整 dropout 或 weight decay，
  **不得回頭修改 feature 清單**（configuration lock）。

### 7.1 過擬合風險的實際評估

參數量並非此處的有效容量指標，記錄完整推論以免日後誤判。

**一、有效容量由相異 feature vector 數決定，不由參數量決定。** 31 維全為布林或
one-hot / multi-hot，訓練池 1,685 筆只落在 **119 個相異 feature vector**。MLP 對同一個
feature vector 必然輸出同一個機率，無法區分同一格內的樣本，因此「記憶 1,685 筆」在結構上
不可行，上限是「記住 119 格的多數標籤」。這與第九章 oracle ceiling 的邏輯相同。

**二、參數量的增減對此無幫助。** 以第三節架構（128 → 64 → 2）估算：

```
輸入 62 維：62×128 + 128×64 + 64×2 ≈ 16,300
輸入 31 維：31×128 + 128×64 + 64×2 ≈ 12,300
```

主要參數量在 128×64 的隱藏層（8,192），不在輸入層。若需要壓縮容量，
縮小隱藏層（例如 64 → 32，約 2,600 參數）比縮減 feature 有效得多；但隱藏層尺寸已於
第三節定案且 M2 與 M3 必須共用，變更屬獨立決定，不在本規格範圍內。

**三、真正較大的風險是過擬合 LF，不是過擬合訓練樣本。** LF 只看 I/S，而 sink 身分在
本規格佔 18 / 31 維。若 LF 的判準同樣建立在 sink 身分上，模型幾乎必然重建 LF，
此時訓練指標與 SLB 內部指標都會很漂亮，但 Gold 指標不動（§10.6 的 revision collapse）。
撰寫 LF 時須刻意使其判準與 feature 不完全同源。

**四、單位不獨立，有效樣本數遠小於 1,685。** 1,685 筆分布在 164 個 APK，平均 10.3 筆／APK
但極不均（最大單一 APK 76 筆，前 5 個 APK 佔 355 筆、21%）。同一 APK 內的 unit 高度相關，
就跨 APK 泛化而言有效獨立樣本數更接近 164 的量級。這是排除全部 APK 層級特徵
（§3.2、§4.1 E）的主要理由。

**五、過擬合若發生會是可見的。** 訓練池與 Gold 為 APK 互斥（lineage 排除已驗證：
385 筆 Gold unit 全部不在訓練池），因此過擬合會直接反映為 Gold 指標下降，
而非像 M1 那樣產生看似良好但虛假的指標。第九章的三條參考線（0.439 / 0.519 / 0.695）
可直接用於判讀。

## 8. 重跑指令

```bash
python -m app.tools.build_authz_features    # 產生 features 與 authz_feature_config_v1.json
```
