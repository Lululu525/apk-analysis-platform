# 安卓 App 越權分析模型開發計畫

## 專案背景

本專案為 NSTC 115 年度大專學生研究計畫，研究期間自 115 年 7 月 1 日至 116 年 2 月底，共 8 個月。
本 PLAN.md 規劃核心實作的前 **4 個月**（Month 1–4），對應 MVP 完成目標。

**研究題目**：結合逆向工程與機器學習之行動應用程式權限越權行為分析與惡意風險評估平台

---

## 核心架構決策（不可更動）

| 決策 | 說明 |
|------|------|
| 不棄用現有 Extractor/Detector | Extractor 改為 Pre-processing；Detector 改為 rule baseline |
| Hidden Privilege 核心 vector 是 row-level | 非 app-level；`intent=[action, category, type, permission]`，`filter=[action, category, type, permission]`，`resolution=[intent fields + intent app + filter fields + filter app]` |
| 弱標註來源 | `privilege_rules.py` 輸出作為 `risk_hint`，例如 `IPC_SERVICE_HIJACK`、`IPC_CONFUSED_DEPUTY` |
| 報告保留可解釋性 | Detector 輸出 rule findings；Model 輸出 `risk_probability` + feature attribution；兩者並存 |
| AndroCom 定位 | 僅作方法論參考（keyword、balanced sampling 策略），不直接引入 source code snippet 作為訓練資料 |
| filter_row 編碼方式 | 採用 multi-hot encoding：一個 component 一筆 row，action/category/data_type 各展開為 `has_action_*`、`has_category_*`、`has_data_type_*` 布林欄位，不做笛卡爾積展開 |
| resolution_row action 欄位 | 使用 `action_match` 布林值（intent 的 action 集合與 filter 的 action 集合是否有交集），不將 filter 側 multi-hot 全部展開進 resolution_row |
| intent_row 來源（v1 限制） | v1 manifest-only 階段，intent_row 從 filter_row 1:1 反推，sender 為 `<UNKNOWN>`，無獨立訓練價值；v2 bytecode 補強後才有真實 sender 資訊 |
| bytecode 補強（v2）定位 | 從 smali/bytecode 掃描 `new Intent()` / `startActivity()` 等 API 呼叫，提取 sender component 身份、發送的 action、caller 持有的 permission，以建構有意義的 resolution_row |

---

## KAN-39 原型狀態

KAN-39（提取敏感 API 使用行為）目前已有組員提供的原型實作，內容包含敏感 API 分組列表、Androguard XREF 掃描、字串 fallback，以及依 API 群組聚合 Finding 的設計。

此原型尚未整合進本 repo，也尚未通過本專案既有 pipeline 與測試驗收。因此本計畫暫時將 KAN-39 視為「已有參考實作、待整合驗證」，不標記為正式完成。

待組員將功能整合進 GitHub 或提供確認版檔案後，再重新審視 Task 3、Task 7 與測試規劃是否需要調整。

---

## 參考來源

- 本地論文：`/Users/hikaru820/Documents/論文/Detection of Hidden Privilege Escalations in Android.pdf`
- 本地論文：`/Users/hikaru820/Documents/論文/AndroCom A Real-World Android Applications' Vulnerability Dataset to Assist with Automatically Detecting Vulnerabilitie.pdf`
- 大專生專題企劃書： `/Users/hikaru820/Documents/專題/大專生計畫/補助大專學生研究計畫申請書(含指導教授初評意見表).pdf`
- AndroCom 官方 repo：https://github.com/kemrec/AndroCom/
- MDPI 論文頁：https://www.mdpi.com/2076-3417/15/5/2665

---

## 4 個月里程碑

| 月份 | 目標 |
|------|------|
| **Month 1** | Task 1 + Task 2 + Task 3 完成：`build_model_features()` 可對單一 APK 輸出三種 row schema，測試穩定 |
| **Month 2** | Task 4 + Task 5 完成：100–150 APK starter dataset + weak labels 就位 |
| **Month 3** | Task 6 + Task 7 完成：MVP pipeline 端到端可跑，模型有初步 metrics |
| **Month 4** | Task 8 完成：golden dataset 涵蓋全部 5 種場景，實驗可重現，撰寫交付文件 |

---

## Task 1：論文 Vector 與現狀差異表 ✅ 已完成

**任務名稱與核心功能**
建立 `Hidden Privilege Vector Spec v1`，將論文中的三種 vector 對應到本地專案的實作場景，作為後續 Parser、Dataset、Model 的共用規格。

**詳細執行指示**
1. 新寫一份規格文件，明確定義三種 row：`intent_row`、`filter_row`、`resolution_row`。
2. `intent_row` 欄位固定為：`sample_id`, `package_name`, `component_name`, `component_type`, `action`, `category`, `data_type`, `permission`, `is_explicit`, `source`。
3. `filter_row` 欄位固定為：`sample_id`, `package_name`, `component_name`, `component_type`, `action`, `category`, `data_type`, `permission`, `exported`, `protected`。
4. `resolution_row` 欄位固定為：`sample_id`, `intent_*`, `filter_*`, `match_action`, `match_category`, `match_type`, `caller_permission`, `callee_permission`, `risk_hint`。
5. 保留 `data_scheme` 作為輔助欄位，但 v1 模型核心 encoder 只使用論文對齊欄位 `action/category/type/permission`。
6. 對現有 `parse_manifest.py` 輸出與上述三種 row 做差異表：已支援、部分支援、缺少。

**完成檢查目標**
完成一份可交給實作者參考的 vector spec，每個欄位都有說明、來源、缺值策略，明確指出目標 Parser 缺 filter row、resolution row、encoder 與 label schema。

---

## Task 2：重構 Parser 為模型 Pre-processing ✅ 已完成

**任務名稱與核心功能**
將現有 `parse_manifest.py` 從「輸出概要 JSON」純化為「輸出模型訓練/推論所需 row-level feature JSON」。

**詳細執行指示**
1. 保留目前 `build_features(apk_path)` 的 manifest summary，避免破壞現有測試。
2. 新增 `build_model_features(apk_path)`，輸出 `intent_rows`, `filter_rows`, `resolution_rows`, `app_summary`。
3. 從 `androguard_analyzer.ComponentInfo` 生成 `filter_rows`，採用 **multi-hot encoding**：一個 component 一筆 row，action/category/data_type 各自展開為布林欄位（`has_action_VIEW`、`has_category_DEFAULT` 等），不做笛卡爾積展開。
4. 對 manifest 可解析的 implicit intent/filter 做單一 App 內部 matching，生成初步 `resolution_rows`，matching 結果以 `match_action`（布林值）表示 action 集合的交集關係，而非逐 action 比對。
5. 對無法由 manifest 得知的 code-generated intent，標記 `source="manifest_only"`，後續由 bytecode extractor（v2）補強。
6. 更新測試，覆蓋 activity/service/provider/receiver、protected/unprotected、缺 action/category/type、multiple filters。

**完成檢查目標**
給定一個 APK 執行 Parser 時，可以同時得到 summary 與新 row-level features，測試能識別三種 row schema 穩定，且缺值不會導致 encoder 失敗。

---

## Task 3：Extractor/Detector 分工重定義 ✅ 已完成

**任務名稱與核心功能**
解決目前 Extractor 與 Detector 分工不清、核心職責衝突的問題，改為清晰的三層架構。

**詳細執行指示**
1. Extractor 只負責萃取原始事實：manifest、permissions、components、intent filters、strings、sensitive APIs。
2. Feature Builder 負責將原始事實轉換為模型 row：intent/filter/resolution/app_summary。
3. Detector 保留為 rule-based baseline，輸出 findings、risk hints、weak labels，不直接代替模型預測。
4. `privilege_rules.py` 的輸出可作為 `risk_hint` 弱標註來源，例如 `IPC_SERVICE_HIJACK`, `IPC_CONFUSED_DEPUTY`。
5. 報告中保留 Detector 的可解釋 evidence，模型只輸出 `risk_probability` 與 feature attribution。

**完成檢查目標**
任何模組都不同時負責「萃取特徵」和「做出模型判斷」；規則結果與 ML 結果可並存；報告能說明兩者差異。

---

## Task 4：Training 與 Inference 資料格式定義 ✅ 已完成

**任務名稱與核心功能**
制定兩套正式資料規範：訓練資料格式與推論格式。

**詳細執行指示**
1. Training format 使用 JSONL 或 Parquet，每筆是一個 row-level 樣本，欄位包含 `sample_id`, `row_type`, `features`, `label`, `label_source`, `split`。
2. `row_type` 固定為 `filter`, `resolution`（v1 訓練集）。`intent_row` 因 v1 manifest-only 階段無獨立訓練價值，不進入訓練；`app_summary` 為 APK 級別摘要，非 row-level 樣本，兩者均不出現在 training / inference data 中。
3. `label` 固定二值：`1=dangerous/overprivilege risk`, `0=normal`；弱標註標記 `label_source="rule_weak_label"`。
4. **label 轉換規則**（由 dataset builder 負責，不放在 Parser）：
   - `filter_row` → `label = 1 if (exported == True and protected == False) else 0`
   - `resolution_row` → `label = 1 if (risk_hint is not None and risk_hint != "<NONE>") else 0`
   - `intent_row` → v1 不產生 label，不進入訓練
5. Inference format 不含 `label/split`，但必須含 `schema_version`, `encoder_version`, `sample_id`, `component_name`, `features`, `row_type`（`component_name` 為 `inference_data_spec.md` v1.1 新增欄位，用於組出 §2 的 `row_id`，詳見該文件 2026-07-18 決策）。
6. 模型輸出格式固定為：`row_id`, `row_type`, `risk_probability`, `predicted_label`, `top_features`, `model_version`。
7. Report 彙整邏輯：row-level 預測彙整為 app-level risk，與 rule findings 合併。

**完成檢查目標**
訓練與推論資料不混用；Inference 可以直接由上傳 APK 生成，不需要 label；Training 可以重現 train/validation/test split；filter_row 與 resolution_row 的 label 轉換規則明確且可驗證。

---

## Task 5：資料蒐集策略決策與 AndroCom 評估

**任務名稱與核心功能**
決定資料來源，以自建 APK-level feature dataset 為主，AndroCom 作為方法論參考與輔助資料。

**詳細執行指示**
1. 採用 AndroCom 的優點：真實世界資料、commit-based labeling、50:50 balance、關鍵字篩選、去重 preprocessing。
2. 不直接採用 AndroCom 作為主資料，因為它以 source-code vulnerability snippet 為主，和本模型的 APK intent/filter/resolution vector 不同。
3. 自行新寫資料蒐集本，目標資料定位是 APK 或可建置 Android 專案，而不是純 code snippet。
4. MVP 資料來源採三選一：公開 APK 樣本、開源 Android 專案自行 build、人工設計 toy APK cases。
5. **資料規模硬性上限：100–150 APK**（4 個月內可完成標記）。
6. 弱標註由現有 Detector 生成；人工抽樣複核高風險與正常樣本；避免模型只學到規則本身。
7. AndroCom repo 可作為後續整合，參考其 keyword、commit metadata、balanced sampling，但不繼承其 dataset schema。

**完成檢查目標**
完成一份資料策略說明，主資料用 APK-level feature dataset，AndroCom 優劣明確，自建資料本標記成本低於模型作業成本，AndroCom 本身特徵與標籤不對齊。

**Toy APK 場景進度**
- [x] Scenario A — OVER_PRIVILEGE ✅ 6 cases, ground_truth.csv updated
- [x] Scenario B — IPC_SERVICE_HIJACK ✅ 6 cases, ground_truth.csv updated
- [x] Scenario C — IPC_CONFUSED_DEPUTY ✅ 6 cases, ground_truth.csv updated
- [x] Scenario D — IPC_BROADCAST_THEFT ✅ 6 cases, ground_truth.csv updated
- [x] Scenario E — IPC_PROVIDER_REDELEGATION / IPC_PROVIDER_URI_GRANT_BYPASS ✅ 6 cases, ground_truth.csv updated

---

## Task 6：模型 MVP 訓練管線

**任務名稱與核心功能**
建立可重現的第一版 ML pipeline，用簡單模型驗證 vector 是否有效。

**模型選型決策**

| row type | 模型 | 理由 |
|----------|------|------|
| `filter_row` | **Random Forest** | multi-hot 稀疏特徵天生友善；`feature_importances_` 直接支援可解釋性報告；小資料不易 overfit |
| `resolution_row` | **Logistic Regression** | action/permission 對稱性為強線性關係；`action_match` 等布林欄位維度低；係數可直接解讀 |
| `intent_row` | **不訓練** | v1 manifest-only 階段 intent 從 filter 1:1 反推，sender 為 `<UNKNOWN>`，match_* 欄位全為 True，無鑑別力；待 bytecode v2 補強後再啟用 |

> **注意**：resolution_row 模型程式碼框架可先實作，但在文件中標注「需 bytecode v2 補強後啟用」。v1 階段只正式訓練 `filter_row` 模型。

**詳細執行指示**
1. 在 `AI-model/app/ml` 下建立 encoder、dataset loader、trainer、predictor。
2. `filter_row` 的 multi-hot 欄位使用 `MultiLabelBinarizer`；類別欄位使用 `OneHotEncoder(handle_unknown="ignore")`；缺值統一轉換 `"<NONE>"`。
3. `resolution_row` 的 `action_match` 欄位為布林值，直接作為特徵輸入，不展開 filter 側 multi-hot。
4. 輸出 `model.joblib`, `encoder.joblib`, `metrics.json`, `feature_schema.json`。
5. 評估指標至少包含 accuracy、precision、recall、F1、confusion matrix；若資料不平衡，以 recall/F1 優化。
6. 訓練資料不足時，允許先用 Detector weak labels 作 baseline，但文件中標明不是終結學術標籤。

**完成檢查目標**
可用一個命令完成 filter_row 資料讀取、訓練、評估與模型輸出；任何一筆 inference feature 可以被 encoder 正確轉換並得到預測；resolution_row trainer 框架存在但有明確的「待 v2 啟用」標記。

---

## Task 7：整合 Inference 至現有分析平台 ✅ 已完成

**任務名稱與核心功能**
讓上傳 APK 的現有 pipeline 可以生成 row-level features、取得模型、輸出 ML findings。

**詳細執行指示**
1. 在 `pipeline_apk.py` 中於 Androguard 萃取後呼叫 model feature builder。
2. 若模型存在，執行 predictor；若不存在，輸出 info finding `MODEL_NOT_AVAILABLE`。
3. 將 ML 結果寫入 artifacts，例如 `{job_id}.ml_features.json` 與 `{job_id}.ml_predictions.json`。
4. Report summary 彙整 rule risk 與 model risk，但保留兩者來源。
5. API response 不破壞現有 `/v1/samples/{sample_id}/result` 格式，只在 artifacts/findings 裡補充新欄位。

**完成檢查目標**
沒有模型時平台仍可獲得基本靜態分析；有模型時額外輸出 ML prediction 與對應 evidence；前端與 PDF 報告不因新欄位失敗。

---

## Task 8：驗證、測試與研究交付

**任務名稱與核心功能**
建立技術驗證與研究報告素材，讓下一階段能對齊審查者與對照模型作業。

**詳細執行指示**
1. 補完單元測試：vector schema、feature builder、encoder unknown category、missing permission。
2. 補完整合測試：APK pipeline 生成 features、模型存在/不存在兩種情境。
3. 建立小型 golden dataset，**覆蓋全部 5 種場景**：
   - 正常（normal）
   - 過度越權（overprivilege）
   - exported unprotected service
   - provider leak
   - receiver broadcast theft
   - 每種至少 5 個可重現的測試案例
4. 產出一份實驗紀錄：資料來源、標註方式、模型版本、metrics、已知限制。
5. 報告中明確寫出：本專案是單一 App 越權風險模型，不宣稱完整偵測跨 App n-order chain。
6. 報告中標注 resolution_row 模型的 v2 依賴：bytecode 補強後方可啟用，v1 實驗結果僅代表 filter_row 模型效能。
7. 報告已知限制段落須涵蓋 `IPC_CONFUSED_DEPUTY` 對真實世界 App 的語意落差（2026-07-18 決定採路線 B，詳見 `NOTES_realworld_exported_semantics.md`）：現行規則不區分「純 launcher／第三方 SDK／平台機制強制／真正自訂進入點」四種 exported 元件性質，人工抽查 7 筆真實世界樣本中 4 筆因此誤判；須引用四類元件表與案例分析，不能只用一句話帶過。

**完成檢查目標**
測試可重現；模型結果可解釋；對題報告能清楚說明第一階段到第四階段的技術連接與研究目標。

---

## 各 Task 風險速查

| Task | 預估工期 | 風險等級 | 主要風險點 |
|------|---------|---------|-----------|
| T1 Vector Spec | 3–4 天 | 低 | 無 ✅ 已完成 |
| T2 Parser 重構 | 1–1.5 週 | 中 | filter_row multi-hot edge cases ✅ 已完成 |
| T3 分工重定義 | 3–4 天 | 低 | 主要是 rename + 職責切割 ✅ 已完成 |
| T4 資料格式 | 3 天 | 低 | label 轉換規則需與 dataset builder 對齊 ✅ 已完成|
| T5 資料蒐集 | 2–3 週 | **高** | APK 取得 + 標記耗時，需遵守 150 上限 |
| T6 MVP ML | 1.5–2 週 | 中 | v1 只訓練 filter_row；resolution_row 待 bytecode v2 |
| T7 Inference 整合 | 1 週 | 低 | 現有 pipeline API 相容性 ✅ 已完成 |
| T8 驗證交付 | 1.5 週 | 中 | golden dataset 5 種場景需人工設計 |
