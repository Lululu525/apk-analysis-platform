# 安卓 App 越權分析模型開發計畫 — Phase 2（Task 9–13）

## 背景與時程修正

`PLAN.md` 規劃的 Month 1–4（Task 1–8）已於 2026-07-23 前全數標記完成，但 `docs/codex意見.md`
（2026-07-23 對照企劃書與評審意見所做的驗收）指出：目前只達到「工程 MVP／流程驗證」，
尚未達到企劃書主張的研究核心——越權辨識能力本身還沒有被有效證明。三個最關鍵的缺口：

1. **標籤洩漏**：`filter_row` 的 label 直接由 `exported`/`protected` 算出，而這兩個欄位同時是
   encoder 的輸入特徵，模型只是在複誦標籤公式本身。
2. **真實世界資料標籤失真**：38 筆真實 APK 中 18 筆 MalDroid 官方 benign 樣本全數被弱規則標成
   `label=1`；人工抽查 7 筆，2 筆正確、4 筆誤判、1 筆部分正確（詳見
   `docs/NOTES_realworld_exported_semantics.md`）。
3. **Intent/攻擊路徑仍是反推資料**：`intent_row` 由 `filter_row` 1:1 反推，sender 恆為
   `<UNKNOWN>`，`resolution_row` 狀態為 `pending_v2`，企劃書主張的「意圖／攻擊路徑建構」尚未有
   真實資料支撐。

`PLAN.md` 原本依 NSTC 計畫書排到 116 年 2 月底（8 個月），但實際硬性截止是
**專題競賽（約 2026 年 12 月底）**，可運用時間是 **2026-07-23 至 2026-11-30，約 18 週**，12 月
整月留給競賽準備，不再排開發工作。本文件（Task 9–13）就是這 18 週的計畫，銜接
`PLAN.md` 既有的 Task 1–8 編號。

**範圍聲明**：Web UI／HTTP API／背景佇列／PDF 報告產生器不屬於本文件負責範圍，`codex意見.md`
表格中列為「未達成」的這一項不在 Task 9–13 之內，不影響以下排程。

---

## 核心決策（延續 PLAN.md，新增兩項）

沿用 `PLAN.md` 的「核心架構決策」表，新增：

| 決策 | 說明 |
|------|------|
| Label 不可與模型輸入特徵同源 | 任何進入 encoder 的欄位不得同時是該筆樣本 label 的直接計算依據；`exported`/`protected` 需保留為特徵，但 label 必須改用獨立訊號 |
| 真實世界資料標籤先過語意分類再入訓練集 | 弱規則標註前，先依 `NOTES_realworld_exported_semantics.md` 的四類 exported 元件分類（純 launcher／第三方 SDK／平台強制／真正自訂）做路線 A 簡化版過濾，未過濾的規則輸出不可直接當 ground truth |

---

## 5 個階段里程碑

| 階段 | 期間 | 目標 |
|------|------|------|
| **P0ａ（Task 9）** | 07/28–08/17（3 週） | 消除結構性標籤洩漏：重新定義 label 來源、`is_used` 接上真實敏感 API 掃描、建立 permission→API 對應 |
| **P0ｂ（Task 10）** | 08/18–08/31（2 週） | 修正真實世界資料標籤：路線 A 簡化版規則、重跑 38 筆標籤、重訓 `filter_row` |
| **P1（Task 11）** | 09/01–09/28（4 週） | 外部測試集 + Rule/ML/Hybrid 三方比較，融合成真正的混合 `risk_score` |
| **P2（Task 12）** | 09/29–10/26（4 週） | Bytecode v2 最小可行版，換取真實 sender，讓 `resolution_row` 有第一批可訓練資料 |
| **緩衝週** | 10/27–11/02（1 週） | Task 12 風險最高，預留 1 週消化延遲，未用完可提前進入 Task 13 |
| **P4（Task 13）** | 11/03–11/23（3 週） | 重寫研究報告／實驗紀錄，附三方法比較表與誠實揭露段落 |
| **最終緩衝** | 11/24–11/30（1 週） | 簡報／口試演練，處理臨時問題 |
| （競賽準備） | 12 月 | 不排新開發工作，僅競賽相關準備 |

---

## Task 9：消除結構性標籤洩漏

**任務名稱與核心功能**
重新定義 `filter_row` 的 label 來源，讓 label 不再與模型輸入特徵同源；把既有的敏感 API 掃描
（KAN-39 原型）接成真正的 `is_used`，作為獨立於 `exported`/`protected` 的判斷訊號。

**詳細執行指示**
1. 停用 `build_training_data.py:61` 目前的 `label = 1 if exported and not protected else 0` 直接公式；
   label 改為至少納入一項不屬於 encoder 輸入特徵的獨立訊號（例如：元件是否持有可被外部觸發的
   危險權限路徑、或人工 ground truth）。
2. 把 30 個 toy APK 的人工標記（`ground_truth_with_split.csv` 的 `label` 欄）真正接入訓練資料，
   不再被 dataset builder 用 `rule_weak_label` 整批覆蓋；人工標記樣本的 `label_source` 需與
   `rule_weak_label` 樣本區分，訓練/評估時可分別報告兩種來源的表現。
3. 將 KAN-39 敏感 API 掃描原型整合進 `androguard_analyzer.py`，把 `is_used` 從恆為 `True`
   改為由實際 API XREF／字串 fallback 掃描結果決定。
4. 建立「permission → 對應敏感 API 群組 → 是否被實際呼叫」的對應表，作為新特徵或新規則輸入，
   不進入 label 計算公式。
5. 補測試：確認新 label 來源下，`exported`/`protected` 兩欄位單獨不能 100% 預測 label
   （用簡單基準模型跑一次「只用 exported+protected 兩欄」應該明顯低於 1.0 F1，作為洩漏已排除的
   驗收證據）。

**完成檢查目標**
`filter_row` 訓練資料的 label 計算邏輯與 encoder 輸入特徵無直接同源關係；30 個 toy APK 的人工
標記可被追蹤為獨立 `label_source`；`is_used` 反映真實 API 使用狀況而非恆為 True；有一份「僅用
exported+protected 預測 label」的對照實驗證明洩漏已消除。

---

## Task 10：修正真實世界資料標籤（路線 A 簡化版）

**任務名稱與核心功能**
依 `docs/NOTES_realworld_exported_semantics.md` 記錄的四類 exported 元件語意，實作路線 A
簡化版規則調整，重新標註 38 筆真實世界資料，解決 benign 樣本 label=1 比例異常偏高的問題。

**詳細執行指示**
1. 在 `privilege_rules.py` 的 `IPC_CONFUSED_DEPUTY`／`EXPORTED_UNPROTECTED_*` 觸發條件中，
   至少排除第①類（純 `MAIN`/`LAUNCHER`，intent-filter 不帶可控資料欄位）與第③類
   （已知平台機制強制 exported 清單，例如 `APPWIDGET_CONFIGURE`/`_UPDATE`、
   `MediaRouteProviderService`）。第②類（第三方 SDK）視時間許可，用常見 SDK 的
   package/class 前綴（`com.google.android.gms.*`/`com.facebook.*`/`com.unity3d.*` 等）做粗略排除，
   完整度不要求 100%。
2. 補 toy APK 測試案例：純 launcher + 持有危險權限的組合，驗證修改後不再誤觸發。
3. 重跑 38 筆真實世界資料的規則標註，記錄 18 個 MalDroid benign 樣本中 `label=1` 比例的變化
   （目標：顯著低於 100%，非硬性數字要求，但需在報告中呈現前後對照）。
4. 用修正後的真實世界標籤 + Task 9 的新 label schema，重新訓練 `filter_row` 模型，比較
   新舊 metrics（含 confusion matrix），任何仍為 100% 的指標需能解釋原因。
5. 依 `NOTES_realworld_exported_semantics.md` 第 7 案例（`com.reneph.passwordsafe`）等既有分析
   案例回歸驗證：規則修正後這幾筆應不再觸發。

**完成檢查目標**
7 筆既有人工抽查案例中，原本判定為誤判的案例（案例 2、3、6、7）在規則修正後不再觸發；
判定正確的案例（案例 1、5）維持觸發；重訓後的 `filter_row` metrics 附有新舊對照與 confusion
matrix，不再單純依賴洩漏公式取得高分。

---

## Task 11：外部驗證與 Rule／ML／Hybrid 比較

**任務名稱與核心功能**
建立一份訓練與規則調校過程中完全未使用過的外部測試集，量化比較「純規則 baseline」「純 ML」
「規則+ML 混合」三種方法的表現，並把 ML 機率真正融合進主要 `risk_score`，而非報告中兩段並列。

**詳細執行指示**
1. 切出一份外部測試集：可用新蒐集的 APK（不早於 Task 9/10 資料凍結時間點），或從既有
   150 上限額度中預留一批全程不參與 Task 9/10 任何調校的樣本。
2. 對外部測試集分別跑：（a）僅用 `privilege_rules.py` 的規則判斷、（b）僅用 `filter_row` ML
   模型、（c）規則+ML 混合分數；三者的 Precision/Recall/F1/Confusion Matrix 需並列呈現。
3. 修改 `pipeline_apk.py`，把 ML `risk_probability` 實際併入主要 `risk_score` 的計算（例如加權
   融合或以規則結果做先驗調整），而不是先算完規則風險摘要才在報告尾端附加
   `ML_RISK_ASSESSMENT`。
4. 建立誤判案例分析：外部測試集中 hybrid 方法的 false positive／false negative 各挑數筆，附
   evidence 與可能原因，作為可解釋性素材。
5. 若 hybrid 未能明顯優於單一方法，如實記錄並分析原因，不得選擇性只呈現對己方有利的指標。

**完成檢查目標**
有一份外部測試集的三方法比較報告（含數字與誤判案例）；`pipeline_apk.py` 輸出的主要
`risk_score` 實質包含 ML 貢獻，可用程式碼位置佐證；誤判分析至少涵蓋 hybrid 方法的
false positive 與 false negative 各一組案例。

---

## Task 12：Bytecode v2 最小可行版（Intent Sender 還原）

**任務名稱與核心功能**
不做完整 bytecode v2，只掃描固定的一組高頻 IPC 觸發 API pattern，換取部分真實 `intent_row`
sender 資訊，讓 `resolution_row` 第一次有非 `<UNKNOWN>` 的訓練樣本可用。

**詳細執行指示**
1. 鎖定掃描範圍：`startActivity`/`startActivityForResult`/`startService`/`bindService`/
   `sendBroadcast`/`sendOrderedBroadcast`/`ContentResolver.query`/`insert`/`update`/`delete`
   這幾類固定 API 呼叫，不做通用 bytecode 資料流分析。
2. 用 Androguard 的 XREF／smali 掃描，從呼叫端方法回推所屬 component（sender），記錄
   sender 實際持有的 permission、呼叫時傳入的 action（若為常數字串可直接解析，動態組字串則
   標記 `source="bytecode_partial"` 並保留原本 `manifest_only` 邏輯作為 fallback）。
3. 用還原出的 sender 資訊重建 `resolution_row`：`intent_*` 欄位改用真實掃描結果，
   `filter_*` 欄位沿用既有 `filter_row`，`match_action`/`match_category`/`match_type` 依真實
   intent 與 filter 比對計算。
4. 依 `PLAN.md` Task 6 原定模型選型，用 Logistic Regression 訓練 `resolution_row` 模型；
   資料量若過小（樣本數個位數／十位數等級），需在報告中明確標注為「初步可行性驗證」，
   不誇大為完整攻擊路徑偵測。
5. 更新 `feature_schema.json`，把 `resolution_row` 狀態從 `pending_v2` 改為實際涵蓋範圍
   （例如「涵蓋 10 類固定 IPC API pattern，其餘仍為 manifest-only fallback」）。

**完成檢查目標**
至少一批（不要求全量）`resolution_row` 樣本的 `intent_*` 來自真實 bytecode 掃描而非
`filter_row` 反推；`resolution_row` 的 Logistic Regression 模型可訓練並輸出 metrics（即使
樣本數小，也要如實報告置信度限制）；`feature_schema.json`／實驗紀錄不再用「v1 全體
manifest-only」一句話帶過，而是清楚寫出真實覆蓋率。

若本階段掃描範圍證實在 4 週內無法產出足量可訓練樣本，退回方案為：如實記錄「已驗證
bytecode sender 還原技術可行，覆蓋率 X%，訓練樣本不足以支撐正式 metrics」，並在 Task 13
報告中將研究主張收斂為「exported/unprotected 元件風險評估 + resolution_row 初步可行性
驗證」，不得沿用舊的 100% 指標做為攻擊路徑偵測證據。

---

## Task 13：研究報告與競賽交付

**任務名稱與核心功能**
把 Task 9–12 的修正成果整理成可對外（指導教授、口試委員、競賽評審）交付的研究報告，
取代目前基於洩漏標籤產出的舊版實驗紀錄。

**詳細執行指示**
1. 重寫 `docs/實驗紀錄 v1.pdf` 對應內容為新版：資料來源、新版標註方式（含 Task 10 的
   四類 exported 元件分類）、模型版本、Task 11 的三方法比較表、Task 12 的 resolution_row
   可行性驗證結果。
2. 已知限制段落須完整涵蓋：`IPC_CONFUSED_DEPUTY` 對真實世界 App 的語意落差（四類元件表
   與代表案例，不能只用一句話帶過，沿用 `NOTES_realworld_exported_semantics.md` 既有分析）、
   `resolution_row` 實際覆蓋率與樣本規模限制、單一 App 越權風險模型不宣稱偵測跨 App
   n-order chain。
3. 明確寫出研究題目與實際交付範圍的對應關係：企劃書主張「權限是否超出實際功能需求」與
   「意圖／攻擊路徑建構」，本階段交付到什麼程度、哪些留待未來工作，用一張對照表呈現，
   避免指標與主張範圍不一致。
4. 準備競賽簡報素材：問題定義、方法（規則+ML 混合）、Task 11 的量化比較結果、代表性
   誤判案例、未來工作。
5. 預留至少 2 次口頭演練，模擬評審提問（特別是「你們宣稱的越權辨識準確率是多少、怎麼
   驗證的」這類問題，需能直接引用 Task 11 的外部測試集數字回答，不能只回「訓練集 F1
   很高」）。

**完成檢查目標**
新版研究報告的每一個量化指標都能追溯到 Task 11 的外部測試集，而非訓練集自我驗證；
已知限制段落具體、有案例佐證；簡報素材與口頭問答準備完成，可直接用於 12 月競賽。

---

## 各 Task 風險速查

| Task | 期間 | 風險等級 | 主要風險點 |
|------|------|---------|-----------|
| T9 消除標籤洩漏 | 3 週 | 中 | 找不到足夠獨立訊號取代洩漏公式，可能需退回「以人工標記為主、規則為輔」的較小規模訓練集 |
| T10 真實資料標籤修正 | 2 週 | 中 | 第②類第三方 SDK 排除清單無法窮舉，可能只解決部分誤判 |
| T11 外部驗證與融合 | 4 週 | 中 | 外部測試集規模若太小，統計結果說服力不足；需視 T5 的 150 APK 上限彈性調整資料切分 |
| T12 Bytecode v2 最小版 | 4 週 | **高** | 全案風險最高：smali 掃描涵蓋率、動態組字串 action 無法解析、時間可能不夠，已內建退回方案 |
| T13 報告與交付 | 3 週 | 低 | 主要是整理與寫作工作，前置 Task 若延遲會直接壓縮此階段時間 |

---

## 與 PLAN.md 的銜接說明

- Task 1–8：延續 `PLAN.md`，狀態不變（皆已完成）。
- Task 9–13：本文件新增，接續既有編號，對應 `PLAN.md` 未展開的 Month 5–8。
- `PLAN.md` 的「核心架構決策」與「各 Task 風險速查」格式沿用於本文件，保持兩份文件可
  對照閱讀。
- Web UI／API／背景佇列／PDF 報告不在本文件範圍內，如需規劃請另立文件。
