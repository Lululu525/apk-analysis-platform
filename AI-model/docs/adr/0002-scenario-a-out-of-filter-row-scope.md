---
status: accepted
---

# Toy APK Scenario A（宣告不符型越權）排除於 filter_row／Task 9 範圍外

**Context**：Task 9 item 2 原計畫把 30 個 toy APK 的人工標記（`dataset/labels/ground_truth_with_split.csv`）當作 `filter_row` 的獨立 ground truth 接入訓練。檢視 `toy_apk_scenario_design.md` 後發現，Scenario A（case0–5）的人工 label 差異其實來自 `privilege_rules.py` 的 `COMBO_RULES`（App 整體宣告的危險權限組合是否超過閾值），跟任何元件的 exported/protected 狀態無關——A-0 到 A-4 的 `MainActivity` 曝露狀態完全相同（皆 exported、無保護），label 卻不同（A-0=0，A-1~A-4=1），證明判斷依據不是元件層級訊號，而是 App 層級的權限宣告組合。這跟 `filter_row` 逐元件的 schema 是不同粒度，無法直接對應同一個 label 欄位。

**Decision**：Scenario A 的 6 個案例，明確排除在 Task 9 的 `filter_row` label 修正範圍外，維持交由 `privilege_rules.py` 的 `COMBO_RULES` 處理（現況已可運作，不需要 ML）。Task 9 item 2 只把 Scenario B/C/D/E 共 24 個案例接入 `filter_row` 訓練資料；其中 B-3、D-5、E-4 三個「同一 APK 內一個元件有保護、一個沒有」的混合案例，需要把原本一整支 APK 一個 label 的 CSV 紀錄拆成逐元件的獨立 label 才能使用，其餘 21 個案例可直接沿用整支 APK 的 label（同一 APK 內所有相關元件曝露狀態一致，套用不會出錯）。

**Why**：企劃書「意圖／攻擊路徑建構」的主張結構上需要元件層級的入口點資訊——一條攻擊路徑一定要有具體的入口元件，App 層級的聚合值答不出「攻擊者從哪個元件進來」。`filter_row`/`intent_row`/`resolution_row` 的 schema（`PLAN.md` Task 6 既有設計，已完成）本來就是逐元件的，勉強把 Scenario A 塞進去只會製造新的粒度混淆，重蹈目前 Task 9 要解決的標籤洩漏問題的覆轍。Scenario A 測的「宣告不符型越權」是真實且獨立的研究支線，已經有 `COMBO_RULES` 在處理，維持現狀即可，不需要改動。

## Considered Options

- **把 Scenario A 的 App 級 label 硬套用到 `MainActivity` 的 `filter_row` 上**——會讓曝露狀態完全相同的元件（A-0 的 `MainActivity` vs A-1 的 `MainActivity`）得到不同 label，直接製造新的標籤矛盾/洩漏，否決。
- **重新設計 Scenario A 的 toy APK，讓它產生元件層級可用的訊號**——時間成本高，且偏離 Scenario A 原本要測「宣告不符」問題本質的設計初衷，否決。
