# 只看 I／S 的 Labeling Function 規格 v1

狀態：**草案，待 commit 凍結**。實作於 `app/tools/build_observed_labels.py`。
執行順序第 5b 項（ADR-0002）。

產出 `observed_authz_label`，即 M2／M3 的訓練標籤。依 ADR-0001，此標籤與
`gold_authz_label`、`revised_authz_label` 語意不同、provenance 分開，不得互相覆寫。

## 1. 範圍：只判 I 和 S

R 由 `app/tools/r_gate.py` 的確定性規則在流程最前面處理，**`exported` 不參與本 LF**。
A 沒有任何自動化證據（每筆 unit 的 `coverage_limitations` 都含
`runtime_guard_not_analyzed`），本 LF 不判 A。

原先負責 Manifest exposure 的那條 LF 已依 ADR-0002 移除。因此 `exported` 既不在 feature，
也不在訓練標籤——模型從頭到尾碰不到它。

## 2. 判定順序與規則

順序依 `authz_annotation_guide.md`：**I → S**，negative 在第一個決定性否定即停止
（`authz_label_spec.md` §247-248）。

| 順序 | 條件 | 判定 | reason code |
|--:|---|---|---|
| 1 | `caller_method` 不在該 `component_type` 的 entry method 集合內 | **negative** | `i_refuted_not_entry_method` |
| 2 | sink 需要平台 permission，但該 APK 的 `uses-permission` 沒有宣告 | **negative** | `s_refuted_sink_permission_undeclared` |
| 3 | `caller_class` 對不上任何 Manifest component（`linkage_status = unlinked_caller`） | **abstain** | `s_unknown_caller_class_not_component` |
| 4 | 其餘 | **positive** | `positive_i_trigger_and_s_linkage` |

### 規則 1（I）

依 2026-09-19 經人工 reviewer 核准、並已寫入 `authz_annotation_guide.md` Step 2 的觸發慣例：
**外部呼叫者的觸發動作本身即構成 I 的控制流影響**，不要求攻擊者資料流進 sink 參數。

因此 I 的判準是「外部呼叫者能不能使這個 method 執行」。若 sink 所在的 method 不是外部可
觸發的 entry method，要到達 sink 需要一條我們沒有分析的 app 內部呼叫鏈，I 不成立。

### 規則 2（S 的弱反證）

呼叫了需要平台 permission 的 sink，但該 APK 從未宣告該 permission，則該呼叫在 runtime
很可能失敗，敏感效果到不了。對應表與 `authz_feature_spec_v1.md` §5 共用同一份
`SINK_PERMISSIONS`，不另立一套。

**這是本 LF 中唯一模型看得見的規則**（`sink_permission_applicable`、
`sink_permission_declared` 是 31 維 feature 的其中兩維）。在本順序下它只觸發 11 次——
那些 sink 多數本來就不在 entry method 裡，規則 1 已先否定。

### 規則 3（S unknown，abstain）

`linkage_status = unlinked_caller` 表示 sink 所在的 class 對不上任何 Manifest 宣告的
component，我們不確定這段程式碼是否屬於這個 component。這是 **S 的證據不足，不是 S 被否定**。

依 ADR-0001「unknown 不得強迫轉成 positive／negative」，這批 unit 的
`observed_authz_label` 寫 `null`、**不進訓練**。它們保留在輸出檔中，並在報告中交代去向與
模型對它們的預測（見 §5）。

## 3. Entry method 集合

| component_type | entry methods |
|---|---|
| activity | `onCreate`、`onNewIntent`、`onStart`、`onResume` |
| service | `onStartCommand`、`onBind`、`onStart`、`onHandleIntent` |
| receiver | `onReceive` |
| provider | `query`、`insert`、`update`、`delete`、`openFile`、`call`、`getType` |

### 3.1 刻意與 `canonical_dataset_pilot.ENTRY_METHODS` 分歧

既有的 `ENTRY_METHODS`（`canonical_dataset_pilot.py:70`）較窄：activity 只有
`onCreate`、`onNewIntent`，service 只有 `onStartCommand`、`onBind`，provider 沒有 `getType`。
該集合是為了計算 `matched_lifecycle_entry_method` 與 `linkage_status` 而設計，用途是
**保守的 direct identity match**，刻意從嚴。

本 LF 問的是不同的問題：外部呼叫者能不能使這個 method 執行。依 Android lifecycle：

- `Activity.onStart`、`onResume`：外部 `startActivity()` 會使
  `onCreate → onStart → onResume` 依序執行。
- `Service.onStart`：舊版 `startService()` 的入口，並收到 Intent。
- `IntentService.onHandleIntent`：直接收到攻擊者送來的 Intent 作為參數。
- `ContentProvider.getType`：外部可直接呼叫。

四者外部都觸發得到，判成 I refuted 與觸發慣例矛盾。

不納入 `onActivityResult`（子 Activity 回傳的 callback，本專題威脅模型下外部呼叫者無法
直接觸發）與 `onRestart`。

分歧的實際影響為 196 筆（`Activity.onStart` 105、`Service.onStart` 53、
`Activity.onResume` 31、`Service.onHandleIntent` 7）：100 筆由 negative 改為 positive、
96 筆由 negative 改為 abstain。

## 4. 不循環也不空洞：可量測的約束

LF 的輸入若全部是 feature，模型會重建 LF，M2／M3 的一切指標失去診斷力；若全部不是
feature，模型學不起來，實驗變成空的。以「用 31 維 feature 重建 LF 輸出的作弊上限」量測：

```
接近 1.0   → 循環論證
接近多數類基準 → 學不到
中間        → 有意義
```

本 LF 的三個訊號中，兩個主力（entry method、`linkage_status`）依 §8.2／§8.3 都**不在
feature 內**，模型看不到；只有 sink-permission 那條可見，且只觸發 11 次。

實測（只用訓練池，未觸及 Gold）：

| | 值 |
|---|--:|
| 二分類可用 | 1,417 筆 |
| positive 佔二分類 | 27.3% |
| 用 31 維重建 LF 的作弊上限 | **0.852** |
| 多數類基準 | 0.727 |

約 15% 的 LF 判定是模型原理上看不到的。

## 5. abstain 的處理（做法一）

- `observed_authz_label` 寫 `null`，訓練時跳過，訓練集為 1,417 筆。
- unit 保留在 `observed_labels_training.jsonl` 中並帶 reason code。
- 訓練後印出模型對這 268 筆的預測，作為**研究發現**（證據不足的那批，模型傾向怎麼判），
  不是訓練訊號。SLB 階段亦可觀察它是否試圖把它們拉向某一邊。

不採 3 分類訓練的理由：`unknown` 是「我們的證據」的性質而非 App 的性質，其成因
（class 歸屬未解）正是 §8.2 把 `linkage_status` 排除在 feature 之外的理由；Gold 的
unknown 主要來自 R 語意未解與 A 未分析，與本 LF 的 unknown 不是同一個變數，無法對照驗證；
第九章的三條參考線（0.439／0.519／0.695）都是二分類 macro F1，3 分類不可比；
且 SLB 的 pseudo-label 會把 noisy 樣本改標成 unknown，那是棄答而非修正，
內部指標會變好看卻什麼都沒修。

`unknown` 的語意在**報告層**與 **Gold** 上成立，在訓練標籤上不成立。

## 6. 程序：先凍結，才能碰 Gold

沿用 sink 先驗權重（`e40bb10`）的做法。§4 的全部數字只用訓練池。

1. 依 R/I/S/A 語意設計 LF ✅
2. 量重建上限（只用訓練池）✅ 0.852
3. **commit 凍結本 LF 與實作**
4. 才以同一個 LF 跑 Gold，量 LF 與 Gold 的一致率作為**噪音率**報告

噪音率是 SLB 要處理的對象，因此必須先凍結再測，不得反過來依 Gold 調整 LF
（`authz_label_spec.md` §10、時程表 `:453`）。

### 預先說明的預期

LF 與模型能取得的程式碼層級證據是同一批。第九章已量出這批證據的天花板為
macro F1 0.695、跨 APK 0.519。因此 **LF 會錯的地方，大致就是模型也無從分辨的地方**——
SLB 被要求修的噪音有相當比例在現有特徵下原理上修不掉。這與 ADR-0002
「M2 ≈ M3 是可接受且有意義的結果」一致，於此先行載明，不留待跑完再解釋。

## 7. 已知限制

- LF 由兩個訊號主導，其中 `i_refuted_not_entry_method` 一條即佔全部 negative 的絕大多數。
  「SLB 修 LF 噪音」實際上主要是「SLB 修 entry-method 判準的錯誤」。
- `linkage_status` 依 §8.2 描述的是工具的分析涵蓋程度而非 App 性質，因此本 LF 的標籤
  部分編碼了工具覆蓋率。這會提高噪音，屬預期，並非缺陷——噪音正是 SLB 的研究對象。
- 沒有任何 A 的證據，本 LF 不判 A。
- entry method 集合是平台語意的先驗判斷，未經 Gold 驗證（依規定也不得以 Gold 驗證後回頭調整）。

## 8. 重跑指令

```bash
python -m app.tools.build_observed_labels              # 產生訓練標籤
python -m app.tools.build_observed_labels --dry-run    # 只印統計
python -m app.tools.build_observed_labels --noise-rate  # 凍結後才可執行：對 Gold 量噪音率
python -m pytest tests/test_build_observed_labels.py
```
