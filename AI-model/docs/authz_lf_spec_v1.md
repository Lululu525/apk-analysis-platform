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
| 1 | `caller_method` 不在該 `component_type` 的 entry method 集合內 | **negative** | `weak_negative_no_entry_to_sink_evidence` |
| 2 | sink 需要平台 permission，但該 APK 的 `uses-permission` 沒有宣告 | **negative** | `weak_negative_sink_permission_undeclared` |
| 3 | `caller_class` 對不上任何 Manifest component（`linkage_status = unlinked_caller`） | **abstain** | `abstain_caller_class_not_component` |
| 4 | 其餘 | **positive** | `weak_positive_sink_in_entry_method` |

**規則 1 與 2 是 weak-negative 啟發式，不是 I 或 S 的 refutation。** reason code 刻意以
`weak_` 開頭，以免被讀成 predicate 判定。規則 1 的實質是「沒有找到 entry 到 sink 的證據」，
誤記為 I refuted 的問題與量測到的代價見 §6.2。

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

### 6.1 凍結後的量測結果（2026-09-28）

LF 於 `a7a8327` 凍結，之後才執行 `--noise-rate`。**標籤未因本節的任何數字而改動**，
只更動 reason code 的命名與本文件的描述（見下）。產物：
`dataset/authz_v2/experiments/lf_noise_rate.json`。

**外部可達子集**（規則判為可達，與 `bottleneck_analysis` 的母體一致，是模型負責的那一層）：

```
102 筆比對（另 4 筆 LF abstain）
TP 14   FP 3   FN 65   TN 20

positive precision  0.824
positive recall     0.177
macro F1            0.331
噪音率              66.7%
```

放進第九章的判讀框架：

| | macro F1 |
|---|--:|
| 全判 negative | 0.184 |
| **本 LF** | **0.331** |
| 全判 positive | 0.436 |
| 跨 APK 多數決 | 0.519 |
| 作弊上限 | 0.695 |

**LF 比「全部猜 positive」還差。** 精確率高（說是 positive 時八成對），但召回率只有 0.177，
漏掉 79 筆真 positive 中的 65 筆。

Gold 全部二分類那一層的數字（344 筆、macro F1 0.432、噪音率 43.6%）**不可用於評價本 LF**：
它被 R 已否定的 unit 主導——那些 unit Gold 判 negative 是因為 R，LF 判 negative 是因為
entry method，兩者偶然一致；而其中 85 筆 LF 判 positive 的 FP 在實際流程中會先被 R gate
攔下，不會進到模型。此處僅列出以說明「43.6%」這個較好看的數字為何不適用。

### 6.2 漏判的成因：一個歸因錯誤

LF 的 positive 要求 sink **寫在** entry method 裡。Gold 的 positive 有大量是這種形狀：

```
onCreate()  →  helper()  →  sendTextMessage()
```

Reviewer 讀了程式碼看得到這條內部呼叫鏈，判 positive。LF 看不到呼叫鏈，判 negative。

**但這筆帳記錯了。** 外部呼叫者確實觸發了 `onCreate()`，I 是成立的；不明的是
`onCreate()` 到不到得了 `helper()`，那是 S 的 linkage，而且我們沒有分析。
這正是 ADR-0002 2026-09-22 修訂警告過的事：

> 同一個事實（外部 entry 到不了 sink）曾被不同 unit 分別記為 I 或 S refuted……
> 因此 I 與 S 的個別次數反映的是審查順序與歸因習慣

本 LF 犯了同一個歸因錯誤。這一點僅憑定義與 ADR 即可看出，不需要 Gold——
**但據實記載：實際上是在看到 §6.1 的 Gold 比對之後才發現的。**

### 6.3 照定義修正會使訓練資料消失

若把「sink 不在 entry method 裡」改判 abstain（因為那是未分析，不是否定）：

```
positive 387、negative 8、abstain 1,290
```

**negative 只剩 8 筆**，二分類訓練集 395 筆中 98% 為 positive，無法訓練二分類器。

因此本 LF 的標籤維持凍結原樣，理由有兩層：改標籤是拿 Gold 回頭調 LF，違反 §10；
而且照定義修正的版本在工程上無路可走。

### 6.4 由此得到的研究發現

這比原本的主張更尖銳，且已量化：

> 現有的自動化證據可以產生**高精確率的 positive** 弱標籤（precision 0.824），
> 但**幾乎無法產生 negative 的 I／S 標籤**。原本唯一大量的 negative 來源
> （1,022 筆）建立在把「未分析」記成「已否定」的歸因錯誤上。

第九章的結論是「模型分不出來」；本節的結論是「弱標註連訓練訊號都生不出來」。
兩者指向同一個瓶頸——缺少 entry-to-sink linkage——但本節是在標籤生成端量到的。

### 6.5 對 5c 的意義

M2 要在噪音率 66.7% 且噪音**高度結構化**（幾乎全部集中在 positive 的系統性漏判）
的標籤上訓練，因此預期 M2 表現很差。SLB 能否修正，取決於那 65 筆漏判在 31 維 feature 上
是否可分辨——而第九章已經量出那大致不可分辨（跨 APK 0.519、23 筆只抓到 5 筆）。

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
