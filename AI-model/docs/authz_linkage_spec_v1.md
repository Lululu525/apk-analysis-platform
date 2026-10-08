# Entry-to-sink linkage 規格 v1

狀態：**規則凍結（§0–§6），已執行，結果見 §7**（2026-10-06）。執行順序新增第 6 項。
實作於 `app/tools/entry_sink_linkage.py`。

一句話的結果：外部可達子集上，**排除設計時看過的 APK 後 macro F1 0.797**（母體 67 筆、
19 個 APK），對照可達性規則 0.439、跨 APK 多數決 0.519、M2 0.400、M3 0.207。
LF 系統性漏判的 65 筆接起來 56 筆，代價是 23 筆 Gold negative 的真陰性由 20 降到 16。
**但先讀 §0：這份規格的發現順序與本專題其他每一份相反。**

本文件定義一個最小的 entry-to-sink 可達性分析，用來回答一個到目前為止答不出來的問題：
**補上程式層級的呼叫鏈證據，外部可達子集上的判別力會變成什麼樣子？**

## 0. 先揭露：這份規則的發現順序是反的

**本專題其他每一份規格都是「先凍結規則、再量 Gold」。本文件不是。**
必須講在最前面，而不是埋在最後一節。

實際的順序是：2026-10-05 在盤點既有證據有沒有可用的呼叫邊時，在 13 個 APK 上試跑了三個
版本的規則（只用靜態邊 → 加回呼邊 → 加 `<init>` 規則），**每一次都看了它恢復了幾筆
Gold positive**，才得到 §2 的三條規則。這是本專題一直在防的那件事。

三項緩解，逐條說明其限度：

1. **三條規則都可以由 Android 平台語意獨立辯護，不需要引用任何 Gold 數字。**
   §2.3 逐條給出辯護。但這不改變「它們是在看了 Gold 之後才被想到」這個事實。
2. **判別力來自沒看過的 APK。** 設計時看過的 2 顆 APK（`9b2a8728`、`9ed8ab7e`）
   **貢獻 0 筆 Gold negative**，而 negative 那一側是全部判別困難的所在。
   因此 §4 要求同時報告「全部 106 筆」與「排除那 2 顆 APK 的 67 筆」兩個數字。
3. **本文件之後規則不再改動。** 這是可驗證的：規則寫在本文件與程式裡，
   先 commit，之後的執行只能產生數字。

**報告中不得把這份規格描述成「先凍結再量」。** 正確的描述是：
「這條規則的設計過程接觸了 Gold 的 positive 側；凍結發生在設計之後、正式量測之前；
判別力所依賴的 negative 側未被接觸，且提供了排除法的對照數字。」

前例：`authz_lf_spec_v1.md` §6.2 同樣記載了「實際上是在看到 Gold 比對之後才發現的」。
這裡沿用同一個做法，但問題比那次嚴重——那次發現的是一個歸因錯誤，這次決定的是規則本身。

## 1. 這個分析要回答什麼，不回答什麼

`authz_lf_spec_v1.md` §6.2 已經指出 LF 漏判的成因：LF 的 positive 要求 sink **寫在**
entry method 裡，而 Gold 的 positive 大量是這種形狀：

```java
public class SMSReceiver extends BroadcastReceiver {
    public void onReceive(Context c, Intent i) {    // 外部可觸發
        new Thread(new Runnable() {
            public void run() { getSDPath(); }      // 經過這裡
        }).start();
    }
    private String getSDPath() {
        Environment.getExternalStorageDirectory();  // sink 在這裡
    }
}
```

LF 看不到 `onReceive → run → getSDPath` 這條鏈，判 negative；reviewer 讀了程式碼，判 positive。

**本分析只回答一個問題**：從該 component 的 entry method 出發，沿著呼叫關係，
到不到得了 sink 所在的 method。

**不回答的**：

- **不做 taint analysis。** 不追攻擊者資料流進 sink 參數。依
  `authz_annotation_guide.md` Step 2 已核准的觸發慣例，外部呼叫者的觸發動作本身即構成
  I 的控制流影響，不要求資料流。
- **不處理反射與動態載入。** `Method.invoke`／`Class.forName` 造成的邊一律看不到。
  這在本專題不是小事：訓練池 1,065 / 1,685 筆的 sink group 是 `CODE_EXEC`。
- **不處理 native code、不處理跨 APK。**
- **不產生 A 的證據。** A 仍然沒有任何自動化證據。

## 2. 三條規則

### 2.1 基礎呼叫邊

以 Androguard 的 `MethodAnalysis.get_xref_to()` 建反向圖：
對每一個 method `m` 與其每一個 callee `c`，加入邊 `c → m`（「`c` 的呼叫者包含 `m`」）。

節點為 `(class_name, method_name)`，**不含 descriptor**。
這是刻意的過度近似：同名多載會被併成一個節點，可能產生不存在的路徑。
理由是 overload 在本問題上幾乎不影響可達性判斷，而帶 descriptor 會讓 `access$N`
之類的編譯器生成方法難以匹配。此項列為已知限制。

### 2.2 兩條補充規則

| # | 規則 | 形式 |
|--:|---|---|
| A | **建構者 → 回呼**：若類別 `C` 有一個方法名在回呼清單內，則**每一個呼叫 `C.<init>` 的方法**都加為該回呼方法的呼叫者 | `C.callback → {呼叫 C.<init> 的所有 method}` |
| B | **`<init>` 視為 entry**：component 類別的 `<init>` 與其 entry method 同等視為外部可達 | entry 集合 ∪ `{<init>}` |

回呼清單（**凍結，不得增減**）：

```
run  doInBackground  onPostExecute  onPreExecute  onProgressUpdate
onClick  onLongClick  onItemClick  handleMessage  call  onReceive
```

entry method 集合直接沿用 `build_observed_labels.ENTRY_METHODS`（已於 `a7a8327` 凍結），
不另行定義，以免兩處分歧：

```
activity  onCreate  onNewIntent  onStart  onResume
service   onStartCommand  onBind  onStart  onHandleIntent
receiver  onReceive
provider  query  insert  update  delete  openFile  call  getType
```

搜尋深度上限 **8**。選 8 的理由：實測需要的最長鏈為 4 跳
（`onCreate → helper → $1.<init> ← 回呼邊 → $1.run → access$N → sink method`），
8 留了一倍餘裕；而上限必須存在，否則大型 APK 的 BFS 會掃過整個呼叫圖。

### 2.3 兩條補充規則的平台語意辯護

**規則 A。** `new Thread(r).start()`、`handler.post(r)`、`new MyTask().execute()`
都把回呼交給框架執行，程式裡**不存在任何一行呼叫 `run()`**。因此靜態呼叫圖在這裡必然斷掉，
這不是 Androguard 的缺陷，是靜態呼叫圖的定義。

「誰建構了這個物件，誰就可能使它的回呼執行」是靜態分析處理框架回呼的標準過度近似。
它**不 sound**（建構了不一定會執行）也**不 complete**（物件可由他處取得後才執行），
會產生不存在的路徑——這正是 §4 必須報告 false positive 的原因。

**規則 B。** Android 框架**一定是先建構 component 實例、才呼叫其生命週期方法**。
因此只要該 component 外部可達，它的 `<init>` 就同樣外部可達。這是平台語意的事實，
不是擬合出來的選擇。實務上這條規則抓的是在欄位初始化中建構的 `Handler`／`Runnable`
（Java 的欄位初始化會被編譯進 `<init>`）。

**兩條規則都只描述控制流可能性，不宣稱必然執行。** 報告用詞應為
「可能被觸發的呼叫鏈」，不得寫成「已證實的執行路徑」。

## 3. 這個分析**不**進 feature，也不重訓模型

明文寫下來，以免被誤解為「那就把它加進模型再跑一次」：

1. **31 維 feature 是 configuration lock**（`authz_feature_spec_v1.md` §4），
   加一維就破壞了 lock，而且會使已完成的 6 次執行失去可比性。
2. **本分析是一條規則，與 `r_gate` 同性質**，應與 `rule_baselines.py` 的三條規則並列評估，
   不與 M2／M3 並列。本專題反覆量到的結果正是規則優於模型。
3. 「以 linkage 為 feature 重訓 M2／M3」列為 future work，需要新的 configuration lock
   與新的凍結程序，不在本文件範圍。

## 4. 量測協議（執行前凍結）

沿用 `authz_eval_protocol_v1.md` 的全部約束：threshold 無可調（linkage 是布林）、
母體兩層都報、指標直接 import `rule_baselines._classification` 與 `_ranking`
以保證與既有參考線同一套實作。

**預先登記要報告的四組數字，不論結果如何都照報：**

| # | 母體 | 為什麼要報 |
|--:|---|---|
| 1 | 外部可達子集全部 106 筆 | 與 0.439／0.519／0.695 同母體，可直接並列 |
| 2 | **排除設計時看過的 2 顆 APK**（`9b2a8728`、`9ed8ab7e`） | §0 第 2 項的對照。此為**主要數字** |
| 3 | Gold 全部二分類 348 筆 | 完整流程；此層被 R 主導，不可用於評價本分析 |
| 4 | 那 65 筆 LF 漏判 × 23 筆 Gold negative | `authz_eval_protocol_v1.md` §6：想修的那一側與代價那一側必須並列 |

**判讀規則：**

1. **超過 0.695 不構成洩漏跡象。** 0.695 的定義是「任何只用**既有那組粗粒度特徵**的
   分類器都無法超過」（`bottleneck_analysis.json`）。linkage 是該組之外的新證據，
   超過它是「補上缺失證據」的預期結果。**但不得反過來用這一點來免除檢查**：
   若數字高到接近完美（例如 macro F1 > 0.95），仍應視為實作錯誤或洩漏，回頭查。
2. 第 2 組數字若明顯低於第 1 組，表示表現主要來自設計時看過的 APK，
   結論必須改寫成「在那個重包裝家族上有效」而非一般性結論。
3. false positive 必須與 recall 並列。這是一個過度近似的分析，FP 是它的代價。

## 5. 產物

```
dataset/authz_v2/entry_sink_linkage.jsonl          逐 unit 的 linkage 結果
dataset/authz_v2/experiments/linkage_eval.json     §4 的四組數字
```

`entry_sink_linkage.jsonl` 每列：

| 欄位 | 說明 |
|---|---|
| `review_unit_id` | join key |
| `sha256` | APK |
| `linkage_result` | `linked`｜`not_linked`｜`error` |
| `linkage_reason` | `sink_in_entry_method`｜`call_chain`｜`no_path`｜`apk_unavailable`｜`parse_failed` |
| `path_depth` | 找到的鏈長（跳數）；`sink_in_entry_method` 為 0，`not_linked` 為 `null` |
| `used_callback_edge` | 該路徑是否用到規則 A |
| `used_init_as_entry` | 該路徑是否用到規則 B |
| `analysis_version` | `authz-linkage-v1` |

`used_callback_edge` 與 `used_init_as_entry` 是刻意記錄的：它們讓「§2.2 的兩條近似各自
貢獻了多少」可以事後稽核，而不必重跑。

**不寫入 Gold 相關欄位。** 本分析不讀 `gold_review_log.jsonl`；與 Gold 的 join 是
`linkage_eval.json` 那一步的事。

## 6. 已知限制

- **不 sound 也不 complete**（§2.3）。規則 A 可能產生不存在的路徑，
  反射／動態載入的邊一律看不到。
- **節點不含 descriptor**（§2.1），同名多載被併。
- **需要 APK 原始檔案。** 分析無法只由既有的 JSONL 產物重跑；APK 不在原路徑時記為
  `apk_unavailable`。這使本分析的可重現性比其他步驟弱，必須在報告中說明。
- **母體的 negative 只有 23 筆**，且本專題已知它們集中在少數 APK。
  任何關於 false positive 的結論都建立在這 23 筆上。
- **設計過程接觸了 Gold 的 positive 側**（§0）。
- 不處理 A，不處理跨 APK，不做 taint analysis。

## 7. 結果（2026-10-06，於規則與實作 commit 之後才執行）

產物：`dataset/authz_v2/entry_sink_linkage.jsonl`、
`dataset/authz_v2/experiments/linkage_eval.json`。

### 7.1 執行本身

384 筆 Gold unit × 37 個 APK，**154 秒**，補出的回呼邊 11,471 條。

```
linked      264        其中 sink 就在 entry method 裡   113
not_linked  120             由呼叫鏈接起來               151
error         0
```

**兩條近似各自的貢獻比預期小。** 151 筆由呼叫鏈接起來的 unit 中：

| | 筆數 | 佔 264 筆 linked |
|---|--:|--:|
| 只用 Androguard 原本的邊 | 106 | 40% |
| 需要規則 A（建構者 → 回呼） | 45 | 17% |
| 需要規則 B（`<init>` 視為 entry） | 21 | 8% |

這一點對報告有用：**linkage 的主要貢獻來自「建一張呼叫圖」這件事本身**，
兩條不 sound 的近似只負責其中 45 + 21 筆。質疑近似的正當性時，
可以退回「只用原本的邊」那一層，而該層仍然遠超越既有做法。

### 7.2 主要數字

| 母體 | 筆數 | TP | FP | FN | TN | precision | recall | **macro F1** | bal. acc |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 外部可達子集（全部） | 106 | 74 | 7 | 9 | 16 | 0.914 | 0.892 | **0.785** | 0.794 |
| **排除設計時看過的 APK** | 67 | 39 | 7 | 5 | 16 | 0.848 | 0.886 | **0.797** | 0.791 |
| Gold 全部二分類 | 348 | 74 | 168 | 9 | 97 | 0.306 | 0.892 | 0.489 | 0.629 |

放進參考線（外部可達子集）：

| | macro F1 |
|---|--:|
| 全判 negative | 0.184 |
| M3（SLB） | 0.207 |
| 只看 I／S 的 LF | 0.331 |
| M2（vanilla MLP） | 0.400 |
| 可達性規則（全判有風險） | 0.439 |
| 跨 APK 多數決 | 0.519 |
| 既有特徵的作弊上限 | 0.695 |
| **linkage 規則（主要數字）** | **0.797** |

### 7.3 §0 第 2 項的對照通過了

這是本節最重要的一件事，因為它決定上面的數字能不能用。

**設計時看過的那 2 顆 APK 貢獻 0 筆 Gold negative。** 它們提供 39 筆 positive、
0 筆 negative，因此排除它們之後 negative 側**完全沒有改變**（FP 7、TN 16 兩層相同），
而 negative 側正是全部判別困難的所在。排除後 macro F1 由 0.785 升到 0.797，
不是降低。

這不表示污染不存在——規則確實是看著 Gold positive 想出來的——但它表示
**判別力不是從設計時看過的樣本上套出來的**。報告應以 0.797 為主要數字，
並同時列出 0.785 與這個對照。

### 7.4 那 65 筆漏判，以及代價

| | 筆數 | linkage 的結果 |
|---|--:|---|
| LF 漏判的真 positive | 65 | **接起來 56 筆（86%）** |
| Gold negative | 23 | **未接起來 16 筆（70%）** |

對照同一組數字上的其他做法：

| | 65 筆漏判救回 | 23 筆 Gold negative 的 TN |
|---|--:|--:|
| LF 自己 | 0（按定義） | 20 |
| M2 | 14 / 13 / 13 | 17 / 19 / 19 |
| M3 | 1 / 1 / 13 | 16 / 16 / 9 |
| **linkage 規則** | **56** | **16** |

linkage 以 TN 由 LF 的 20 降到 16（4 筆代價）換到漏判由 0 救回 56 筆。
M2 在相同的代價區間（TN 17–19）只救回 13–14 筆。

### 7.5 Gold 全部二分類那一層為什麼是 0.489，以及它為何不是壞消息

該層 168 筆 FP，precision 掉到 0.306。原因單純：**linkage 完全不看外部可達性**，
它只問「呼叫鏈接不接得起來」，所以 R 已經否定的 242 筆 unit 它一樣會接起來。

這正是 ADR-0002 的流程設計：**R 由規則在最前面把關，linkage 只處理 R 之後剩下的那一層。**
實際流程不會把 R 已否定的 unit 送進來。該層的數字只用於說明「linkage 不能取代 R gate」，
不可用於評價 linkage 本身，這一點在 §4 第 3 組已事先登記。

### 7.6 排序

`units_to_80pct_recall` 在主要層為 **41 筆**（母體 67、positive 44）。
隨機排序的期望值約 55 筆。因為 linkage 只有兩個分數（0／1），
排序的實質是「接起來的排前面」，這已足以產生改善。

對照：M2／M3 的同一指標為 85–89 筆（母體 106、positive 83），
隨機約 85 筆——**兩個模型在排序上等於隨機，linkage 不是。**
《總覽》1.3 節「模型的價值在排序」那個定位，在 linkage 上才首次成立。

### 7.7 全量執行與訓練池的交叉結果

全量：**2,121 筆 unit × 208 個 APK**，補出的回呼邊 62,134 條，
`error` 0 筆（全部 APK 都讀得到）。Gold 那 384 筆的判定與 §7.1 的單獨執行**完全相同**，
分析是決定性的。

```
linked      1,481      其中 sink 就在 entry method 裡   804
not_linked    640           由呼叫鏈接起來               677
```

需要近似的比例與 Gold 上一致：規則 A 156 筆、規則 B 39 筆，合計僅佔 linked 的 13%。

> **【2026-10-07 修正：實作與本規格不符，非規則變更】**
> §2.2 規則 B 寫的是「**component 類別的** `<init>`」，§2.3 的辯護也只對 component 成立
> （框架先建構 component 實例才呼叫生命週期方法）。但初版實作對**任何**類別都套用了這條
> 規則——而每個類別都有 `<init>`，等於對非 component 的 caller class 幾乎無條件放行。
>
> 已加上閘門：`linkage_status = unlinked_caller`（caller class 對不上任何 Manifest
> component）的 unit 不適用規則 B，並補上一條專門的測試。
>
> **影響範圍先量過才修**：Gold 外部可達子集 106 筆中，用到規則 B 的 21 筆**全部是
> component 類別**，因此 §7.2、§7.4 的全部數字**一字未變**（重跑後逐欄位核對相同）。
> 受影響的只有全量：linked 1,491 → 1,481、規則 B 49 → 39、規則 A 166 → 156，
> 恰好是那 10 筆非 component 的 unit。訓練池交叉的數字（§7.7 下方）隨之更新。
>
> 這是「實作沒照著凍結的規格做」的修正，不是「改規則」——§2.2 的文字未改動。
> 發現過程：在檢查 §7.4 那 7 筆 false positive 的樣態時，注意到 `abstain` 的 268 筆
> 全部被判為 `linked` 這個過於整齊的數字，追下去才發現閘門缺失。

**與弱標籤的交叉（訓練池 1,685 筆）：**

| LF 的 reason code | 筆數 | linked | not_linked |
|---|--:|--:|--:|
| `weak_positive_sink_in_entry_method` | 387 | **387** | 0 |
| `weak_negative_no_entry_to_sink_evidence` | 1,022 | **524** | 498 |
| `weak_negative_sink_permission_undeclared` | 8 | 8 | 0 |
| `abstain_caller_class_not_component` | 268 | 268 | 0 |

**第一列是一個 sanity check，而且通過了**：LF 的 387 筆 positive 條件是「sink 寫在 entry
method 裡」，linkage 對它們必然回報 `sink_in_entry_method`，實測 387／387 相符。
若有任何一筆不符，就是實作錯誤。

**第二列是這份分析對弱標籤的意義**：LF 最大的 negative 來源 1,022 筆被切成
534／488。`authz_lf_spec_v1.md` §6.3 記載過一個死路——照定義把「sink 不在 entry method 裡」
改判 abstain，negative 只剩 8 筆，無法訓練二分類器。有了 linkage，同一個修正變成：

```
現行弱標籤   positive   387、negative 1,030   （positive 佔 27.3%）
若把 linked 的 weak negative 改判 positive
             positive   911、negative   506   （positive 佔 64.3%）
```

**兩邊都有足夠的筆數，§6.3 的死路因此被解開了。**

**但本文件不做這件事，理由不是成本：**

1. 那會是一個新的 LF（`authz-lf-v2`），必須重新凍結、重新量噪音率，而噪音率要量就得碰
   Gold——那是另一個完整的凍結程序。
2. 隨之要重訓 M2／M3，而 feature 是 configuration lock（§3），已完成的 6 次執行會失去
   可比性。
3. 更根本的是：**本分析的設計已經接觸過 Gold 的 positive 側**（§0）。
   把它接進訓練標籤，污染就從「一條規則的評估數字」擴散到「模型的訓練資料」，
   那是無法用排除法對照來緩解的。

因此「以 linkage 重寫 LF 並重訓」列為 future work，且必須以**新的、未被本次設計接觸過的
評估資料**來做，不得沿用現有的 385 筆 Gold。

## 8. 重跑指令

```bash
python -m app.tools.entry_sink_linkage                  # 產生逐 unit 的 linkage 結果
python -m app.tools.entry_sink_linkage --evaluate       # 再與 Gold join，產生 §4 的四組數字
python -m pytest tests/test_entry_sink_linkage.py
```
