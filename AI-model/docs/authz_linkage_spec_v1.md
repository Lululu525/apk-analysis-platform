# Entry-to-sink linkage 規格 v1

狀態：**規則凍結，執行前 commit**（2026-10-06）。執行順序新增第 6 項。
實作於 `app/tools/entry_sink_linkage.py`。

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

## 7. 重跑指令

```bash
python -m app.tools.entry_sink_linkage                  # 產生逐 unit 的 linkage 結果
python -m app.tools.entry_sink_linkage --evaluate       # 再與 Gold join，產生 §4 的四組數字
python -m pytest tests/test_entry_sink_linkage.py
```
