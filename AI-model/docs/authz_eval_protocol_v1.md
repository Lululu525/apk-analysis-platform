# M2／M3 對 Gold 的評估協議 v1

狀態：**協議凍結（§0–§8），評估已執行，結果見 §10**（2026-10-04）。
執行順序第 5c-ii 項（ADR-0002）。實作於 `app/tools/evaluate_authz_models.py`。

一句話的結果：主要層上 **M2 平均 macro F1 0.400、M3 0.207**，M3 在三個 seed 上
全部較差；兩者都低於「把外部可達的全部當成有風險」的 0.439；SLB 在它該修的那 65 筆
漏判上由 M2 的 14／13／13 退到 1／1／13。細節與判讀見 §10。

**這是整個專題第一次把模型預測與 Gold 放在一起。** 在此之前的 6 次訓練執行
（`slb_config_spec_v1.md` §8、§9）全程未讀取 Gold，manifest 的 `gold_consulted`
皆為 `false`。本步驟之後，任何回頭改動模型、threshold 或超參數的行為都不可能再被
視為乾淨的——因此本文件的全部決定必須在看到任何一個 Gold 分數之前 commit。

## 0. 為什麼這一步特別需要先凍結

前面幾個步驟的凍結協議（`slb_config_spec_v1.md` §0）防的是「看到結果再挑設定」。
到了評估這一步，可以被挑的東西更多，而且每一個都能單方面讓數字變好看：

| 可挑的東西 | 不挑的做法（本文件凍結的） |
|---|---|
| threshold | 固定 0.5（即 argmax），不搜尋。另列與 threshold 無關的排序指標 |
| 母體 | 兩層都報（整條流程、外部可達子集），不得只報好看的那一層 |
| seed | 三個 seed 全報，另報平均與極差。**不取最佳 seed** |
| 指標 | 分類與排序並列，主指標固定為 macro F1，以便與既有三條參考線直接比 |
| M2／M3 的比較方式 | 逐 seed 配對比較 + 平均差，**不做統計檢定**（n = 3，檢定沒有意義） |

**不論結果如何都照實報告**，包含「M3 沒有比 M2 好」與「兩者都低於全判 positive」。
ADR-0002 已明載 `M2 ≈ M3 是可接受且有意義的結果`，`authz_lf_spec_v1.md` §6.5 更已
預先說明預期 M2 表現很差。

## 1. 母體

模型預測取自 `experiments/predictions_<run>.jsonl` 的 `split = "gold_eval"`（384 筆，
由 `features_gold_eval.jsonl` 編碼而來）。與之 join 的 Gold 取 `gold_review_log.jsonl`
的每個 unit **最新一筆 event**（`gold_consistency.load_latest_events`，即 supersession
之後的結果）。

| 層 | 定義 | 用途 |
|---|---|---|
| `pipeline_all_binary` | Gold 為 `positive`／`negative` 且有 feature 的全部 unit | 完整流程的數字。**會被 R 已否定的 unit 主導**，解讀須加註 |
| `reachable_subset` | 同上，再排除 `r_gate` 判為 `refuted` 的 unit | **主要層**。ADR-0002 指定這是模型實際負責的那一層 |

Gold 為 `unknown` 的 unit 一律排除（無法二分類比對），排除筆數照實列出。

`reachable_subset` 是主要層的理由已在 ADR-0002 與 `authz_lf_spec_v1.md` §6.1 說明：
`pipeline_all_binary` 的 negative 中約八成由 R 否定，而 R 可由 Manifest 規則完全重現
（384／384），模型在那一層的分數主要反映「它有沒有重建 R」，而 R 根本不在它的 feature 裡。

## 2. 判定規則

```
predicted_label = positive  若 prob_positive >= 0.5，否則 negative
```

即 `argmax`，與訓練時的 loss 一致。**不做任何 threshold 搜尋**，理由與
`slb_config_spec_v1.md` §1.1 相同：搜尋 threshold 需要一把 Gold 以外的尺，而此處沒有。
`predictions_<run>.jsonl` 內的 `predicted_label` 已是此規則的結果，本模組直接採用。

另列三個與 threshold 無關的排序指標（沿用 `rule_baselines.py` 的同名實作，使數字可直接
並列）：`P@10`、`P@50`、`units_to_80pct_recall`、`per_apk_mean_P@3`。
排序的次要鍵固定為 `review_unit_id`，使並列分數的順序可重現。

## 3. 指標與參考線

主指標 **macro F1**，因為既有的三條參考線都是 macro F1。一併列出 TP／FP／FN／TN、
positive 的 precision／recall、balanced accuracy，以及第 2 節的排序指標。
分類指標的實作直接 import `rule_baselines._classification` 與 `_ranking`，
不另寫一份，避免兩套實作算出不同的數字。

外部可達子集（106 筆）上的參考線，全部取自已 commit 的既有產物：

| 參考線 | macro F1 | 來源 |
|---|--:|---|
| 全判 negative | 0.184 | `lf_noise_rate.json` |
| 只看 I／S 的 LF | **0.331** | `lf_noise_rate.json`，`authz_lf_spec_v1.md` §6.1 |
| 可達性規則（全判有風險） | 0.439 | `rule_baselines.json`、`bottleneck_analysis.json` |
| 跨 APK 多數決 | 0.519 | `bottleneck_analysis.json` |
| 以 Gold 直接擬合的作弊上限 | 0.695 | `bottleneck_analysis.json` |

**判讀規則，先凍結：**

1. **macro F1 > 0.695 視為洩漏的強烈跡象**，不得當成好消息。時程表 5c 已明載
   「超過 0.695 幾乎一定是洩漏」。若發生，優先查 feature 與 train／eval 的 APK 互斥性。
2. 低於 0.439（全判有風險）即表示模型不如「把外部可達的全部當成有風險」這條規則，
   這是可能的結果，照報。
3. 與 LF 的 0.331 比較回答的是「模型有沒有超過它的訓練標籤」；
   與 0.519 比較回答的是「模型有沒有超過跨 APK 可泛化的訊號上限」。
   兩個比較的意義不同，不得混為一談。

## 4. Seed 的處理

六次執行（M2、M3 各 3 個 seed）全部逐一報告。另報**三個 seed 的平均與極差**。

- **不取最佳 seed**，不以任何理由排除某個 seed。
- **不做機率平均的 ensemble。** 那是一個未曾預先登記的新方法，且 M2／M3 各只有
  3 個模型，ensemble 的效果會與 SLB 的效果混在一起，使 §2.3 辛苦對齊的控制變數失效。
  此項列為未做，不是忘記。
- M3 的 seed 間分散度已知遠大於 M2（`slb_config_spec_v1.md` §9.2：`|D_c|` 786–1,056），
  因此**極差必須與平均並列**，只報平均會隱藏這件事。

## 5. M2 與 M3 的比較

```
逐 seed 配對：同一個 seed 的 M3 macro F1 − M2 macro F1，共 3 個差值
平均差：M3 的平均 macro F1 − M2 的平均 macro F1
```

**不做顯著性檢定。** n = 3、且三個 seed 共用同一份資料與同一個評估集，配對樣本不獨立，
任何 p 值都是裝飾。報三個差值本身，讀者自己看方向是否一致。

三個差值方向不一致（有正有負）即視為「差距在 seed 噪音之內」，照此敘述，
不得只引用平均差的符號。

## 6. 預先登記的錯誤分析：那 65 筆漏判

`authz_lf_spec_v1.md` §6.1 量到 LF 在外部可達子集上漏掉 **65 筆**真 positive
（Gold = positive、LF = negative），這是本專題噪音的主體，也是 SLB 被要求修的東西。
`slb_config_spec_v1.md` §5.1 把「這 65 筆 SLB 有沒有救回來」列為 audit log 的用途之一。

**先講清楚這個問題的限制**，以免事後被誤讀：

SLB 修的是**訓練池**的標籤，而這 65 筆是 **Gold 評估集**的 unit，兩者 APK 互斥
（`authz_feature_spec_v1.md` §7.1 第五點）。因此不存在「SLB 把這 65 筆改對了」這種
直接的事。可以問、也值得問的是**同一個失效模式有沒有被跨過**：

```
M2 與 M3 在這 65 筆上各預測對幾筆（即預測為 positive）
```

M2 的訓練標籤在這個模式上系統性地錯；若 SLB 的修正有效，M3 應該在這 65 筆上
recall 較高。這是本步驟唯一的因果性問題，其餘皆為描述。

一併報告其補集：LF 判對的 14 筆（TP）與 3 筆 FP 上兩個模型的表現，
以免只看漏判那一側而忽略「M3 是不是只是把所有東西都往 positive 推」。
後者有具體的理由要擔心：`slb_config_spec_v1.md` §9.4 已量到 SLB 把
`positive_share_of_training_labels` 由 0.273 推到 0.288／0.329／0.472。

**因此以下兩個數字必須並列，不得只報前者：**

```
在 65 筆漏判上的 recall        （SLB 想修的）
在 23 筆 Gold negative 上的 TN （修正的代價）
```

## 7. 本模組不做的事

- **不修改任何 label、不重新訓練、不調整任何設定。** 唯讀。
- 不計算 I／S 各自的指標。ADR-0002 2026-09-22 修訂已說明審查在第一個被否定的
  predicate 停止，I 與 S 的個別次數反映審查順序，不具比較意義。
- 不做 subgroup analysis（F-Droid／MalDroid）。那是時程表 Week 10 的獨立項目。
- 不產生任何「調整後」的分數。看到結果之後唯一允許的動作是**記錄與解釋**。

## 8. 產物

```
dataset/authz_v2/experiments/model_eval_gold.json
```

一份檔案，含兩層 × 6 次執行的全部指標、參考線、seed 聚合、第 5 節的配對差、
第 6 節的錯誤分析，以及母體的筆數交代（Gold 事件數、有 feature 數、二分類數、
可達數、排除數）。

## 10. 結果（2026-10-04，於本文件與實作 commit 之後才執行）

產物：`dataset/authz_v2/experiments/model_eval_gold.json`。

### 10.1 母體交代

```
Gold event 385 → 有 identity 384 → 有預測 384 → 二分類 348（排除 unknown 36）
                                              → 外部可達 106（R 已否定 242）
```

三個數字與既有產物完全吻合，可互相驗證：348 與 `rule_baselines.json` 的
`pipeline_all_binary` 相同，106 與 `bottleneck_analysis.json` 的母體相同，
而 `lf_noise_rate.json` 的 `102 + 4 abstain = 106`、`344 + 4 = 348` 也對得上。

### 10.2 主要層：外部可達子集（106 筆，positive 83、negative 23）

| 執行 | TP | FP | FN | TN | precision | recall | **macro F1** | balanced acc |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| m2-seed20260823 | 25 | 6 | 58 | 17 | 0.806 | 0.301 | **0.393** | 0.520 |
| m2-seed20260824 | 24 | 4 | 59 | 19 | 0.857 | 0.289 | **0.404** | 0.558 |
| m2-seed20260825 | 24 | 4 | 59 | 19 | 0.857 | 0.289 | **0.404** | 0.558 |
| m3-seed20260823 | 5 | 7 | 78 | 16 | 0.417 | 0.060 | **0.189** | 0.378 |
| m3-seed20260824 | 5 | 7 | 78 | 16 | 0.417 | 0.060 | **0.189** | 0.378 |
| m3-seed20260825 | 17 | 14 | 66 | 9 | 0.548 | 0.205 | **0.241** | 0.298 |

```
M2 macro F1  平均 0.400，極差 0.393–0.404（0.012）
M3 macro F1  平均 0.207，極差 0.189–0.241（0.052）
M3 − M2      −0.203 / −0.215 / −0.163，平均 −0.194，三個差值方向一致
```

放進參考線：

| | macro F1 | |
|---|--:|---|
| 全判 negative | 0.184 | |
| **M3** | **0.207** | 僅略高於全判 negative |
| 只看 I／S 的 LF（M2 的訓練標籤） | 0.331 | |
| **M2** | **0.400** | 高於自己的訓練標籤，低於可達性規則 |
| 可達性規則（全判有風險） | 0.439 | |
| 跨 APK 多數決 | 0.519 | |
| 以 Gold 直接擬合的作弊上限 | 0.695 | |

**沒有洩漏跡象**：最高分 0.433（整條流程層）遠低於 0.695，協議 §3 的絆索未觸發。

### 10.3 三個結論

**一、M2 超過了它的訓練標籤，但沒有超過最笨的規則。**
M2 的形狀與 LF 幾乎相同——高精確率、低召回率（precision 0.81–0.86 對 LF 的 0.824）——
但召回率由 LF 的 0.177 提升到 0.289，macro F1 由 0.331 提升到 0.400。
也就是說模型確實從噪音標籤中學到了比標籤本身更好的東西，這是弱監督有作用的證據。
**但 0.400 仍低於「把外部可達的全部當成有風險」的 0.439**，所以在這一層，
訓練一個模型的淨效益是負的。

**二、M3 比 M2 差，三個 seed 一致。** 配對差 −0.163 到 −0.215，方向一致，
不是 seed 噪音。M3 的 0.207 只比全判 negative 的 0.184 高一點。
兩個 seed 的 recall 崩到 0.060（83 筆真 positive 只抓到 5 筆）。
M3 的 seed 間極差（0.052）是 M2 的四倍，與 `slb_config_spec_v1.md` §9.2 量到的
`|D_c|` 分散度（786–1,056）一致。

**三、排序完全沒有判斷力。** `units_to_80pct_recall` 為 85–89（母體 106 筆、
83 個 positive）。隨機排序大約需要 85 筆才能看到 80% 的 positive，六次執行全部落在
這個數字附近。`bottleneck_analysis.json` 對規則排序的結論在模型上同樣成立。

### 10.4 §6 預先登記的錯誤分析：SLB 在它該修的那一側變得更差

| LF 的格子 | 筆數 | 要的 | m2·0823 | m2·0824 | m2·0825 | m3·0823 | m3·0824 | m3·0825 |
|---|--:|---|--:|--:|--:|--:|--:|--:|
| `lf_missed_positives` | 65 | 判 positive | **14** | **13** | **13** | **1** | **1** | **13** |
| `lf_true_positives` | 14 | 判 positive | 7 | 7 | 7 | 1 | 1 | 1 |
| `lf_false_positives` | 3 | 判 positive | 2 | 2 | 2 | 2 | 2 | 2 |
| `lf_abstained` | 4 | 判 positive | 4 | 4 | 4 | 3 | 3 | 3 |
| `gold_negatives` | 23 | 判 negative | 17 | 19 | 19 | 16 | 16 | 9 |

**這是本步驟最尖銳的一個數字。** 那 65 筆是 LF 的系統性漏判、是本專題噪音的主體、
也是 SLB 被要求修的東西：

- **M2 救回 14／13／13 筆**（LF 本身按定義是 0 筆）。弱監督跨過了這個失效模式的一部分。
- **M3 救回 1／1／13 筆。** 三個 seed 中有兩個幾乎完全退回去。

協議 §6 要求與代價那一側並列，而並列之後的結果比單看一側更不利：

```
seed 20260823    漏判救回 14 → 1，Gold negative 的 TN 17 → 16
seed 20260824    漏判救回 13 → 1，Gold negative 的 TN 19 → 16
seed 20260825    漏判救回 13 → 13，Gold negative 的 TN 19 → 9
```

**前兩個 seed 不是取捨，是兩側同時變差。** 第三個 seed 維持了漏判的救回數，
但 23 筆 Gold negative 的 TN 由 19 掉到 9——它是靠把更多東西判成 positive 換來的，
不是靠判斷力。

### 10.5 為什麼 M3 會這樣，以及這不是 bug

機制在訓練階段就已經量到並記錄，不是事後編出來的解釋：

1. `slb_config_spec_v1.md` §9.5：階段二只訓練「標籤與模型自己的 EMA 判定一致」的樣本，
   而 `α = 0.95` 使 EMA 幾乎等於當下預測，所以訓練準確率恆為 1.0000——**模型在自我確認**。
2. §9.3：格內同質化從階段二第一個 epoch 就是完全的
   （`distinct_training_labels_per_cell_mean` 恆為 1.000）。衝突格內的少數類全部被排除
   或被同化，而那正是唯一可能帶有「漏判」訊號的地方。
3. 首次重組（epoch 6）之後集合幾乎凍結，其後 95 個 epoch 只是強化同一個決定。
4. §9.4 量到翻標籤方向以 negative→positive 為主（102／120／169 筆）。
   **方向與已知的噪音方向一致，但落在錯的 unit 上**——訓練池的 positive 比例被推高
   （0.273 → 0.288／0.329／0.472），Gold 上的 recall 卻崩了。

**這正是 `authz_lf_spec_v1.md` §6.5 預先登記的預期，而且成立得比預期更強。** 原文：

> LF 會錯的地方，大致就是模型也無從分辨的地方——SLB 被要求修的噪音有相當比例在
> 現有特徵下原理上修不掉。

實測不只是「修不掉」，而是**在 31 維特徵下，SLB 的自我確認機制會主動把 M2 原本靠噪音
標籤學到的那一點召回率抹掉**。ADR-0002 寫「M2 ≈ M3 是可接受且有意義的結果」，
實際得到的是 M3 < M2，方向一致。這對本專題的主軸（量化自動化證據的瓶頸）是一個**正面**
的結果：它在第三個獨立的位置上量到了同一個瓶頸——規則端（0.439／0.519）、標籤生成端
（LF recall 0.177）、以及現在的標籤修正端。

### 10.6 一項事後的描述性觀察

**以下數字是在看到 §10.2 之後才算的，屬協議 §7 允許的「記錄與解釋」，
不涉及任何模型、threshold 或母體的改動。**

六次執行判為 positive 的 unit，落在哪一層：

| 執行 | 判 positive 總數 | 落在外部可達 | 落在 R 已否定 |
|---|--:|--:|--:|
| m2 三個 seed | 138／137／135 | 31／28／28（20–22%） | 107／109／107（78–80%） |
| m3 三個 seed | 92／99／123 | 12／12／31（12–25%） | 80／87／92（75–88%） |
| （母體比例） | 348 | 106（30.5%） | 242（69.5%） |

模型的 positive 預測與外部可達性**幾乎無關**，M3 甚至略為反向。這是預期中的，
因為 `exported`／可達性依 `authz_feature_spec_v1.md` §1 刻意完全不在 feature 內。
記錄它的用途是說明為什麼 `pipeline_all_binary` 那一層的數字不可用於評價模型：
該層 242 筆 negative 由 R 決定，而模型對 R 一無所知，它在那層的分數主要由
「它碰巧沒把多少 R 已否定的 unit 判成 positive」決定。

### 10.7 本步驟沒有改動任何東西

6 個模型、threshold、母體定義、指標、參考線在本步驟之後與之前完全相同。
`model_eval_gold.json` 內記下 `threshold_searched`、`best_seed_selected`、
`probability_ensemble`、`significance_test` 皆為 `false`，供稽核。

## 11. 重跑指令

```bash
python -m app.tools.build_observed_labels --gold-eval-labels   # LF 在 Gold 上的逐筆標籤
python -m app.tools.evaluate_authz_models
python -m app.tools.evaluate_authz_models --dry-run            # 只印報表，不寫檔
python -m pytest tests/test_evaluate_authz_models.py
```

## 12. 下一步

5c 全部完成。接下來依時程表：

- Week 10 的錯誤分析與 F-Droid／MalDroid subgroup analysis（本文件 §7 明載不在此做）。
- 桌面 `專題報告_20260927/` 的分冊 03、04、05 需要補上本文件 §10 的數字；
  目前那三份只寫到規則基準線與噪音量測，模型的實測結果尚未納入。
- 分冊 00 的摘要需要新增一項：瓶頸在第三個獨立位置（標籤修正端）也量到了。
