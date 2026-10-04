# M2／M3 對 Gold 的評估協議 v1

狀態：**協議凍結，執行前 commit**（2026-10-04）。執行順序第 5c-ii 項（ADR-0002）。
實作於 `app/tools/evaluate_authz_models.py`。

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

## 9. 重跑指令

```bash
python -m app.tools.evaluate_authz_models
python -m app.tools.evaluate_authz_models --dry-run    # 只印報表，不寫檔
python -m pytest tests/test_evaluate_authz_models.py
```
