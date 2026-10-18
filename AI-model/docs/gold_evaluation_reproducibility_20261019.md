# Golden-50 模型評估重現性稽核（2026-10-19）

## 結論

共享 Drive 的 `model_eval_gold.json` 不能直接與目前 repository 中的 Gold
review log 合併或重算。兩者使用的評估母體不一致，而且共享資料包沒有逐筆
`review_unit_id` 預測。

| 母體欄位 | 封存評估 | 目前 Gold | 差值（目前－封存） |
|---|---:|---:|---:|
| Binary units | 348 | 361 | +13 |
| Positive | 83 | 58 | -25 |
| Negative | 265 | 303 | +38 |
| Unknown | 36 | 24 | -12 |

封存評估另排除 1 筆無 identity，並在 reachable subset 使用 106 units
（83 positive、23 negative）。目前物化 Gold 的 label 分布來自
`gold_review_log.jsonl` 最新未被 supersede 的事件；不能用 aggregate 數字反推
哪些 unit 改變，也不能將舊 confusion matrix 當成目前 Gold 的模型成績。

## 權威來源

- Drive file：`model_eval_gold.json`，file ID
  `1Ig9HVCM64idgqskD21MT6A-LD9sCljWY`
- 檔案 SHA-256：
  `7141d3e5f743166e8f7744e1f193e502df94c7d5c0bc00c5e72dde87663a7e77`
- 比較欄位：`/population_accounting` 與
  `/layers/pipeline_all_binary/{positives,negatives,evaluated_units}`
- 目前 Gold authority 與輸出雜湊：
  `dataset/authz_v2/golden_50_labels_summary.json`

Drive 檔案包含 M2/M3 三個 seeds 的彙總 confusion matrix 與 metrics，但沒有逐筆
prediction rows。`entry_sink_linkage.jsonl` 有 linkage identity，仍不能替代模型逐筆
輸出；把兩者用名稱或列序猜接會破壞評估可追溯性。

## 重新評估的完成條件

1. 指定並凍結要使用的 Gold review-log revision 與 SHA-256。
2. 由每個 M2/M3 run 匯出逐筆：`review_unit_id, model_id, seed,
   predicted_label, score`。
3. 確認 run manifest 的 training pool 排除所有 Golden-50 identity 與 lineage
   siblings。
4. 使用 `app.tools.evaluate_gold_predictions` 對相同 Gold revision 執行評估。
5. 報告 coverage、unknown 排除數、每 seed 指標與跨 seed 分布；不得用 Gold 搜尋
   threshold 或挑選 best seed。
