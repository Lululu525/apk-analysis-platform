---
status: accepted
date: 2026-09-21
---

# 以 R/I/S/A 評估框架與自動化瓶頸拆解為主軸，SLB 降為探索性實驗

ADR-0001 定下分析範圍後，Golden APK Set 已完成全部 385 個 review units 的 Gold 授權標籤。實際資料顯示：外部可達性（R）可以完全由 Manifest 語意的確定性規則重現，但在外部可達的候選中，區分真假主要依賴攻擊者輸入影響（I）；而 I 與授權控制（A）的自動化證據需要 taint analysis 與 runtime guard dominance 分析，工程量超出本專題規模。現有自動化證據只涵蓋 R 與 S，因此原先以 Vanilla／SLB 比較為主要成果的研究主張，其前提（模型能從自動化特徵學到 I）不成立。本決策與學姐討論後採用。

## 決策

- 研究主軸改為兩部分：（1）以 R/I/S/A 定義並人工建立 Gold 授權標籤的評估框架；（2）以 Gold 量化「自動化越權風險偵測的難點在哪」，即 R、I、S、A 各自能被現有自動化證據解決到什麼程度。
- R 由確定性的可達性規則（`app/tools/r_gate.py`）在最前面判定，依 `docs/authz_annotation_guide.md` Step 1 只在 Manifest 語意確定時給 confirmed／refuted，其餘為 unknown；R refuted 的候選 early-stop，unknown 不視為 negative。判定順序維持 R → I → S → A。
- 可達性規則使用的 exported、permission、protection level 等欄位，仍依 `authz_label_spec.md` §8.3 不得進入模型 feature，也不參與產生觀測授權標籤。
- Vanilla（M2）與 SLB（M3）降為小規模探索性實驗，定位為「在缺少 I 自動化證據的條件下，模型與 weak-label revision 能做到什麼」。M2 ≈ M3 是可接受且有意義的結果，不視為失敗。
- 評估分兩層：模型單獨評估只用 Gold 中 R confirmed 的二分類 units；整條流程（可達性規則加模型）用 Gold 全部二分類 units，並與洩漏基線及 `exported && !protected` 規則比較。分類指標與排序指標（Precision@K、找到 80% positive 需檢視的筆數）並列報告。
- 重申：Gold 授權標籤不得用於 feature、LF、threshold 或超參數的選擇。任何 feature 的納入或排除必須有 Gold 以外的依據。

## Considered Options

- **採用：評估框架與瓶頸拆解為主軸，SLB 為探索性實驗。** 成果建立在已完成、可稽核的 Gold 與已驗證的可達性規則上，不依賴專題無法完成的 I／A 自動化。
- **不採用：照原計畫以 Vanilla／SLB 比較為主要成果。** 模型幾乎只能從自動化特徵學到 S；若 LF 也主要依據 sink，模型會重建 LF，SLB 的 revision 會把 label 往規則推（revision collapse），結論很可能是各模型重疊而無法解讀。
- **暫不採用：補一個最小版 I 分析（method 內追 `getIntent()`／extras 是否流到 sink）。** 工程量中等但準確度不確定；保留為時間允許時的加強項或 future work，不列入本版主線。
- **不採用：以可達性規則先篩掉訓練資料。** 會連帶縮減訓練池並牽動其他已定案的範圍決定；改為訓練時使用全部訓練 units，可達性只在判定與評估時由規則處理。

## Consequences

- ADR-0001 的範圍、prediction unit、三層標籤分離與 SLB 不定義越權等決定全部沿用；本決策只取代 `docs/SLB越權偵測實作時程.md` 中「凍結後的研究主張」與後續週次的優先序。
- 時程表新增 2026-09-21 scope reframe 區段作為唯一有效的執行順序；2026-09-04 區段與原 14 週 schedule 保留為歷史紀錄。
- 新的主線工作依序為：Gold 在 safe group 內的 R/I/S/A 一致性檢查；在 Gold 上比較 `exported && !protected`、可達性規則、可達性規則加 sink 類別先驗（先驗不得由 Gold 估計）；量化 I 瓶頸；最後才是縮小規模的 M2／M3。
- 先前 feature 討論中以 Gold 分布作為排除 `linkage_status`、強調 `sink_group_id` 的理由，須改以 spec §8.2 與 S 的先驗語意為依據，並在報告中揭露曾檢視 Gold 分布。
- 「模型缺少 I 證據」與「LF 依據 sink 可能被模型重建」從設計漏洞轉為本研究要量化與報告的發現。
- 報告不得宣稱模型能自動判定越權，也不得以 SLB 結果推論 weak-label revision 在具備 I 證據時的效果。
