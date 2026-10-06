---
status: accepted
date: 2026-09-21
---

# 以 R/I/S/A 評估框架與自動化瓶頸拆解為主軸，SLB 降為探索性實驗

ADR-0001 定下分析範圍後，Golden APK Set 已完成全部 385 個 review units 的 Gold 授權標籤。實際資料顯示：外部可達性（R）可以完全由 Manifest 語意的確定性規則重現；但在外部可達的候選中，區分真假需要程式碼層級的證據，也就是攻擊者輸入是否影響 sink（I），以及 entry 是否真的能到達 sink（S 的 linkage）。這兩者連同授權控制（A）的自動化需要 taint analysis、call graph 與 runtime guard dominance 分析，工程量超出本專題規模。現有自動化證據只有 Manifest 語意與「component class 內有呼叫敏感 API」，沒有 entry-to-sink 的連結，因此原先以 Vanilla／SLB 比較為主要成果的研究主張，其前提（模型能從自動化特徵學到程式碼層級的差異）不成立。本決策與學姐討論後採用。

> **2026-09-22 修訂**：原文寫「區分真假主要依賴 I」。Gold 一致性檢查（`app/tools/gold_consistency.py`）顯示這個說法不成立：審查依 R → I → S → A 順序，並在第一個被否定的 predicate 停止，所以 I 永遠比 S 先被檢查；當時外部可達的 51 筆 negative 中，有 37 筆記錄為 I refuted，但 S 並未檢查。另外，同一個事實（外部 entry 到不了 sink）曾被不同 unit 分別記為 I 或 S refuted。因此 I 與 S 的個別次數反映的是審查順序與歸因習慣，不能用來證明瓶頸在 I。改為較保守、但不受審查順序影響的說法：瓶頸在需要讀程式碼的 I 與 S linkage，兩者合併計算。

> **2026-10-06 修訂（本 ADR 的核心前提有一部分被推翻）**：本文第一段寫
> 「這兩者連同授權控制（A）的自動化需要 taint analysis、call graph 與 runtime guard
> dominance 分析，工程量超出本專題規模」。**這句話把三件不同的事綁在一起一併寫掉，
> 而其中 call graph 那一件實際上很便宜。**
>
> 2026-10-06 實作了 `app/tools/entry_sink_linkage.py`（規格
> `docs/authz_linkage_spec_v1.md`）：以 Androguard 的 XREF 建反向呼叫圖，判定 component
> 的 entry method 到不到得了 sink 所在的 method。約 200 行，37 個 Gold APK 跑 154 秒。
> 在外部可達子集上，**排除設計時看過的 APK 後 macro F1 0.797**（母體 67 筆、19 個 APK），
> 對照可達性規則 0.439、跨 APK 多數決 0.519、M2 0.400、M3 0.207。
> LF 系統性漏判的那 65 筆真 positive 接起來 56 筆，代價是 23 筆 Gold negative 的真陰性
> 由 20 降到 16。
>
> **三件事要分開記，否則這個修訂會被讀成「原本的判斷全錯」：**
>
> 1. **call graph：原判斷錯了。** 它不需要新工具——Androguard 已在用，
>    完整的呼叫關係在抽取敏感 API 證據時就存在過，只是沒有被寫進產物
>    （`sensitive_api_callers.jsonl` 的 `linkage_limit` 欄位自己寫著「未建立跨方法
>    call graph」）。
> 2. **taint analysis：原判斷仍然成立，但本專題不需要它。** 下方「暫不採用」第 3 項說的是
>    追 `getIntent()`／extras 的資料流，那確實工程量中等且準確度不確定。
>    但依 `authz_annotation_guide.md` Step 2 於 2026-09-19 經人工核准的觸發慣例，
>    **外部呼叫者的觸發動作本身即構成 I 的控制流影響，不要求攻擊者資料流進 sink 參數**。
>    因此只做控制流可達性就足以對應 Gold 的 I 判準。新增的分析**不是** taint analysis。
> 3. **runtime guard dominance（A）：原判斷完全成立。** A 仍然沒有任何自動化證據，
>    385 筆的 `A_predicate_result = refuted` 為 0 筆，全部 positive 的 A 確認都建立在
>    `runtime_guard_not_analyzed` 之上。本次修訂不觸及 A。
>
> **對主軸的影響**：原本第 5 項主張（剩下的訊號在程式層級的 I／S linkage）只有負面證據
> ——三份獨立量測都在證明「沒有它不行」，但答不出「有了它會怎樣」。
> 現在那個問題有數字了，主張由負面證據變成可量化的 demonstration。
> 主軸（以 R/I/S/A 評估框架量化自動化瓶頸）不變，而且更完整：
> **R 可由 Manifest 規則解決、剩下的那一層可由呼叫圖解決到約 0.80、A 仍然無解。**
>
> **必須一併記載的程序瑕疵**：這條規則的設計過程接觸了 Gold 的 positive 側
> （規格 §0），與本專題其他每一份規格的「先凍結再量」順序相反。
> 緩解與對照見規格 §0、§7.3——設計時看過的 2 顆 APK 貢獻 0 筆 Gold negative，
> 而 negative 側是全部判別困難的所在。

> **2026-09-25 更新（早期 I 判定重審完成）**：同一次一致性檢查也發現第 1–226 筆與第 227 筆之後的 I 判定標準不同。依 `docs/golden_revision_i_convention_plan.md` 重審 46 筆後，Gold 由 positive 58／negative 302／unknown 25 變為 **positive 84／negative 265／unknown 36**（二分類 349）。R 判定未變，可達性規則仍為 384／384。外部可達（R confirmed）的 129 筆中，positive 84、negative 21、unknown 24；那 21 筆 negative 由 I（13 筆）或 S（10 筆）否定，全部屬於程式碼層級，Manifest 語意無法判定，本 ADR 的主張因此更明確。重審後 Gold 內部無矛盾，且每筆 label 都可由 R/I/S/A 唯一推導。

## 決策

- 研究主軸改為兩部分：（1）以 R/I/S/A 定義並人工建立 Gold 授權標籤的評估框架；（2）以 Gold 量化「自動化越權風險偵測的難點在哪」，即 Manifest 層級（R）與程式碼層級（I 與 S linkage 合併）各自能被現有自動化證據解決到什麼程度。因審查會在第一個被否定的 predicate 停止，I 與 S 不分開計算瓶頸。
- R 由確定性的可達性規則（`app/tools/r_gate.py`）在最前面判定，依 `docs/authz_annotation_guide.md` Step 1 只在 Manifest 語意確定時給 confirmed／refuted，其餘為 unknown；R refuted 的候選 early-stop，unknown 不視為 negative。判定順序維持 R → I → S → A。
- 可達性規則使用的 exported、permission、protection level 等欄位，仍依 `authz_label_spec.md` §8.3 不得進入模型 feature，也不參與產生觀測授權標籤。
- Vanilla（M2）與 SLB（M3）降為小規模探索性實驗，定位為「在缺少程式碼層級自動化證據的條件下，模型與 weak-label revision 能做到什麼」。M2 ≈ M3 是可接受且有意義的結果，不視為失敗。
- 評估分兩層：模型單獨評估只用 Gold 中 R confirmed 的二分類 units；整條流程（可達性規則加模型）用 Gold 全部二分類 units，並與洩漏基線及 `exported && !protected` 規則比較。分類指標與排序指標（Precision@K、找到 80% positive 需檢視的筆數）並列報告。
- 重申：Gold 授權標籤不得用於 feature、LF、threshold 或超參數的選擇。任何 feature 的納入或排除必須有 Gold 以外的依據。

## Considered Options

- **採用：評估框架與瓶頸拆解為主軸，SLB 為探索性實驗。** 成果建立在已完成、可稽核的 Gold 與已驗證的可達性規則上，不依賴專題無法完成的程式碼層級（I、S linkage、A）自動化。
- **不採用：照原計畫以 Vanilla／SLB 比較為主要成果。** 模型幾乎只能從自動化特徵學到 S；若 LF 也主要依據 sink，模型會重建 LF，SLB 的 revision 會把 label 往規則推（revision collapse），結論很可能是各模型重疊而無法解讀。
- **暫不採用：補一個最小版 I 分析（method 內追 `getIntent()`／extras 是否流到 sink）。** 工程量中等但準確度不確定；保留為時間允許時的加強項或 future work，不列入本版主線。
  > **2026-10-06**：此項維持不採用，且**不需要**採用——依核准的觸發慣例，I 不要求資料流（見上方修訂第 2 點）。實際補上的是另一件事：控制流可達性（entry method 到 sink method 的呼叫鏈），不追任何資料流。兩者不可混稱。
- **不採用：以可達性規則先篩掉訓練資料。** 會連帶縮減訓練池並牽動其他已定案的範圍決定；改為訓練時使用全部訓練 units，可達性只在判定與評估時由規則處理。

## Consequences

- ADR-0001 的範圍、prediction unit、三層標籤分離與 SLB 不定義越權等決定全部沿用；本決策只取代 `docs/SLB越權偵測實作時程.md` 中「凍結後的研究主張」與後續週次的優先序。
- 時程表新增 2026-09-21 scope reframe 區段作為唯一有效的執行順序；2026-09-04 區段與原 14 週 schedule 保留為歷史紀錄。
- 新的主線工作依序為：Gold 在 safe group 內的 R/I/S/A 一致性檢查；在 Gold 上比較 `exported && !protected`、可達性規則、可達性規則加 sink 類別先驗（先驗不得由 Gold 估計）；量化程式碼層級的瓶頸（I 與 S linkage 合併）；最後才是縮小規模的 M2／M3。
- 先前 feature 討論中以 Gold 分布作為排除 `linkage_status`、強調 `sink_group_id` 的理由，須改以 spec §8.2 與 S 的先驗語意為依據，並在報告中揭露曾檢視 Gold 分布。
- 「模型缺少程式碼層級證據」與「LF 依據 sink 可能被模型重建」從設計漏洞轉為本研究要量化與報告的發現。
- 報告不得宣稱模型能自動判定越權，也不得以 SLB 結果推論 weak-label revision 在具備程式碼層級證據時的效果；也不得以 I／S 各自的 refuted 次數宣稱哪一個是瓶頸。
