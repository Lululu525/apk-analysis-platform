# Golden 修訂計畫：早期 I 判定依 2026-09-19 慣例重審

- 建立日期：2026-09-22
- 範圍凍結時的 review log SHA-256：`763593dc7f893cbe9c03062604af9d0a80447c38804d93f7bf3cb301fa56f921`
- 依據：`docs/authz_annotation_guide.md` Step 2 的「外部觸發本身屬於控制流影響」釐清
- 寫入方式：`golden_review_session.py append-revision`（`docs/agents/golden-review-session.md` §5.1）

## 為什麼要重審

2026-09-19 的 Golden review 第 261–280 筆 session 中，reviewer 核准了 I 的判定慣例：外部 caller 的啟動或廣播這個動作本身會讓 sink 執行時，算 I=confirmed（控制流），不需要攻擊者資料流入 sink 參數。第 227 筆之後的 event 依此判定；更早的 event 用的是字面讀法（沒有 Intent 資料流入就判 I=refuted）。當時決定不回頭修。

2026-09-21 改採 ADR-0002 之後，Gold 授權標籤本身成為研究主要成果，標準前後不一致會直接影響結論。Gold 一致性檢查也顯示兩段落差很大：

| | unit 數 | I refuted | 其中 R 未被否定 |
|---|---:|---:|---:|
| 第 1–226 筆 | 226 | 52 | 46 |
| 第 227 筆之後 | 159 | 6 | 6 |

因此於 2026-09-22 決定重審第 1–226 筆中，I=refuted 且 R 未被否定的 46 筆。R 已被否定的 6 筆，不論 I 怎麼判都是 negative，不在範圍內。

## 預期影響

重審不代表每筆都會改變。慣例本身也規定：sink 實際上無法由任何外部觸發到達時，仍判 I=refuted。

- 46 筆目前全部是 negative。
- R=unknown 的 9 筆（`com.uniplugin.sender.AReceiver` 3 筆、`eu.evandorostech.droider.BPrelon` 6 筆）：即使 I 改判 confirmed，label 最多變成 unknown，不會變成 positive。
- S 已被否定的 3 筆（`…d014c1a3756f`、`…50947f49237a`、`…d14b49fe20c9`）：不論 I 怎麼判仍是 negative，重審只是讓 I 欄位一致。
- 其餘 34 筆：依重新讀碼的結果，可能維持 negative，或變成 positive／unknown。

Gold 的統計數字（positive 58、negative 302、二分類 360）在重審完成後會改變；所有依賴 Gold 的分析，都要等三批全部完成後再計算。可達性規則的驗收不受影響，因為這次重審不改 R。

## 批次

依 APK 分組，同一個 component 不拆到不同批次。每批一個新的 Claude session，單批不超過 20 筆，比照日常審查的 session 上限。

| 批次 | unit 清單 | 筆數 | APK |
| --- | --- | ---: | --- |
| A | `docs/golden_revision_i_convention_batch_A.units` | 19 | `05271388` jp.bravo.honda、`1092263f` de.nico.asura、`223f9bd3` com.security.service、`2a86208f` com.opgermany.iqtest、`335f0260` ru.zveryatki.stado、`340a131b` com.kandian.ustvapp |
| B | `docs/golden_revision_i_convention_batch_B.units` | 19 | `37582c51` com.note.donote、`37e4cf5a` com.beauty.jw、`43cf3d7a` eu.margaritasoft.firstdevelop、`60f5f450` com.adobe.flpview、`73cd2e8a` ru.erofon、`82e4db9b` cn.com.lw.LSD_01_fox |
| C | `docs/golden_revision_i_convention_batch_C.units` | 8 | `98079236` home.solo.launcher.free |

## 每批的流程

1. 執行 `status`，確認 log SHA 與上一批結束時相同，且沒有 lock 檔。
2. 依 APK 分組，逐組讀 `packet.json`、Manifest（重複宣告與 activity-alias）與完整反編譯原始碼；需要平台語意時查一手來源。
3. 每筆重新判定完整 R/I/S/A。R 不重新判定、沿用原值，除非讀碼時發現原 R 有明顯錯誤；發現時要另外列出，不在本批修正。
4. 畫面上逐筆（或依 safe group）列出：原判定、依慣例重新判定的理由、引用的原始碼（附行號）、推導的 label。維持原判定的 unit 也要列出並說明理由。
5. 人工 reviewer 只回覆 label 與 confidence。label 或任一 predicate 有變更的 unit，用 `append-revision` 寫入，並在 `change_reason` 註明「I re-reviewed under the 2026-09-19 trigger convention」。重新判定後 R/I/S/A 與 label 完全不變的 unit 不寫入 event，只記在該批的紀錄裡。
6. 本批結束後執行：

   ```powershell
   .\.venv\Scripts\python.exe -m app.tools.golden_review_session revision-report `
     --units-file <本批實際寫入修訂的 unit 清單> `
     --output docs/golden_revision_i_convention_report_<批次>.md `
     --title "Golden 修訂：I 慣例重審 批次 <批次>"
   ```

   並在同一份紀錄的末尾補上「維持原判定」的 unit 與理由。
7. 本批完成後結束 session，下一批由新 session 從步驟 1 開始。

## 全部完成後

- 重新執行 `python -m app.tools.gold_consistency` 與 `python -m app.tools.r_gate`。
- 更新 ADR-0002、時程表與報告中引用的 Gold 數字。
- 在 guide Step 2 的釐清段落註明重審已完成，並列出三份修訂紀錄的路徑。
