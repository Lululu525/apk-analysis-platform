# Golden review session 硬性協議

- Workflow version：`golden-review-session-protocol-v1.1`
- 生效範圍：Claude CLI 對 Golden-50 reviewer packets 的所有新審查與 append
- Label spec：`authz-label-spec-v0.2-meeting-approved`
- Review guide：`authz-annotation-guide-v0.3-ai-assisted-review`

本文件是 Claude CLI 的執行步驟；R/I/S/A 語意仍以 `docs/authz_label_spec.md` 與 `docs/authz_annotation_guide.md` 為準。`app/tools/golden_review_session.py` 是 `dataset/authz_v2/gold_review_log.jsonl` 的唯一允許寫入入口。

## 0. 輸出語言與編碼邊界

- 對人工 reviewer 的標題、證據解釋、風險邊界、限制與操作提示，以繁體中文為主要敘述語言；必要的 Android/security 術語保留英文。
- Component/package/class/method/variable 名稱、method descriptor、code snippet、Manifest/XML attribute、JSON/JSONL key、enum、reason code、schema/version、CLI option、path、URL、hash 與 ID 都是技術 identity，按來源原樣保存，不翻譯、不中文化。
- `gold_review_log.jsonl` 的 keys、enums 與 agent-authored prose values（包括 `reviewer_notes`、`grouping_basis`）固定使用英文。來源中真實存在的非 ASCII／obfuscated identifier 直接以原始 UTF-8 字元保存，例如 `o.灬` 維持 `o.灬`。
- Source code 原文逐字保留。若程式碼本身含非 ASCII class name、comment 或 string literal，那是 evidence，不是敘述語言；不得翻譯、改名或改成 Unicode escape。
- 所有 Markdown、CSV、JSON 與 JSONL 檔案以 UTF-8 讀寫；讀取後出現 Unicode replacement character `U+FFFD` 時立即停止，視為 encoding failure，不進行判定或 append。

完成條件：繁體中文只承載人類敘述；每一個技術 token 與非 ASCII identifier 都逐字對回原始 evidence，JSONL 不含 Claude 撰寫的中文 prose。

## 1. Session 開始閘門

1. 執行：

   ```powershell
   .\.venv\Scripts\python.exe -m app.tools.golden_review_session status
   ```

2. 以輸出的 `review_log_sha256` 作為本次 append 的 `--expected-log-sha256`。每次人工回覆後、append 前都要重新執行 `status`；SHA 改變即停止並回報 concurrent writer。
3. 一個 Claude CLI session 只能處理 `status.session.start` 至 `status.session.end`。每個 session 最多新增 20 個 unique `review_unit_id`；revision 不得混入日常 append。
4. 先確認沒有其他 Claude／agent／人工程序正在寫同一 log。有疑慮即停止，不以推測解除 writer 衝突。
5. 前一個 20 筆 session 的實驗紀錄不存在時，先完成 `close-session`；不得開始下一批。

完成條件：已取得最新 log SHA、唯一 session 範圍與剩餘名額，且沒有其他 writer。

## 2. Claude 證據審查

Claude 先完成全部查核，再向人工 reviewer 提問：

1. 從 verdict-blind `review_units.csv` 與該 unit 的 `packet.json` 取得 identity、Manifest、caller、sink、linkage、input、guard 與 limitation。
2. 每遇到新的 component identity，都要檢查全部同名 Manifest declarations、resolved owner 與 activity-alias。結果寫入 proposal 的 `evidence_checklist`。
3. Packet 有相關反編譯 Java／smali 時必須實際讀取，引用 unit-specific callsite／entry／guard 行；沒有 source 時明確填 `source_review_status=unavailable`，證據不足的 predicate 保留 `unknown`。
4. exported、permission、protected broadcast、target SDK、Manifest merge 或其他平台語意會影響判斷時，查官方 Android 文件或 AOSP 原始碼，填 `platform_semantics_status=verified_primary_source` 與 URL；不需要平台語意時填 `not_needed`。
5. 一次提出完整 R/I/S/A、各自 evidence status、由決策表推導的 label、reason codes、confidence 建議、證據引用與 limitation。畫面上的解釋使用繁體中文；寫入 proposal JSONL 的 `reviewer_notes`／`grouping_basis` 使用英文。Claude 不把 zero finding、缺 XML、工具失敗、XREF／keyword hit 或「未觀察到」當成 negative proof。
6. 不論 derived label 是 positive 或 negative，每一組呈現給人工 reviewer 的畫面都必須附上該 unit 相關的實際原始碼片段（quoted source code，逐字引用行號與內容，而非僅用文字描述或摘要代替）。人工只能核准畫面上實際看得到程式碼的 unit；negative 不得以「元件未 exported，故省略程式碼」為由略過程式碼呈現。

完成條件：每個 unit 都通過 `golden_review_session.validate_proposal` 的 mandatory checklist，且 label 可由 R/I/S/A 唯一推導，且畫面上每個 unit（不分 positive／negative）都附有實際引用的原始碼片段。

## 3. Safe grouping

只有同一 APK、同一 Manifest component identity、同一段程式邏輯且共用關鍵證據的 units 才可分組。Claude 必須：

- 給整組同一個 `safe_group_id` 與 `shared_evidence_fingerprint`；
- 為每一筆保留自己的 `review_unit_id`、callsite 與 `unit_specific_evidence_references`；
- 對每筆保留完整 event，不以「同上」取代 unit-specific evidence；
- 把疑似 positive/negative、Claude 推論衝突、低信心、duplicate/alias、平台語意或 evidence identity 不一致的 unit 展開說明。

完成條件：人工 reviewer 能從畫面看見整組成員、共用證據、每筆 callsite、完整 R/I/S/A、derived label 與 limitation。

## 4. 人工 reviewer 介面

人工 reviewer 每次只需輸入兩個值：

```text
label=<positive|negative|unknown>
confidence=<high|medium|low>
```

Claude 不要求人工填 R/I/S/A、evidence status、reason code、notes、event ID、JSON 或 timestamp。人工回覆只核准 Claude 畫面上明列的單一 unit 或 safe group；不得把一次核准延伸到未列出的 unit。

若人工 label 與 Claude 的 R/I/S/A 決策表不一致，Claude回到證據與 proposal 修正，再請人工重新確認；Claude不得改寫人工給定的 label 來讓驗證通過。

完成條件：人工明確給出 label 與 confidence，且兩者只套用到本次畫面列出的 units。

## 5. 唯一 append 流程

Claude 將 proposal 寫入 session-local JSONL，然後只使用：

```powershell
.\.venv\Scripts\python.exe -m app.tools.golden_review_session append-approved-group `
  --proposals <session-local-proposals.jsonl> `
  --label <人工label> `
  --confidence <人工confidence> `
  --reviewer-id hikaru820 `
  --assistant-id <精確Claude模型與session識別> `
  --expected-log-sha256 <status輸出的SHA-256>
```

此命令會從 reviewer packet 補 identity，將人工 label/confidence 與 Claude proposal 分開記錄，為每個 unit 建立獨立 `gold-review-event-v1`，並以 lock、expected SHA 與 pure-suffix 驗證 append。

Claude 對 `gold_review_log.jsonl` 的直接 Edit、重寫、腳本臨時 append、文字替換或先讀後自行寫入都不屬於本協議。驗證失敗時立即停止並回報；不繞過 guard。

完成條件：命令成功、append 後狀態可重新解析，且新增 events 數等於人工核准的 units 數。

## 6. 第 20 筆終止閘門

當輸出出現 `SESSION_LIMIT_REACHED`，只執行：

```powershell
.\.venv\Scripts\python.exe -m app.tools.golden_review_session close-session
```

`close-session` 只有在累計到 20 筆邊界（或整個 collection 最後不足 20 筆）時才會成功，並以 exclusive create 產生 `docs/golden_review_experiment_log_<start>_<end>.md`。紀錄包含每筆 identity、R/I/S/A、人工 label/confidence、reviewer/assistant provenance、evidence packet、notes、統計、log SHA 與下一個範圍。

命令輸出 `SESSION_TERMINATED` 後，Claude 必須立刻結束目前對話。不得在同一 session 讀取、分析、詢問或 append 下一筆，也不得自動啟動背景 agent。最後只回報完成範圍、實驗紀錄路徑、log SHA 與「請另開新的 Claude CLI session」。下一批由全新的 session 從第 1 節重新開始。

完成條件：實驗紀錄已建立且不可覆寫，目前 Claude CLI session 已停止在批次邊界。

## 7. 下一輪 session 交接 prompt

`close-session` 成功產生實驗紀錄並印出 `SESSION_TERMINATED` 後，Claude 必須在回報「目前 session 已完成」訊息時，一併附上下一輪 session 的完整起始 prompt（供人工直接複製貼上開啟新 Claude CLI session），不得只回報完成範圍、實驗紀錄路徑與 log SHA 而省略此 prompt。

下一輪起始 prompt 固定套用以下樣板；`{next_start}`／`{next_end}` 代入 `close-session` 後重新執行 `status` 所回傳的下一個 session window（`session.start`／`session.end`），`{prev_start}`／`{prev_end}` 代入本次剛完成、已產生實驗紀錄的範圍：

```text
開始第{next_start}-{next_end}筆unit的審查

延續 Golden-50 review。請先讀取並依 docs/agents/golden-review-session.md（workflow v1.1）執行完整流程：

1. 執行 .\.venv\Scripts\python.exe -m app.tools.golden_review_session status 確認目前 log SHA、session 範圍（應為 {next_start}-{next_end}）、剩餘名額，並確認前一批（{prev_start}-{prev_end}）的實驗紀錄 docs/golden_review_experiment_log_{prev_start}_{prev_end}.md 已存在（存在才可開始本批）。
2. 從 output/framework_poc/golden_50_v1/reviewer_packets_v1/review_units.csv 依序取下一批尚未出現在 dataset/authz_v2/gold_review_log.jsonl 的 20 個 review_unit_id（依 CSV 原始順序，排除已審查者）。
3. 依 APK 分組，逐組讀取該 APK 的 packet.json、manifest_evidence（務必檢查 duplicate declaration 與 activity-alias）與反編譯 source（有 source 必須實際讀完，不能只看 keyword hit），需要平台語意時查 developer.android.com 或 AOSP 原始碼一手來源（引用具體 URL/檔案位置，不得只憑記憶推斷）。
4. 每組列出完整 R→I→S→A 推理、evidence 引用、derived label，交給人工 reviewer（hikaru820）確認 label 與 confidence（reviewer 只需回覆這兩個值）。
5. 人工確認後，重新執行 status 取得最新 SHA，再用 app/tools/golden_review_session.py append-approved-group append（同一 component、同一段程式邏輯、共用關鍵證據的多筆才可用 safe_group；不同 component 或決定性證據不同時需逐筆 append）。assistant-id 用本 session 的 claude-sonnet-5/session_<本次session id> 格式。
6. 滿 20 筆觸發 SESSION_LIMIT_REACHED 後立即執行 close-session，產生實驗紀錄後立刻停止，不得繼續分析或 append 下一筆。

其他規範：全程繁體中文敘述、英文/原始 identity 保留技術欄位（gold_review_log.jsonl 的 reviewer_notes/grouping_basis 固定英文 ASCII）；append 前務必再次 status 確認 SHA 未變；未經人工明確核准前不得 append；每組須先完整讀完程式碼與 manifest 才能提出 R/I/S/A，不得以 keyword hit 或工具零結果代替判定；不論 label 為 positive 或 negative，每一組都必須附上該 unit 相關的實際原始碼片段（quoted source code，逐字引用行號與內容）供人工 reviewer 直接審閱，不得只用文字描述或摘要取代程式碼本身。
```

若 `close-session` 前的 `status` 顯示 `dataset_complete: true`（全部 385 個 review units 已審查完畢），則不產生下一輪 prompt，改為回報「全部 review units 已完成審查，不得再開新 review session」。

完成條件：每次 session 終止時，人工都能直接取得下一輪可用的起始 prompt，不需自行重新編寫或回憶樣板細節。
