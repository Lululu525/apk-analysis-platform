# Golden-50 盲化 reviewer evidence packets

`app/tools/golden_review_packets.py` 將已完成的 Golden-50 coordinator artifacts materialize 成 verdict-blind reviewer collection。它不執行 APK、不重新跑 MobSF／FlowDroid、不改 membership、不填 R/I/S/A，也不寫入 `gold_review_log.jsonl`。

## 正式輸出

```text
output/framework_poc/golden_50_v1/reviewer_packets_v1/
  packet_collection_manifest.json
  packet_inventory.csv
  review_units.csv
  PACKET_AUDIT_REPORT.md
  packets/<APK-SHA-256>/
    packet.json
    sources/java/<package-path>.java
    sources/smali/<package-path>.smali   # Java 無法取得時才使用
```

2026-09-08 materialization 結果：

- 50 個 APK packet containers；
- 385 個唯一 review units；
- 384 個 `candidate` units；
- 1 個 `concrete_path` unit；
- 144 份反編譯 source artifacts；
- 0 次 source fetch failure；
- 13 個 APK 在目前 evidence 下沒有可 materialize 的 review unit；
- 4 條缺 Manifest component identity 的 FlowDroid traces 保留在 packet 的 `unlinked_flow_traces`，不進入 `review_units.csv`；
- collection fingerprint：`f7c904b3fbf87bbb882d8c79fd7487fe38d5b3f2be86b2d5f972f6d0b9e46458`。

50 是固定 APK membership，不是必須產生 50 個 verdict。每個 APK 可以有零到多個 review units；不得為湊數建立假的 component/path。

## Evidence 輸入與盲化

允許的輸入：

- frozen Golden membership 的 SHA／package identity；
- SHA 驗證後 neutral APK 的 binary Manifest；
- pilot `sensitive_api_callers.jsonl` 中嚴格 allowlist 投影後的 caller/callee/call-offset/linkage evidence；
- MobSF 4.4.6 `view_source` 提供的反編譯 Java／smali；
- 既有 FlowDroid 2.15.1 XML 中的 source、sink 與 taint path；
- execution ledger 的工具 status／limitation。

禁止輸出的 structured fields：dataset/family/binary labels、真實 source path、`risk_hint`、cluster/selection hints、LF/observed/revised labels、model score/decision 與 Gold label。API key 只存在 request header／程序記憶體；產生完成前會掃描 staging tree，確認 key 未持久化。

Package/component identity 與反編譯 source 是 reviewer 可見 evidence。Source keyword hits 只定位 Intent input、sink method 或 authorization guard 候選，不是 R/I/S/A verdict。

## Review-unit 邊界

- Androguard XREF 即使 caller 就是 lifecycle entry，仍只 materialize 成 `candidate`；沒有完整 entry-to-sink data/control-flow 時不得升格。
- FlowDroid trace 必須能對應 Manifest component、支援的 lifecycle entry，且有 taint path，才 materialize 成 `concrete_path`。
- 缺 component identity 的 sensitive caller／FlowDroid trace只放在 packet limitation，不進入 `review_units.csv`。
- `review_unit_id` 在整個 collection 中必須唯一，每列必須有 Manifest component identity。

## 兩個 neutral input fallback

產生時 Windows security control 無法提供兩個正確 SHA 的 active neutral APK：

- `cdc5a93b...` active copy SHA 為 `059daa35...`，與 frozen SHA 不符；
- `de3ff71d...` active copy SHA 為 `e22ffe0c...`，與 frozen SHA 不符。

產生器拒絕把錯誤 copy 當成 APK evidence，也沒有覆寫、刪除、執行或新增 Defender exclusion。這兩個 packet 改用先前已綁定正確 APK SHA 的 MobSF report、pilot component/caller projection 與 batch provenance，並標記 `fallback_sha_bound_projected_evidence`。Fallback 無法提供 explicit-exported 原值、custom permission declaration、Provider path-permission 細節，因此相應 predicate 必須保留 limitation／unknown，除非其他 packet evidence 足以回答。

## 執行

MobSF source API key 只由環境變數提供：

```powershell
$env:MOBSF_API_KEY = '<existing-local-key>'
.\.venv\Scripts\python.exe -m app.tools.golden_review_packets
Remove-Item Env:MOBSF_API_KEY
```

工具拒絕覆寫既有 `reviewer_packets_v1`。要重建時必須先明確隔離舊 collection、記錄 fingerprint 與原因，再重新執行；不得原地改寫 frozen reviewer input。

## 人工覆核入口

> 2026-09-10 起，新 AI-assisted review event 使用 `authz-annotation-guide-v0.3-ai-assisted-review`；目前 workflow 為 `golden-review-session-protocol-v1.1`。Packet 仍保留產生當時的 v0.2 guide version，並在新 event 以 `packet_guide_version` 追溯。Claude CLI 必須先載入 `docs/agents/golden-review-session.md`，且只可透過 `app/tools/golden_review_session.py` append。人工畫面以繁體中文解釋；technical identifiers、code 與 JSONL 保留英文／來源 identity，非 ASCII identifier 直接使用原始 UTF-8 字元。

1. 先核對 `packet_collection_manifest.json` 與 `PACKET_AUDIT_REPORT.md`。
2. 從 `review_units.csv` 選一列，開啟其 `evidence_packet_reference`。
3. 固定依 R → I → S → A 判斷；predicate result 與 evidence status 分開。
4. `candidate` 若缺 concrete linkage，S 通常是 `unknown`，不能因 XREF 或 source keyword hit 自動 confirmed。
5. 每次人工 decision 只能新增 `gold-review-event-v1`；不得原地覆寫舊 event。

## 審查節奏與嚴謹度守則（2026-09-09 reviewer hikaru820 確認）

Golden-50 review units 數量遠大於 50（385 個），逐一以「R→I→S→A 分開發問」的節奏審查會非常耗時。reviewer 與 assistant 討論後，針對「加速審查」做出以下明確切分：

**可以加速、不影響嚴謹度的做法**：

- 證據明確時，R/I/S/A 的推理與建議可以一次列出供 reviewer 一次確認，不必逐項分開發問。
- 證據薄弱（`component_class_caller`、無 source 可查、`coverage_limitations` 涵蓋 attacker-input/no-entry-to-sink/guard 三項）的 candidate，可以直接快速判 `unknown`，不需要長篇分析——`unknown` 本身就是誠實答案。
- 積極使用 spec 允許的 `safe_grouping`：同一 component identity、同一段程式碼邏輯的多個 candidate 可以一次列出、一次確認分組判斷，但仍須為每個 review unit 建立獨立 review event。

**不得省略、否則會實質降低 gold label 信心的步驟**：

1. **每個新 component 都必須檢查有沒有 duplicate manifest declaration 或 activity-alias**（`manifest_evidence.components` 內同名重複宣告）。這一步成本低（grep 幾秒），但省略後可能產生過度自信、實際上證據不足的 refutation（見 review-unit `39014150...` 的教訓，原始 R=refuted 因未檢查 duplicate declaration 而被 supersede 為 unknown）。
2. **有反編譯 source 可查時，必須實際讀過，確認 entry-to-sink chain 與是否真的用到 attacker-controlled input**，不能只看 XREF/keyword hit 就跳過。省略這步會讓本該有明確 negative（甚至 positive）結論的 candidate 被草率歸類為 unknown，降低資料集的資訊量。
3. **需要 Android 平台語意判斷時（例如 protected broadcast、component exported 語意、manifest merge 行為）必須查證官方一手文件或原始碼，不能憑印象判斷**。本次審查中曾因未查證而暫時得出錯誤結論（`android.permission.BROADCAST_SMS` 語意），經查證 AOSP 原始碼後才確認正確判斷。跳過查證直接下高信心結論，是唯一會讓 gold label 信心「實質」降低的做法。

換句話說：加速的代價不是「證據品質變差」，而是「reviewer 主動把關、即時抓出 assistant 推理錯誤的機會變少」。上述三項因為成本低、風險高，明確排除在加速範圍之外；其餘純粹減少來回輪數或處理明顯薄弱證據的部分，可以加速執行。
