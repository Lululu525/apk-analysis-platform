# Golden annotation 空白模板

依已凍結的 `golden-50-v1` membership 建立：

- `dataset/authz_v2/golden_50_annotations.csv`：50 筆 APK placeholder rows，28 欄，UTF-8 BOM。
- `dataset/authz_v2/gold_review_log.jsonl`：空檔，0 bytes、0 筆 review events。

建立前已驗證 membership CSV fingerprint 與 50 個 SHA 集合 fingerprint；建立後確認 membership 未變更。

## Row 與欄位語意

只從 membership 預填 `membership_id`、`sha256`、`package_name`，另以固定 `row_kind=apk_membership_placeholder` 標示用途。這 50 列不是已建立的 component/path review units，也不是 50 個 Gold verdicts。

此檔仍保留「建立 evidence packets 前」的 50-row placeholder 狀態，因此 `review_unit_id`、`evidence_packet_reference`、`evidence_packet_sha256`、`component_identity_reference`、`method_identity_reference`、`materialization_version`、`spec_version` 與 `guide_version` 仍留白。2026-09-08 已另外產生 `output/framework_poc/golden_50_v1/reviewer_packets_v1/`；實際 review units 位於該集合的 `review_units.csv`，沒有回頭覆寫 placeholder 或建立假的人工 event。Packet 本身固定記錄產生時使用的 `authz-label-spec-v0.2-meeting-approved` 與 `authz-annotation-guide-v0.2-meeting-approved`；採新 AI-assisted workflow append 的 event 另記實際使用的 `authz-annotation-guide-v0.3-ai-assisted-review`、`packet_guide_version` 與 `golden-review-session-protocol-v1.1`，不回頭改寫 packet。

下列 16 個人工欄位全部留白，共 800 個空白 cells：

```text
review_event_id, reviewer_id,
R_predicate_result, R_evidence_status,
I_predicate_result, I_evidence_status,
S_predicate_result, S_evidence_status,
A_predicate_result, A_evidence_status,
gold_authz_label, primary_gold_unknown_reason, gold_unknown_reason_codes,
reviewer_confidence, reviewer_notes, reviewed_at
```

空白表示尚未人工覆核，不代表 `unknown`、`negative`、`abstain` 或已確認的 evidence status。後續依實際 evidence 為每個 APK 建立零到多個 component/path units；不得為維持 50 列而強制產生 unit 或 verdict。

## Reviewer 盲化與 append-only 原則

Reviewer-facing allowlist 已擴充為 `output/framework_poc/golden_50_v1/reviewer_packets_v1/` 內由 `packet_collection_manifest.json` 列出的 packet/source artifacts，以及頂層 `packet_inventory.csv`、`review_units.csv`、`PACKET_AUDIT_REPORT.md`。空白 annotation CSV 與 review log 仍是 coordinator-side frozen human artifacts；開始覆核時由指定流程將 decision 寫成 append-only event，而不是直接把整個 `dataset/authz_v2/` 交給 reviewer。

**不要把整個 `dataset/authz_v2/` 資料夾提供給 reviewer。** 同目錄的 membership 與 selection metadata 是 coordinator 稽核資料，包含真實來源 reference，不能視為盲化資料包。2026-09-08 packet collection 已清除 dataset/family labels、真實 source path、risk hint、cluster/selection hints、weak/model verdict 與 Gold label；詳細生成、fallback 與稽核規則見 `docs/golden_review_packets.md`。

JSONL 目前不寫入初始化 event，避免把模板建立冒充人工覆核。後續每次人工決策新增 event；不得刪除或覆寫先前事件。修訂須引用前一 event、新 evidence fingerprint 與變更理由。CSV 之後只能作指定 `materialization_version` 的 current view，不能成為唯一 provenance。

### Review event schema

`gold_review_log.jsonl` 採 `gold-review-event-v1`：每行是一個完整 JSON object。每個人工覆核 event 必須包含 `event_schema_version`、`review_event_id`、`membership_id`、`sha256`、`review_unit_id`、`row_kind`、`evidence_packet_reference`、`evidence_packet_sha256`、`materialization_version`、`spec_version`、`guide_version`、`reviewer_id`、R/I/S/A 的 predicate result 與 evidence status、`gold_authz_label`、unknown reason 欄位、`reviewer_confidence`、`reviewer_notes` 與 `reviewed_at`。`spec_version` 與 `guide_version` 不得為空，且必須等於該次實際使用版本。AI-assisted event 另須包含 `packet_guide_version`、`review_workflow_version`、`assistant_id`、`assistant_proposal_sha256`、`assistant_proposed_fields` 與 `human_confirmed_fields`；後者固定只列 `gold_authz_label`、`reviewer_confidence`。

新 event 只能透過 `app/tools/golden_review_session.py` append；Claude CLI 的完整 20 筆 session、safe grouping、人工輸入與終止規則見 `docs/agents/golden-review-session.md`。

修訂 event 另須包含 `supersedes_review_event_id`、`change_reason` 與 `new_evidence_packet_sha256`；初次 event 的這三欄為 `null`。同一 `review_event_id` 不得重複，log 只能 append。Materializer 以 event 順序及 supersession chain 產生 CSV current view，但不得刪改 JSONL 歷史。

## 初始化驗證

- 50 個 membership IDs／SHA-256／packages 與凍結 membership 逐列相符。
- 16 個人工欄位、6 個尚未建立的 reference／materialization 欄位，以及 2 個待 unit materialization 寫入的版本欄位全部為空。
- 欄位符合明確 allowlist；review log 為 0 bytes。
- Annotation CSV SHA-256：`66beedb08655fdd82483a332f2ac4bc4dc6558739c38c2bfe8acb1bd3e462944`。
- 空白 review log SHA-256：`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。

以上 hashes 描述初始空白版本；未來合法新增 review events 或 materialize CSV 後會改變，不能重新生成空白檔來清除歷史。
