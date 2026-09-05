# Golden annotation 空白模板

依已凍結的 `golden-50-v1` membership 建立：

- `dataset/authz_v2/golden_50_annotations.csv`：50 筆 APK placeholder rows，28 欄，UTF-8 BOM。
- `dataset/authz_v2/gold_review_log.jsonl`：空檔，0 bytes、0 筆 review events。

建立前已驗證 membership CSV fingerprint 與 50 個 SHA 集合 fingerprint；建立後確認 membership 未變更。

## Row 與欄位語意

只從 membership 預填 `membership_id`、`sha256`、`package_name`，另以固定 `row_kind=apk_membership_placeholder` 標示用途。這 50 列不是已建立的 component/path review units，也不是 50 個 Gold verdicts。

尚未建立 evidence packets，因此 `review_unit_id`、`evidence_packet_reference`、`evidence_packet_sha256`、`component_identity_reference`、`method_identity_reference`、`materialization_version` 均留白，不引用其他 calibration APK 的 artifact，也不填入不存在的路徑。`spec_version` 與 `guide_version` 也保留在 schema 中；placeholder 尚不是可覆核 unit，故目前留白，materialize 實際 unit 時必須分別填入 `authz-label-spec-v0.2-meeting-approved` 與 `authz-annotation-guide-v0.2-meeting-approved`，reviewer 開始前須核對。

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

目前 reviewer-facing 檔案 allowlist 為上述 annotation CSV 與空白 review log。CSV 未帶入 observed/revised labels、model score/decision、malware label、dataset/source 欄位或來源路徑，也未帶入 cluster、selection role、distance 或抽樣分數。Package 為使用者允許保留的 APK identity。

**不要把整個 `dataset/authz_v2/` 資料夾提供給 reviewer。** 同目錄的 membership 與 selection metadata 是 coordinator 稽核資料，包含真實來源 reference，不能視為盲化資料包。本次未建立或宣稱已完成 evidence packets；未來 packets 仍須使用中性路徑，清除來源／verdict hints，再填入本模板的 reference 與 fingerprint。

JSONL 目前不寫入初始化 event，避免把模板建立冒充人工覆核。後續每次人工決策新增 event；不得刪除或覆寫先前事件。修訂須引用前一 event、新 evidence fingerprint 與變更理由。CSV 之後只能作指定 `materialization_version` 的 current view，不能成為唯一 provenance。

### Review event schema

`gold_review_log.jsonl` 採 `gold-review-event-v1`：每行是一個完整 JSON object。每個人工覆核 event 必須包含 `event_schema_version`、`review_event_id`、`membership_id`、`sha256`、`review_unit_id`、`row_kind`、`evidence_packet_reference`、`evidence_packet_sha256`、`materialization_version`、`spec_version`、`guide_version`、`reviewer_id`、R/I/S/A 的 predicate result 與 evidence status、`gold_authz_label`、unknown reason 欄位、`reviewer_confidence`、`reviewer_notes` 與 `reviewed_at`。`spec_version` 與 `guide_version` 不得為空，且必須等於該次實際使用版本。

修訂 event 另須包含 `supersedes_review_event_id`、`change_reason` 與 `new_evidence_packet_sha256`；初次 event 的這三欄為 `null`。同一 `review_event_id` 不得重複，log 只能 append。Materializer 以 event 順序及 supersession chain 產生 CSV current view，但不得刪改 JSONL 歷史。

## 初始化驗證

- 50 個 membership IDs／SHA-256／packages 與凍結 membership 逐列相符。
- 16 個人工欄位、6 個尚未建立的 reference／materialization 欄位，以及 2 個待 unit materialization 寫入的版本欄位全部為空。
- 欄位符合明確 allowlist；review log 為 0 bytes。
- Annotation CSV SHA-256：`66beedb08655fdd82483a332f2ac4bc4dc6558739c38c2bfe8acb1bd3e462944`。
- 空白 review log SHA-256：`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。

以上 hashes 描述初始空白版本；未來合法新增 review events 或 materialize CSV 後會改變，不能重新生成空白檔來清除歷史。
