# Android Authorization Evidence Annotation Guide

- 文件版本：`authz-annotation-guide-v0.2-meeting-approved`
- 依據：`docs/authz_label_spec.md` 的 `authz-label-spec-v0.2-meeting-approved`
- 狀態：供 50 APK Golden Set 單一 reviewer 人工覆核使用
- 最後更新：2026-09-02

## 1. 本指南要回答的問題

Reviewer 不是判斷「這個 APK 是否惡意」，也不是看到 exported component 或 sensitive API 就判斷有漏洞。每一個 annotation unit 只回答：

> 在指定的一般第三方 app 威脅模型下，現有 evidence 是否足以確認該 Manifest component 的特定 entry-to-sensitive-effect candidate/path 同時具備外部可達、攻擊者輸入影響、敏感效果可達，以及缺乏有效 authorization guard？

標註順序固定為 R（reachability）→ I（input）→ S（sensitive effect）→ A（authorization failure）。不得從 `risk_hint`、MalDroid family 或模型輸出倒推答案。

## 2. Reviewer 角色與權限

### 2.1 指定 reviewer

- 本版依會議決策由同一位指定 reviewer 完成 50 APK Golden Set 的人工覆核，不以第二位 reviewer 作為前置條件。
- Reviewer 必須逐一保存 R/I/S/A decision、evidence reference、reason code、confidence、timestamp 與 guide version。
- Reviewer 可以指出欄位不足、reason code 不清楚或 guide 無法處理的分支；證據不足時保留 `unknown`，不得為了補 positive／negative 數量降低標準。
- 若後續取得第二位 reviewer，其結果只能作額外 validation event，不回頭覆寫本版的原始 manual review event。

### 2.2 工具與模型邊界

- MobSF／FlowDroid 可以協助定位 Manifest、source、sink、path 與 guard candidates，降低搜尋時間。
- 工具 finding、risk score、zero finding、LF vote、observed label、revised label 或模型輸出都不能直接決定 `gold_authz_label`。
- Reviewer packet 採 evidence-visible、verdict-blind：可以看原始與正規化工具 evidence，不得看其結論性風險標籤或模型答案。

## 3. Reviewer 可以看與不得看的資料

### 3.1 可以看

- APK SHA-256、package/component identity；
- component type、Manifest attributes、target SDK/platform semantics evidence；
- entry method、caller、sink、call offset；
- caller→entry→sink edge 及其 unsupported/unresolved 標記；
- Intent/Bundle/URI/Binder/Provider input evidence；
- Manifest/runtime guard evidence、location 與 dominance/bypass evidence；
- parser/XREF/call-graph status；
- evidence file、line/reference、schema/tool version；
- 本 spec/guide 的 version 與 reason-code definitions。

### 3.2 不得看

- `binary_label`；
- MalDroid family／`original_label`；
- `source_dataset`，除非只為追查 artifact provenance，且不得顯示 benign/non-benign 語意；
- 會在目錄名或檔名暴露 dataset/family label 的真實 `source_path`；reviewer-facing packet 必須改用中性命名且已驗證 SHA-256 的 `review_apk_path`；
- `risk_hint` 的結論性文字；
- LF votes、aggregate weak label、`observed_authz_label`；
- `revised_authz_label`、model score、model decision；
- 其他 review event 的既有答案（若未來進行獨立 validation）。

Membership／audit manifest 可以保存上述 metadata 供抽樣稽核，但產生 reviewer packet 時必須移除或遮蔽。

## 4. 開始前檢查

對每個 unit 依序確認：

1. `review_unit_id`／`candidate_id` 是否唯一。
2. `apk_sha256` 是否完整，evidence references 是否可開啟。
3. unit 是 `apk_shell`、`candidate` 或 `concrete_path`。
4. `spec_version` 與 `guide_version` 是否就是本次指定版本。
5. 是否有會暴露 malware label、LF/model output 或另一 reviewer decision 的欄位；有則先停止並回報 blinding breach。
6. Evidence 是否屬同一 SHA-256、同一 component/caller/sink identity；若 join 不一致，不自行猜測，記錄 `analysis_failed` 或適用 limitation。

## 5. 固定標註流程

### Step 0：辨認 unit 類型

- `apk_shell`：只用來校準 parser failure、parsed-no-component、complete-zero-allowlist 的處理；不產生 candidate/path label。
- `candidate`：證據不完整，`candidate_id` 有值、`path_id` 為空；仍可練習 R/I/S/A，但通常會因 linkage/input/guard coverage 得到 `unknown`。
- `concrete_path`：只有 evidence 真正建立 entry-to-sink chain 才能填 `path_id`；不可因檔名叫 `manifest_path_evidence` 就視為 concrete path。

### Step 1：R — External reachability

檢查：

- Manifest component identity 與 component type；
- explicit `android:exported` 或依 Android/target SDK 規則推導的值；
- activity-alias 的 alias attributes，而非只看 target activity；
- component/app permission 的 protection level 與 caller 是否可能持有；
- Receiver sender permission、Service binding permission；
- Provider exported/read/write/path permissions、URI grants；
- platform-required、system-only、signature-only 或其他明確 blocker。

判定：

- `confirmed`：有證據支持一般第三方 app 可呼叫指定 entry。
- `refuted`：有證據支持一般第三方 app 被有效且適用的機制阻擋。
- `unknown`：只有 exported/protected boolean、permission name 未解析、SDK semantics 不明或動態註冊狀態不明。

若 R 被可靠 refute，可標 negative 並 early-stop；I/S/A 設為 `not_reviewed_after_decisive_blocker`。

### Step 2：I — Attacker-controlled input influence

檢查外部輸入是否實際影響敏感效果：

- Activity：`Intent` data、extras、deep link parameters、`onNewIntent`；
- Receiver：`onReceive(Context, Intent)` 的 action/data/extras，以及 sender identity；
- Service：`onStartCommand` Intent、`onBind` input、returned Binder methods 的 arguments；
- Provider：URI、projection、selection、selectionArgs、ContentValues、mode、extras/Bundle；
- 是否經 validation、canonicalization、constant replacement、lookup 或 trusted-state gate；
- influence 是資料流、控制流，或兩者皆有。

只看到 entry method 有 Intent/URI 參數，不等於已確認 influence。若 input analysis 未執行，使用 `attacker_input_not_analyzed`，I=`unknown`。

### Step 3：S — Sensitive effect reachability

檢查：

- entry → intermediate caller → sensitive callsite 的每條 edge；
- caller class/method/descriptor 與 call offset；
- lifecycle identity match 是否只是名稱比對；
- component-class-only match 是否缺 entry linkage；
- branch condition 是否讓該 sink 真正可到達；
- callback、Binder、reflection、native 或 dynamic dispatch edge 是否支援。

證據等級由強到弱：

1. 可重現、具 callsite 的 concrete entry-to-sink chain；
2. direct lifecycle method 與 sensitive callsite identity match，但缺完整 branch/data-flow；
3. component-class-only caller；
4. 任意 XREF caller／allowlist match；
5. Manifest-only risk hint。

只有第 1 級在 coverage 與 branch 條件皆足夠時，才可能令 S=`confirmed`。第 2–5 級只能觸發深入審查，不能自行證明 S。

### Step 4：A — Authorization failure

先分開填：

- `manifest_guard_presence`
- `runtime_guard_presence`
- `guard_effectiveness`
- `guard_bypass_status`

再判定 A：

- `confirmed`：相應 Manifest/runtime guard 在足夠 coverage 下確認缺失，或存在但無效／可繞過。
- `refuted`：有效 guard 適用於本 caller，且支配所有相關敏感 branch。
- `unknown`：只看到 permission/check 名稱、未解析 protection level、未證明 dominance、runtime analysis 未做或有 reflection/native gap。

`protected=true`、`permission != null` 或看到 `checkCallingPermission` 名稱都不能單獨令 A=`refuted`。

### Step 5：套用互斥 decision table

```text
R=confirmed AND I=confirmed AND S=confirmed AND A=confirmed
    -> positive

ANY(R,I,S,A)=refuted with sufficient evidence
    -> negative

otherwise
    -> unknown (human) / abstain (LF or model)
```

### Step 6：填 reason、confidence 與 evidence references

- `unknown` 必須填至少一個 `gold_unknown_reason_code`，並選一個 primary reason。
- 所有結論必須引用 evidence reference；不可只寫「看起來像」。
- Reviewer confidence 只能是 metadata，不得把低信心 positive 改叫 unknown，亦不得用高信心補足缺失 evidence。
- Primary dry-run 模板中的 human label/confidence/reason/timestamp 起始必須為空，由 reviewer 親自填入。

## 6. Component-specific checklist

### 6.1 Activity

- Entry：`onCreate`、`onNewIntent`；必要時記錄 deep-link routing method，但不得取代 lifecycle entry identity。
- 分開檢查 explicit Intent、implicit Intent、data URI、extras。
- Launcher filter 只能表示啟動入口的一種線索，不是 hard negative，也不是 positive proof。
- 若 activity-alias 指向 target activity，保留 alias Manifest identity 與 target code owner；不得合併成一個 component name。

### 6.2 BroadcastReceiver

- Entry：`onReceive`。
- 檢查 exported、receiver permission、broadcast sender permission、protected broadcast/platform restrictions。
- `registerReceiver` 動態註冊屬 v1 明確 unsupported branch；沒有在 Manifest 看到 receiver 不表示不存在。
- 若 `goAsync` 或 callback 把工作移出 `onReceive`，必須記錄 unresolved callback edge。

### 6.3 Service

- `onStartCommand` 與 `onBind` 分開標註。
- `onBind` 回傳的 Binder object 不是終點；必須追到具體 Binder method/transaction 與 arguments。
- 只看到 service class 內有 sensitive API，不代表指定 entry 可達。
- 檢查 component permission、bind permission、runtime caller UID/signature checks。

### 6.4 ContentProvider

- `query`、`insert`、`update`、`delete`、`openFile`、`call` 分列。
- 分開檢查 read/write permission、path-permission、`grantUriPermissions`、URI grant flags 與 persisted grants。
- URI 可達不等於 attacker influence 已確認；需說明 URI/arguments 如何影響 sensitive effect。
- 同一 Provider 若不同 URI path 的 guard 不同，必須使用不同 `authz_path_variant`。

## 7. 困難案例的固定處理

### 7.1 Parser failure

- `parse_invalid_bytecode`、timeout 或 Manifest/DEX 解析失敗只產生 `apk_shell`。
- `analysis_status_code` 記錄失敗；candidate/path ID 與所有 labels 留空。
- 不得標 negative；「工具讀不到」不等於「路徑不存在」。

### 7.2 Parsed but no component evidence

- 記錄 parser 成功與 candidate-generation coverage 為 0。
- 未確定是 app 真無支援 component、filter 被排除或 extractor limitation 前，不得標 negative。
- 保持 `apk_shell`，必要時列 `manifest_only_candidate` 或 extractor limitation。

### 7.3 Complete scan but zero allowlist match

- 只表示目前 allowlist/XREF 沒有 match。
- 不得建立「safe」或 negative gold。
- 記錄 LF/candidate coverage；若沒有具體 candidate，labels 留空。

### 7.4 No caller／no lifecycle link

- `unlinked_caller`、component-class-only 或 direct method-name match 都是 linkage evidence 的不同強度。
- 找不到 caller 只能是 `not_observed`／`no_entry_to_sink_chain`，不是 S=`refuted`。
- 若要 S=`refuted`，必須有足以涵蓋相關 dispatch/callback 的分析證明 entry 無法到達 sink。

### 7.5 No guard

- 「沒有在目前 detector 中看到 guard」先填 `not_observed`。
- 只有在 Manifest semantics、runtime check coverage 與 bypass analysis 足夠時，才可填 `confirmed_absent` 並令 A=`confirmed`。

### 7.6 Reflection

- `Class.forName`、`Method.invoke` 等本身是 sensitive/dynamic signal，不等於 authorization failure。
- 若 reflection edge 影響 R/I/S/A 中尚未確認的必要條件，使用 `reflection_edge_unresolved`，通常為 unknown。
- 若在 reflection 之前已存在確定的 reachability blocker，可依 R=`refuted` 給 negative；不必因無關 reflection 強迫 unknown。

### 7.7 Native code

- `System.load`／`loadLibrary` 只證明可能進入 native；不證明指定 native function 的效果或 guard。
- 受影響 predicate 使用 `native_edge_unresolved`。
- Native limitation 只影響相關 candidate，不把整個 APK 全部改成 unknown。

### 7.8 Dynamic dispatch/callback

- 無法解析的 interface dispatch、callback、async task 或 framework edge 使用 `dynamic_dispatch_unresolved`。
- 只有在該 unresolved edge 可能改變最終 R/I/S/A 時才阻止二分類。
- 與結果無關且已有 decisive refutation 時，可以 negative early-stop。

## 8. 50 APK Golden Set review

### 8.1 Membership 與選樣

- Golden membership 固定為 50 個 APK，候選來自 300-APK pilot 的 297 個 parse-success APK。
- 先以不含 labels、weak-rule proxies 或 APK identity 的結構特徵做 clustering，再跨群集分層選樣；目的只是提高情境涵蓋，不作 label propagation。
- 每群優先選 representative、diverse 與第三候選，並盡量維持 package uniqueness。KMeans 固定 `K=17`、seed `20260823`、`n_init=50`，另以 `K=15/17/20` 檢查選樣敏感度。
- 50 是 APK membership 數；每個 APK 可以包含多個 candidate/path review units。所有實際覆核 units 都必須可追溯回 APK SHA-256。
- Membership 凍結後，不因 MobSF／FlowDroid failure、沒有 concrete path、標成 unknown 或結果不符合預期而替換 APK。

### 8.2 工具輔助與 reviewer workload

- MobSF 對 50 APK 提供 static-analysis enrichment、decompiled-code 定位與人工 triage。
- FlowDroid v1 只處理 Activity、Receiver 與 started-Service 中由 Intent／Bundle／URI 進入 Tier-A sensitive effect 的候選 flow；Binder、Provider 與完整 control dependence 延後。
- 工具正式套用 50 APK 前，先用 6 APK（low／medium／high complexity 各一組 matched pair）比較 baseline manual review 與 tool-assisted review；每 APK 固定 2 個 units，分開記錄機器時間與人工時間。
- 工具 finding 只是 evidence candidate。`no_result`、`partial`、`timeout`、`analysis_failed` 與 zero finding 都不得自動變成 negative。

## 9. Golden annotation template

Golden annotation artifact 應包含 identity/evidence/status 欄位，以及下列由指定 reviewer 親填的空白欄：

```text
review_event_id
reviewer_id
R_predicate_result
R_evidence_status
I_predicate_result
I_evidence_status
S_predicate_result
S_evidence_status
A_predicate_result
A_evidence_status
gold_authz_label
primary_gold_unknown_reason
gold_unknown_reason_codes
reviewer_confidence
reviewer_notes
reviewed_at
```

建立模板時，上述 human decision/confidence/reason/timestamp 欄位必須全部為空。Identity 與 evidence references 可以預填；`observed_authz_label`、`revised_authz_label`、model score 與 `model_decision` 不得顯示在 reviewer packet。

## 10. Append-only review 與修訂

- Reviewer 每次 decision 都新增 review event；不得原地覆寫先前的 positive、negative 或 unknown。
- 補足 evidence 後若結論改變，新 event 必須引用前一 event、更新的 evidence fingerprint 與變更理由。
- `gold_authz_label` 只 materialize 指定版本下最新且有效的人工 review event。
- 未來若加入第二位 reviewer，其 decision 與 disagreement 另存，不回寫或刪除原單人 review provenance。

## 11. Golden Set 完成／停止條件

### 11.1 完成條件

- 50 個 APK membership、SHA-256、package/lineage、cluster 與 selection role 已凍結。
- 所有進入人工覆核的 candidate/path units 都有一致 identity 與 evidence references。
- 每個 human label 都能由 R/I/S/A decision table 推導。
- Unknown 有 namespace-specific reason；parser failure、no caller、no guard、reflection/native 與 tool failure 沒有被誤標為 negative。
- 沒有用 malware family、risk_hint、allowlist、exported/unprotected、MobSF finding 或 FlowDroid trace 直接產生 Gold。
- Spec/guide version、evidence packet fingerprint 與 review events 可稽核。

### 11.2 停止條件

- Evidence packet 不足以回答必要條件時，該 unit 保留 unknown；若整體 coverage 不足，停止擴大並回到 evidence schema／工具 PoC。
- 不因 positive／negative 數量不足而更換已凍結 APK、降低 R/I/S/A 標準或把 unknown 強迫轉成二分類。
- Golden Set 完全不參與 Vanilla／SLB training 或 SLB revision；正式 evaluation 前必須另行完成 configuration lock。

## 12. Raw APK/DEX 分享狀態

本 Golden review 流程不授權上傳、不受控複製或公開分享 raw APK/DEX，也不變更 Windows Defender。未來若其他 reviewer 必須取得 raw artifact，需另立安全傳輸、儲存、隔離、權限、checksum、清除與 incident-handling 流程。

目前狀態固定記為：

```text
raw_artifact_transfer_protocol = deferred_unresolved
```

本指南不建議、也不授權在 host 上建立 Defender folder exclusion；該議題不影響本次 spec/guide 與 evidence-only calibration 的完成。
