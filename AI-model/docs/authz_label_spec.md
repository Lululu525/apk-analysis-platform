# Android Component-Path Authorization Label Specification

- 文件版本：`authz-label-spec-v0.2-meeting-approved`
- 狀態：依 2026-09-02 會議決策更新；採單一 reviewer 與 50 APK Golden Set
- 適用範圍：`dataset/authz_v2/` 及後續 authorization-risk labeling、Gold review、SLB label revision
- 最後更新：2026-09-02
- 範圍決策：依 [`ADR-0001`](adr/0001-single-target-apk-authorization-risk.md) 採 single-target-APK Component-path risk，不偵測 order-n multi-app chain

## 1. 目的與規範性用語

本規格定義 Android app 內「外部 component 入口是否形成未經有效授權而可觸發敏感能力的疑似路徑」之標註單位、威脅模型、證據要求、標籤語意與版本規則。

本規格的 `positive` 只表示：在本文件限定的靜態分析與人工審查範圍內，某一 component-path 的四項必要條件均獲得足以支持的證據。它不等同於已完成動態 exploit、CVE、惡意程式判定、app 整體有漏洞，亦不代表所有執行環境皆可成功利用。

本文使用下列規範性用語：

- 「必須」：不符合即不得產生該標籤或不得進入該資料集合。
- 「不得」：明確禁止。
- 「應」：原則上必須遵循；偏離時必須留下理由與版本紀錄。
- 「可以」：允許但非必要。

## 2. 威脅模型與研究主張邊界

### 2.1 攻擊者能力

第一版攻擊者為一般、未受信任的第三方 Android app：

- 與目標 app 不同 UID；
- 不具有目標 app 的 signing certificate；
- 不具有 root、ADB、system、privileged app 或 instrumentation 能力；
- 不使用 `sharedUserId` 或其他與目標 app 共享身分的機制；
- 只能透過 Android 正常提供的 IPC／component invocation 介面送入 Intent、Bundle、URI、Binder arguments 或 Provider operations。

若一個案例只有在 root、ADB、system UID、同簽章、shared UID 或使用者手動授予特殊權限後才成立，必須把該前提寫入 evidence；不得直接視為本威脅模型下的 `positive`。

### 2.2 支援的 component 類型

v0.1-draft 同時涵蓋：

- `activity`
- `activity-alias`
- `service`
- `receiver`
- `provider`

動態註冊的 BroadcastReceiver、深度 reflection、native code、無法解析的 dynamic dispatch 等能力可以被記錄，但若現有分析無法回答必要條件，結果必須是 `unknown`／`abstain` 或保留空值，不得以「沒有找到」推論為安全。

### 2.3 Single-target-APK 邊界

- 每次 analysis attempt 只接受一個目標 APK；外部呼叫者是威脅模型中的抽象主體，不要求提供或共同分析第二個 APK。
- Candidate/path 必須位於目標 APK 內，從可由正常 Android IPC 到達的 Component entry 連到目標 App 所執行的敏感效果。
- 本版不建立跨 APK escalation graph，也不偵測 El-Zawawy 與 Hamdy 所定義的 order-n multi-app escalation chain。
- 「單一目標 APK」不表示忽略 privilege boundary；越權風險仍以不同 UID 的外部呼叫者借用目標 App 權限或敏感能力為前提。

### 2.4 不在標籤內的主張

下列概念不得混入 authorization label：

- APK 是否為 malware／benign；
- MalDroid family；
- app 整體風險分數；
- sensitive API 是否曾出現在任意 caller；
- component 是否單純 `exported`；
- 是否存在 `risk_hint` 或 allowlist match；
- 動態 exploit 是否已被證實。

## 3. 標註單位與識別碼

### 3.1 三種不同記錄

本資料流程必須區分三種記錄，不得混稱為 component-path row：

1. **Analysis attempt**：對一個 APK 執行 parser 或 analyzer 的嘗試。若 APK 解析失敗，只能產生 analysis-attempt／APK-shell 記錄，不得憑空產生 candidate 或 path。
2. **Candidate row**：已知某個 Manifest component、caller、sink 或其他 evidence 組合值得審查，但尚未建立完整 entry-to-sink chain。必須有 `candidate_id`，`path_id` 為空。
3. **Concrete component-path row**：已有具體的 Manifest component identity、lifecycle entry、caller-to-sink callsite chain 與 authz-distinct path variant。必須同時有 `candidate_id` 與 `path_id`。

目前 `pilot_300_six_strata_seed_20260823_v3` 的 `manifest_resolution_candidate`、`component_filter_row` 與大多數 `sensitive_api_caller` 只足以形成 candidate evidence；除非另有可稽核 call graph／data-flow 證據，否則不得改稱為已確認的 concrete path。

### 3.2 真正 component-path row 的 identity

一筆 concrete component-path row 的最小 identity 為：

```text
APK SHA-256
+ Manifest component identity
+ resolved code owner（activity-alias 時與 Manifest identity 分開）
+ lifecycle entry method
+ sensitive sink callsite
+ authorization-distinct path variant
```

其中：

- `apk_sha256` 必須是 64 位小寫十六進位 SHA-256，並可追溯到 canonical membership。
- `manifest_component_name` 必須保留 Manifest 中的外部 identity。
- `resolved_component_owner` 是實際承載 lifecycle code 的 class；`activity-alias` 不得用 target activity 覆蓋 alias identity。
- `entry_method` 必須包含 class、method 與 descriptor；只有 method name 不足以唯一識別 overload。
- `sink_callsite` 必須至少包含 callee class、callee method、caller method 與 call offset；若工具無法提供 offset，必須記錄替代定位資訊與 limitation code。
- `authz_path_variant` 用於區分同一 entry/sink 間具有不同 guard、不同 Provider operation、不同 URI path 或不同 Binder transaction 的路徑。

建議 `candidate_id` 與 `path_id` 由上述 canonicalized identity 產生 deterministic digest；若 canonicalization 規則改變，必須升版，不得靜默重算並覆蓋既有 ID。

### 3.3 一列不得合併的情況

下列情況必須分列：

- 同一 component 的不同 lifecycle entry；
- 同一 entry 的不同 sensitive sink callsite；
- 同一 sink 前存在 authz 結果不同的 guard branch；
- Provider 的 `query`、`insert`、`update`、`delete`、`openFile`、`call`；
- Provider read permission、write permission、path permission 或 URI grant 語意不同；
- Service 的 `onBind` 與 `onStartCommand`，以及不同 returned Binder method；
- activity-alias 的不同 alias identity，即使 target activity 相同。

## 4. 每筆 row 的必要證據欄位

一筆可審查的 candidate/path row 必須能表示下列資訊；欄位可以分散於 normalized evidence records，但 materialized review view 必須可直接追溯：

| 類別 | 必要內容 |
| --- | --- |
| APK identity | `apk_sha256`、canonical membership reference、package name（若解析成功） |
| Manifest component | component type、Manifest name、resolved owner、exported 宣告／推導方式、intent filter、component permission、app permission、Provider permission 與 URI grant evidence |
| External reachability | 呼叫方式、平台/target SDK 語意、caller 所需 permission、任何使一般第三方 app 無法到達的 blocker |
| Lifecycle entry | entry class、method、descriptor；Service Binder／Provider operation 等次入口 |
| Attacker input | Intent/Bundle/data URI/extras/Binder/Provider arguments 的來源與 influence evidence |
| Caller/sink | caller identity、sensitive callee、call offset、group/description，以及 entry-to-caller-to-sink linkage |
| Authorization guard | Manifest guard、runtime UID/signature/package/permission check、guard location、支配關係、是否覆蓋敏感 branch、可否繞過 |
| Four predicates | `R_external_reachability`、`I_attacker_input`、`S_sensitive_effect`、`A_authorization_failure` 的結論與 evidence status |
| Labels | `observed_authz_label`、`gold_authz_label`、`revised_authz_label`，各自 provenance/version |
| Uncertainty | namespace-specific reason codes、unsupported edges、analysis coverage、review status |
| Audit | evidence references、tool/schema version、review event IDs、timestamps |

`binary_label`、MalDroid family／`original_label` 與 `source_dataset` 只可存在於非盲審 metadata view；不得放入 reviewer evidence packet，也不得參與 authorization label 的證據判定。

## 5. 四項判定條件（R/I/S/A）

### 5.1 Predicate 定義

每筆 candidate/path 以四個 predicate 判斷：

| 代號 | Predicate | `confirmed` 的意義 | `refuted` 的意義 |
| --- | --- | --- | --- |
| R | External reachability | 本威脅模型中的第三方 app 可到達該 Manifest component/entry | 有具體且有效的 reachability blocker，第三方 app 不可到達 |
| I | Attacker-controlled input influence | 外部輸入可影響通往敏感效果的參數、receiver state 或控制流程 | 已證明敏感效果不受外部輸入影響，或輸入在到達前被可靠固定／拒絕 |
| S | Sensitive effect reachability | entry 可沿具體支援的 chain 到達該 sensitive sink/effect | 已證明該 entry/branch 不可到達敏感效果 |
| A | Authorization failure | 在敏感效果前沒有有效且不可繞過的 authorization guard | 已確認存在適用、有效、支配敏感 branch 且不可由攻擊者繞過的 guard |

每個 predicate 的 `predicate_result` 僅可為：

```text
confirmed | refuted | unknown
```

### 5.2 Evidence status 不等於 predicate result

每個 predicate 還必須有獨立的 `evidence_status`；允許值如下：

```text
confirmed_present
confirmed_absent
observed_unresolved
not_observed
not_analyzed
analysis_failed
not_applicable
not_reviewed_after_decisive_blocker
not_analyzed_due_to_upstream_unknown
```

關鍵差異：

- `confirmed_absent`：分析範圍與證據足以支持「不存在」。
- `not_observed`：在已執行的有限分析中沒有看到，不能推論不存在。
- `not_analyzed`：尚未執行相應分析。
- `analysis_failed`：已嘗試但工具失敗／逾時／無法解析。
- `observed_unresolved`：看到可能相關的構造，但無法判斷其語意或支配關係。
- `not_reviewed_after_decisive_blocker`：已出現足以給 negative 的 blocker，依 early-stop 未審查後續 predicate。
- `not_analyzed_due_to_upstream_unknown`：上游 coverage limitation 已使答案不可判定，未繼續成本較高的分析。

不得把 `null` 同時用來表示上述所有情況。

### 5.3 Guard presence 與 guard effectiveness 必須分離

看到 permission 或 runtime check 只表示 `guard_presence=confirmed_present`，不代表 `A=refuted`。要判定 guard 有效，至少必須確認：

- guard 適用於本威脅模型的 caller；
- permission protection level／signature 關係已解析，而非只看到 permission name；
- runtime check 發生於 sensitive effect 前；
- guard 支配該敏感 branch，所有相關 path 都不能繞過；
- check 使用的 UID、package、signature、permission 或 token 確實對應 caller authorization；
- catch/fallback/default branch 不會在拒絕後仍執行 sensitive effect。

因此 `permission != null`、現有 `protected=true` 或 `callee_permission` 有值都只能作為待查 evidence，不可單獨產生 negative。

## 6. 互斥標籤規則

### 6.1 Gold label 的決策表

在 R/I/S/A 均依本規格審查後：

| 條件 | `gold_authz_label` |
| --- | --- |
| R、I、S、A 全部為 `confirmed` | `positive` |
| R、I、S、A 任一為 `refuted`，且 refutation 有可稽核證據 | `negative` |
| 無 predicate 被可靠 refute，但至少一項為 `unknown` | `unknown` |

三類互斥：一筆 gold row 在同一個 review event 中只能有一個 current decision。

### 6.2 Positive 的必要證據

`positive` 必須同時具備：

1. R：外部可達證據；
2. I：攻擊者輸入可影響敏感效果的證據；
3. S：entry-to-sink 的具體 linkage／reachability 證據；
4. A：Manifest 與 runtime authorization guard 均已在相應 coverage 下確認缺失、無效或可繞過。

只要其中一項未知，就不得標成 positive。`exported && !protected`、`risk_hint`、allowlist match 或 direct lifecycle caller 即使同時出現，仍不足以替代四項條件。

### 6.3 Negative 的必要證據

`negative` 必須至少有一項被具體證據 `refuted`，例如：

- 依 target SDK、Manifest 與 permission semantics 確認外部 caller 不可到達；
- 確認 signature-level／同簽章 permission 有效阻擋本威脅模型 caller；
- 確認 runtime UID/signature/permission check 支配所有相關敏感 branch；
- 確認 entry 無法到達該 sink；
- 確認 attacker input 不可能影響該敏感效果。

「找不到 caller」、「沒有 allowlist match」、「沒有觀察到 sink」、「parser 失敗」或「現有工具不支援」都不是 negative evidence。

### 6.4 Unknown／Abstain 的必要條件

當沒有可靠 refutation，但又無法同時確認 R/I/S/A 時，human gold 必須使用 `unknown`；weak LF 或 model 則使用 `abstain`。常見原因包括：

- parser／DEX／XREF 失敗或逾時；
- 只有 component-class match，沒有 lifecycle/linkage；
- 無 caller、無 sink 或無 guard 只代表未觀察到；
- reflection、native、dynamic dispatch 或 callback edge 未解析；
- attacker-controlled input influence 未分析；
- permission protection level、URI grant、Binder transaction 或 runtime check 語意未解；
- reviewer 在可用 evidence 下仍不能判定；
- 補充 review 或未來的獨立 validation 仍無法解決。

### 6.5 Early-stop

- Positive 不可 early-stop；四項均須確認。
- Negative 可在第一個 decisive refutation 後停止；未檢查欄位標為 `not_reviewed_after_decisive_blocker`，不得假裝已確認。
- Unknown 可在 decisive coverage limitation 後停止；後續欄位標為 `not_analyzed_due_to_upstream_unknown`。

## 7. 三層標籤與不可覆寫規則

### 7.1 欄位語意

| 欄位 | 允許值 | 產生者 | 用途 |
| --- | --- | --- | --- |
| `observed_authz_label` | `positive`、`negative`、`abstain`、空值 | weak-label aggregation／規則流程 | 原始 noisy/weak observation |
| `gold_authz_label` | `positive`、`negative`、`unknown`、空值 | 指定 reviewer 依 R/I/S/A 人工覆核 | 人工 evidence reference |
| `slb_partition` | `D_c`、`D_n`、空值 | SLB Data Split | 記錄 clean/suspect partition；`D_n` 不等於已確認錯標 |
| `slb_proposed_label` | `positive`、`negative`、空值 | SLB EMA／revision logic | 候選修訂，不是 Gold |
| `revision_applied` | `true`、`false`、空值 | SLB revision pipeline | 是否實際套用修訂 |
| `revised_authz_label` | `positive`、`negative`、空值 | SLB／後續 revision algorithm | 模型修訂結果 |
| `model_decision` | `positive`、`negative`、`abstain` | final predictor | 推論輸出，與 revised label 分開 |
| `revision_epoch` | 非負整數或空值 | SLB revision pipeline | 實際修訂發生的 epoch |

空值表示該階段尚未產生決策，不等於 `unknown` 或 `abstain`。

### 7.2 Append-only provenance

上述三欄不得互相覆寫；任何 label change 必須新增 event：

- manual review event；
- observed-label aggregation event；
- SLB revision event；
- model decision event。

例如原 manual review 是 `unknown`，補足 evidence 後決定 `negative`：必須保留原 `unknown` event，再新增一筆引用新 evidence 的 `negative` review event。不得把原 event 原地改成 negative。

CSV 只可作為某一 `materialization_version` 的 current view；append-only JSONL／event store 才是審計來源，CSV 不得成為唯一 provenance。

## 8. Metadata、weak evidence 與禁止洩漏

### 8.1 只能作 metadata/subgroup analysis

下列欄位只能作抽樣、來源追蹤與 subgroup analysis：

```text
binary_label
original_label / MalDroid family
source_dataset
```

它們不得：

- 直接或間接計算 observed/gold/revised authorization labels；
- 提供給盲審 reviewer；
- 進入 strict authz model features；
- 用來填補缺失的 R/I/S/A evidence。

### 8.2 只能作 weak evidence

下列信號無論單獨或組合，都不得被宣稱為 gold proof：

```text
exported && !protected
risk_hint
sensitive allowlist match
permission == null
protected == true
launcher-only
XREF caller match
direct lifecycle method identity match
```

它們可以觸發候選抽樣、LF vote 或 reviewer 深查，但 LF 必須能 `abstain`，且需保留 reason/evidence reference。

### 8.3 `anti_leakage_feature_profile`

Vanilla 與 SLB 正式比較共用同一份、包含多個輸入欄位的 feature allowlist；這是 feature profile 名稱，不是單一模型參數。實際欄位須在 configuration lock 前逐欄稽核 provenance。

正式模型不得納入：

- observed／gold／revised labels、SLB proposal/partition、model decision 或人工 R/I/S/A verdict；
- `exported`、`protected`、`permission_<NONE>` 及其直接衍生 weak-rule proxies；
- APK filename、SHA-256、package/source path、cluster ID、selection role 或 Golden membership；
- `risk_hint`、finding ID/severity、人工 notes 或任何直接表達漏洞結論的欄位。

在人工覆核前由 parser、MobSF 或 FlowDroid 自動產生的 raw structural／call-flow／input-to-sink／guard evidence，可以經 provenance 與 proxy audit 後列入。R0 與既有 leakage RF 只作 rule-reconstruction diagnostic，不列為正式 authorization-risk classifier 結果。

## 9. Reason-code namespaces

不同階段的原因不可共用一個模糊 `reason` 欄位：

### 9.1 `analysis_status_code`

```text
analysis_success
parse_invalid_bytecode
parse_failed
analysis_timeout
dex_unavailable
xref_failed
manifest_unavailable
unsupported_artifact
```

### 9.2 `candidate_limitation_codes`

```text
manifest_only_candidate
no_lifecycle_link
component_class_only_link
no_entry_to_sink_chain
attacker_input_not_analyzed
runtime_guard_not_analyzed
guard_effectiveness_unresolved
permission_semantics_unresolved
reflection_edge_unresolved
native_edge_unresolved
dynamic_dispatch_unresolved
dynamic_receiver_unsupported_v1
binder_method_unresolved
provider_uri_grant_unresolved
callsite_location_unavailable
```

### 9.3 `lf_abstain_reason_codes`

LF 使用 `abstain` 時必須列出適用的 limitation，例如：

```text
lf_missing_required_evidence
lf_conflicting_weak_signals
lf_out_of_scope_component
lf_analysis_incomplete
```

### 9.4 `gold_unknown_reason_codes`

```text
gold_unknown_parse_failure
gold_unknown_no_concrete_path
gold_unknown_input_influence
gold_unknown_guard_effectiveness
gold_unknown_reflection
gold_unknown_native
gold_unknown_dynamic_dispatch
gold_unknown_permission_semantics
gold_unknown_reviewer_disagreement
gold_unknown_insufficient_evidence
gold_unknown_unsupported_v1
```

多個 code 可並存，但必須另有一個 `primary_gold_unknown_reason` 供統計。

### 9.5 `model_abstain_reason_codes`

```text
model_low_confidence
model_out_of_distribution
model_missing_required_features
model_policy_threshold
```

Human `unknown` 與 LF/model `abstain` 必須分開統計。

## 10. Golden Set、split 與 evaluation 約束

- Golden Set membership 固定為 50 個 APK；50 是 APK 數量，不代表只有 50 個 candidate/path review units。
- 50 APK 從 300-APK pilot 的 297 個 parse-success APK 中，以 clustering 後的跨群集分層選樣建立；clustering 只用於增加情境涵蓋，不傳播或產生 label。
- Clustering 固定使用 10 個結構／coverage features：`log1p(activity_count)`、`log1p(service_count)`、`log1p(provider_count)`、`log1p(receiver_count)`、`log1p(component_evidence_row_count)`、`log1p(unique_exported_component_name_count)`、`log1p(sensitive_api_call_site_count)`、`log1p(sensitive_api_caller_count)`、`direct_component_ratio`、`direct_entry_ratio`。先以 `StandardScaler` 標準化，再執行 KMeans；不得納入 label、weak-rule proxy、APK identity 或 malware metadata。
- 指定 reviewer 依 R/I/S/A 覆核 Golden APK 內的 candidate/path units，建立 `gold_authz_label`。MobSF、FlowDroid、LF 或模型輸出都只能提供候選 evidence，不能直接產生 Gold。
- Golden Set 完全排除於 Vanilla／SLB training、SLB clean/noisy split、pseudo-label、EMA 與 Continuous Revision；不強制在 Golden rows 產生 `revised_authz_label`。
- 先以 exact SHA-256 去重，再建立 package/version/lineage group，以 group 為單位隔離，最後才展開 candidate/path rows。禁止 row-level split。
- 相同 SHA-256、package 或已知 lineage 不得跨 Golden／training。Golden membership 仍固定 50 APK；其 sibling 從 weak-training candidate pool 排除，因此原 247 APK 是訓練上限，不是保證的最終數量。
- Golden label 不得用於 feature、epoch、threshold、model 或 hyperparameter selection。正式 evaluation 前必須建立 configuration lock；因 bug 重跑時保留舊結果並記錄理由。
- 本版只有一個 Golden Set，不另建 development、representative sealed 與 challenge sealed 三組資料。這是人力與時程下的明確範圍限制，不得宣稱等同大型獨立 final test。

## 11. Coverage 與評估

至少分開報告：

- parse coverage；
- candidate-generation coverage；
- annotation coverage；
- LF coverage 與 abstention rate；
- model prediction coverage 與 abstention rate；
- unknown reason distribution；
- confusion matrix 原始 counts；
- positive／negative precision、recall 與 F1；
- Macro F1（主要指標）與 balanced accuracy（輔助指標）；
- `observed_authz_label`、Vanilla `model_decision`、SLB `model_decision` 對同一 Golden binary subset 的結果；
- Golden APK count、review-unit count、positive／negative／unknown count 與 binary evaluation coverage；
- 3 個固定 seeds（20260823、20260824、20260825）的逐次結果、mean、standard deviation 與 paired difference；
- SLB revision count、direction、epoch 與 provenance；不把未經人工驗證的 individual revisions 宣稱為正確。

Human `unknown` 不轉成 negative，也不進入 binary metrics；另外報告數量、比例與原因。任何 F1 都必須與相應 coverage 及原始 counts 一起解讀。

## 12. 版本、凍結與變更控制

目前狀態為 `v0.2-meeting-approved`：

1. 先完成 MobSF／FlowDroid 工具 PoC 與 6 APK baseline-vs-assisted benchmark；
2. 以 KMeans `K=17`、seed `20260823`、`n_init=50` 進行 Golden APK 候選 clustering，並以 `K=15/17/20` 做敏感度檢查；
3. 凍結 50 APK Golden membership、reviewer-visible evidence packet 與盲化欄位；
4. 指定 reviewer 依 R/I/S/A 建立 positive／negative／unknown Gold；
5. 凍結 `anti_leakage_feature_profile` 與 Vanilla／SLB configuration 後，才執行正式 3-seed evaluation。

凍結後的語意變更必須：

- 建立新 spec/guide version；
- 保留舊版；
- 提供 migration ledger；
- 標出需重審的 affected rows；
- 不得原地覆蓋舊 label events。

## 13. 本版明確不做

- 不把 2,262 個 exported rows 直接標成 positive。
- 不把 4 個無 sensitive allowlist match 的 APK 標成 negative。
- 不對全部 25,358 APK 執行目前的完整 DEX/XREF 流程。
- 不把 v3 pilot candidate 稱為已驗證的 concrete path。
- 不增加第二位 reviewer、第二組 gold dataset 或第二篇 uncertainty-weighting 方法。
- 不把 Golden Set 放入 Vanilla／SLB training 或 SLB revision。
- 不宣稱 247 APK weak-training pool 上的 individual `revised_authz_label` 已全部人工驗證。
- 不上傳或分享 APK/DEX，不調整 Windows Defender；raw artifact transfer protocol 目前為 `deferred_unresolved`，另案定義。
