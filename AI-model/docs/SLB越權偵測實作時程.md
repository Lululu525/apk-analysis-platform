# SLB 越權偵測實作時程

- **建立日期**：2026-08-22
- **最近更新**：2026-09-02
- **預定開始日**：2026-08-24
- **主要開發截止日**：2026-11-30
- **資料來源**：MalDroid-2020 與 F-Droid APK
- **Canonical membership authority**：`C:\Users\s1002\Documents\ChatGPT\資料集處理\maldroid_pipeline\outputs\final\canonical_balanced_dataset.csv`

---

## 先看這一段：現在只需要做什麼？

300 APK 六層 pilot 已完成；現在仍然**不要先寫 SLB trainer，也不要直接分析全部 25,358 個 APK**。

目前第一個任務只有一個：

> 先完成 FlowDroid bounded CLI PoC，再完成 MobSF Docker sidecar PoC，使用固定 6 APK matched-pair benchmark 比較 baseline manual review 與 tool-assisted review；通過後才套用到 50 APK Golden Set。

Pilot 已確認目前 evidence 仍以 Manifest candidate、component row 與 sensitive caller/XREF 為主；尚不足以把所有 candidate 稱為 concrete component path。現階段先凍結語意，原因如下：

1. Positive、negative、unknown/abstain 必須先有互斥且可稽核的 R/I/S/A 證據要求。
2. `exported && !protected`、`risk_hint`、allowlist match 與 direct lifecycle identity 都只能是 weak evidence。
3. `binary_label`／MalDroid family 只能作 metadata 與 subgroup analysis，不能成為 authorization label。
4. `observed_authz_label`、`gold_authz_label`、`revised_authz_label` 必須保留獨立 provenance，不得互相覆寫。
5. Pilot 的 sequential planning estimate 約 31.8 小時，另有 111 秒單 APK 長尾；300 APK sensitive caller JSONL 已約 47.8 MB，現階段不合理直接外推全量 DEX/XREF。

本階段完成後，必須能回答：

- 一筆 analysis attempt、candidate 與 concrete component-path row 如何區分？
- R/I/S/A 各自需要什麼 confirmed/refuted/unknown evidence？
- parser failure、no caller、no guard、reflection/native 如何標記而不誤判 negative？
- 哪些欄位 reviewer 可以看，哪些 weak label／malware metadata 必須盲化？
- 6 APK benchmark 是否證明 MobSF／FlowDroid 能降低人工時間並提供非重複 evidence？
- 50 APK Golden membership、review units 與 append-only review events 如何保持可稽核？

---

## 一、目前已經有什麼

### 1. APK 母體已經整理完成

資料集處理專案已建立：

```text
canonical_balanced_dataset.csv
```

目前包含：

| 項目 | 數量 |
| --- | ---: |
| Canonical APK | 25,358 |
| Unique SHA-256 | 25,358 |
| Benign | 12,679 |
| Non-benign | 12,679 |
| MalDroid-2020 | 16,716 |
| F-Droid | 8,642 |
| Unique packages | 16,057 |

這份 CSV 是後續 APK membership 的唯一依據。不得重新掃描 MalDroid 或 F-Droid 實體資料夾來決定哪些 APK 納入實驗。

### 2. `AI-model` 已經有的能力

- Manifest 與 component 解析。
- `filter_row`、`intent_row`、`resolution_row` 的資料結構雛形。
- `exported`、Manifest permission、Provider permission、URI grant 等欄位。
- 敏感 API 掃描原型，可取得部分 caller class／method。
- 既有 Random Forest 與 F1=1.0 的模型產物。
- Toy APK scenario A–E 與相關回歸測試。

### 3. 既有模型的定位

目前的 label 是：

```python
label = 1 if exported and not protected else 0
```

而模型輸入又包含：

```text
exported
protected
permission
```

因此舊模型保留作為：

```text
M1：label leakage baseline
```

不要刪除或覆蓋它，也不要再把它的 F1=1.0 解讀成真正的越權偵測準確率。

---

## 二、這個專題真正要預測什麼

### 預測單位

第一版以 **component-path row** 為單位：

```text
APK
+ exported component
+ lifecycle entry method
+ authorization guard evidence
+ sensitive sink/reachability evidence
```

### Positive

一筆較可信的 `authz positive` 至少需要證據支持：

1. 外部攻擊者可到達 component；
2. 攻擊者可控制輸入，例如 Intent、Bundle、URI 或 Binder input；
3. 路徑可到達敏感資料或敏感能力；
4. 缺乏有效的 Manifest 或 runtime authorization control。

### Negative

一筆較可信的 `authz negative` 需要證據支持至少一個有效阻擋條件，例如：

- component 不可由外部到達；
- signature-level permission 有效阻擋未授權 caller；
- runtime UID／signature／package check 有效；
- 外部入口無法到達敏感 sink；
- 輸入不可由攻擊者控制。

### Unknown／Abstain

以下情況不得強迫標成 negative：

- reflection；
- native code；
- dynamic dispatch 無法解析；
- 分析逾時或失敗；
- 找不到證據，但也不能證明不存在；
- reviewer 無法達成一致。

---

## 三、MalDroid 與 F-Droid label 要怎麼使用

Canonical CSV 中的：

```text
original_label
binary_label
source_dataset
```

用途是：

- 抽樣分層；
- 資料來源追蹤；
- subgroup analysis；
- 比較 F-Droid、MalDroid benign、MalDroid non-benign 的 authz-risk 分布。

它們不能用來計算：

```text
observed_authz_label
gold_authz_label
```

禁止以下做法：

```python
authz_label = 1 if binary_label == "non_benign" else 0
```

正確資料欄位應分開保存：

```json
{
  "original_maldroid_label": "SMS",
  "malware_binary_label": "non_benign",
  "observed_authz_label": 1,
  "gold_authz_label": null,
  "revised_authz_label": null
}
```

---

## 四、整體工作順序

```text
Canonical CSV consumer
        ↓
300 APK pilot（297 parse-success）
        ↓
FlowDroid CLI PoC → MobSF sidecar PoC
        ↓
6 APK baseline-vs-assisted benchmark
        ↓
Clustering 選出並凍結 50 APK Golden Set
        ↓
指定 reviewer 依 R/I/S/A 建立 Gold
        ↓
Golden lineage isolation → 最多 247 APK weak-training pool
        ↓
Weak labeling functions + observed_authz_label
        ↓
凍結 anti_leakage_feature_profile 與 configuration
        ↓
Vanilla／SLB 各 3 fixed seeds
        ↓
SLB revised_authz_label（training pool only）
        ↓
同一 Golden binary subset 最終評估
```

SLB 位於流程後半段。若前面的 label 與 evidence 尚未建立，先寫 SLB 沒有意義。

---

## 五、14 週 Schedule

### Week 1：2026-08-24～2026-08-30

**目標：Canonical consumer + 300 APK pilot input**

要完成：

- 新增 canonical CSV consumer。
- 不複製、不移動、不修改原始 APK。
- 每筆重新驗證完整 SHA-256。
- 建立 300 APK 分層 pilot：
  - F-Droid Benign：50；
  - MalDroid Benign：50；
  - MalDroid Adware：50；
  - MalDroid Banking：50；
  - MalDroid Riskware：50；
  - MalDroid SMS：50。
- 抽樣必須可重現，保存 random seed 與 selection reason。
- 產出 pilot membership CSV。

交付物：

```text
dataset/authz_v2/pilot_300_membership.csv
dataset/authz_v2/pilot_300_parse_ledger.csv
dataset/authz_v2/pilot_300_summary.json
```

完成條件：

- 300 筆都有 `sample_id`、完整 SHA-256、`source_path`、source、package 與抽樣原因。
- 每筆都有 `sha256_status` 與 `parse_status`。
- 單筆失敗不會中止整批。

### Week 2：2026-08-31～2026-09-06

**目標：跑完 pilot 並取得真實 throughput**

要完成：

- 對 300 APK 執行現有 Manifest／component 分析。
- 執行 sensitive API caller 掃描。
- 記錄每 APK duration、timeout、error code。
- 統計 exported component 與 sensitive caller 數量。
- 估算全量 Manifest 與深度 DEX 分析時間。

交付物：

```text
dataset/authz_v2/pilot_300_features.jsonl
dataset/authz_v2/pilot_300_errors.csv
dataset/authz_v2/pilot_300_benchmark.json
docs/experiments/pilot_300_report.md
```

決策 Gate：

- 若解析成功率過低，先修 parser，不進下一階段。
- 若平均 DEX 分析時間過長，限制深度分析子集，不跑全量 DEX。

### Week 3：2026-09-07～2026-09-13

**目標：凍結 authorization label specification**

要完成：

- 定義 component-path row。
- 定義 positive／negative／unknown。
- 定義 gold evidence 等級。
- 定義指定 reviewer 的 append-only review 與補充 evidence 修訂方式。
- 定義 label 欄位不可互相覆寫。
- 區分 `candidate_id` 與僅供 concrete entry-to-sink chain 使用的 `path_id`。
- 定義 R（reachability）、I（attacker input）、S（sensitive effect）、A（authorization failure）四項 predicate 與 evidence status。
- 依會議決策由指定 reviewer 覆核 50 APK Golden Set；證據不足時保留 unknown，不因沒有第二位 reviewer 而停止。

交付物：

```text
docs/authz_label_spec.md
docs/authz_annotation_guide.md
dataset/authz_v2/golden_50_membership.csv
dataset/authz_v2/golden_50_annotation_template.csv
```

上述兩份 CSV 的 human label、confidence、reason 與 timestamp 欄位建立時必須為空；identity、cluster selection 與 evidence references 可以預填。Reviewer packet 必須隱藏 observed/revised/model verdict。

必須分開保存：

```text
observed_authz_label
gold_authz_label
revised_authz_label
```

### Week 4～5：2026-09-14～2026-09-27

**目標：Weak labeling functions**

第一版完成 6～8 個 LF：

- Manifest exposure；
- strong/signature permission；
- sensitive sink reachable；
- runtime caller guard；
- attacker-controlled input；
- launcher-only hard negative；
- Provider permission／URI grant；
- dynamic exploit evidence（若有）。

每個 LF 必須輸出：

```text
positive / negative / abstain
confidence
reason_code
evidence
```

交付物：

```text
app/labeling/authz_lfs.py
app/labeling/aggregate_votes.py
tests/test_authz_lfs.py
dataset/authz_v2/pilot_300_lf_votes.jsonl
```

### Week 6～7：2026-09-28～2026-10-11

**目標：Component → guard → sensitive sink path MVP**

優先支援固定 lifecycle entry：

| Component | Entry methods |
| --- | --- |
| Activity | `onCreate`、`onNewIntent` |
| Service | `onStartCommand`、`onBind` |
| Receiver | `onReceive` |
| Provider | `query`、`insert`、`update`、`delete`、`openFile`、`call` |

第一版只做有限深度 call graph，不追求完整 program analysis。

交付物：

```text
app/extractors/authz_path_analyzer.py
app/extractors/authz_guard_detector.py
tests/test_authz_path_analyzer.py
dataset/authz_v2/component_paths.jsonl
dataset/authz_v2/path_coverage_summary.json
```

決策 Gate：

- 若 entry-to-sink coverage 太低，研究主張退回 Manifest + sensitive-caller weak evidence。
- 不因找不到路徑而自動標成 negative。

### Week 5～8：2026-09-21～2026-10-18（平行工作）

**目標：建立唯一一組 50 APK Golden Set**

- Golden membership 固定為 50 個 APK，從 300-APK pilot 的 297 個 parse-success APK 以 clustering 後跨群集選樣。
- KMeans 固定 `K=17`、seed `20260823`、`n_init=50`，以 `K=15/17/20` 做敏感度檢查；每群優先選 representative、diverse 與第三候選。
- Clustering 只提高 authorization 情境涵蓋，不傳播 label。每一種典型情境可先覆核約 2～3 筆，但所有實際 Gold 都必須由指定 reviewer 依 R/I/S/A 判定。
- 50 是 APK 數；一個 APK 可包含多個 candidate/path review units。Membership 凍結後，不因工具失敗、沒有 path、unknown 或結果不理想而替換 APK。

交付物：

```text
dataset/authz_v2/golden_50_membership.csv
dataset/authz_v2/golden_50_annotations.csv
dataset/authz_v2/gold_review_log.jsonl
```

Golden Set 僅作獨立評估，不參與：

- LF threshold 調整；
- SLB clean/noisy split；
- pseudo-label；
- EMA；
- Continuous Revision；
- model selection。

正式評估前建立 configuration lock；Golden label 不得用來選 feature、epoch、threshold 或 hyperparameters。Golden Set 不強制產生 `revised_authz_label`。

### Week 8：2026-10-12～2026-10-18

**目標：資料凍結與 package-group split**

切分單位：

```text
exact SHA-256 去重
→ package / version / lineage group
→ group-level split
→ 最後展開 component-path rows
```

禁止 row-level split。相同 SHA-256、package 或已知 lineage 不得跨 Golden／training；signing certificate 只能作 lineage 輔助 evidence。Golden 50 APK 凍結後，其 sibling 從原 247 APK weak-training candidate pool 排除，因此 247 是上限；不得為補訓練數量而隨機拆散 lineage。

交付物：

```text
dataset/authz_v2/split_manifest.csv
dataset/authz_v2/training_rows.jsonl
dataset/authz_v2/dataset_summary.json
```

### Week 9：2026-10-19～2026-10-25

**目標：Baseline experiments**

完成：

| ID | 方法 |
| --- | --- |
| R0 | `exported && !protected` exact rule（leakage diagnostic） |
| M1 | 現有 leakage Random Forest（rule-reconstruction diagnostic） |
| M2 | Vanilla DNN，使用正式 anti-leakage features |

正式 Feature profile 只有一套：

```text
anti_leakage_feature_profile
```

交付物：

```text
dataset/authz_v2/experiments/r0_rule/
dataset/authz_v2/experiments/m1_leakage_rf/
dataset/authz_v2/experiments/m2_vanilla/
```

### Week 10～11：2026-10-26～2026-11-08

**目標：實作 Genuine SLB**

必須包含：

- warm-up epoch prediction history；
- consistency ratio；
- initial clean/noisy split；
- pseudo-label；
- softmax EMA；
- Continuous Revision；
- clean/noisy membership history；
- revised label audit log。

交付物：

```text
app/ml/slb_trainer.py
tests/test_slb_trainer.py
dataset/authz_v2/experiments/m3_slb/
dataset/authz_v2/label_revision_audit.jsonl
```

注意：Random Forest ensemble 不能稱為 genuine SLB。

### Week 12：2026-11-09～2026-11-15

**目標：正式 Golden Set evaluation**

至少比較：

```text
R0
M1
M2
M3
```

至少報告：

- confusion matrix 原始 counts；
- positive／negative precision、recall 與 F1；
- Macro F1（主要指標）與 balanced accuracy（輔助指標）；
- 3 個固定 seeds（20260823、20260824、20260825）的逐次結果、mean、standard deviation 與 Vanilla/SLB paired difference；
- observed label vs gold；
- Vanilla model decision vs gold；
- SLB model decision vs gold；
- parse、candidate、annotation、LF 與 model prediction coverage；
- abstention rate 與 unknown reason distribution；
- Golden APK count、review-unit count與 binary evaluation coverage。

Human unknown 不轉成 negative，也不進入 binary metrics。Golden Set 不參與 revision，因此本版不直接計算 revised-vs-gold 或宣稱 individual revisions 正確；只報 revision count、direction、epoch 與 provenance。任何 F1 都要與 coverage 和原始 counts 一起解讀。

### Week 13：2026-11-16～2026-11-22

**目標：錯誤分析與報告**

要完成：

- False positive 案例；
- False negative 案例；
- SLB revision 行為案例（不得在沒有 Gold 的 training rows 上稱為 correct／harmful）；
- F-Droid／MalDroid subgroup analysis；
- 已知限制；
- 可重現命令與 artifact fingerprint。

### Week 14：2026-11-23～2026-11-30

**目標：Buffer 與成果凍結**

只做：

- 修正 blocking bug；
- 補必要實驗；
- 凍結 dataset fingerprint；
- 凍結 model artifact；
- 整理簡報與口試回答。

不再新增大型功能。

---

## 六、時間不足時怎麼縮小範圍

### 優先保留

1. Canonical membership 與 SHA-256 evidence chain。
2. Component-level／path-level label semantics。
3. `observed / gold / revised` 三層標籤。
4. Package-group split。
5. 50 APK Golden Set 完全排除於 training／revision。
6. R0／M1／M2／M3 比較。
7. SLB revision audit。

### 可以先刪減

1. 全量 25,358 APK 的 DEX 深度分析。
2. 完整跨方法 taint analysis。
3. 所有 reflection／native-code 支援。
4. 第二套 feature profile 或其他 model ablation。
5. 自動化 attacker APK 動態 exploit。
6. 完整 app-level hybrid risk score 整合。

### 最低可交付版本

如果 11 月時間不足，研究主張收斂為：

> 建立一套以 canonical MalDroid/F-Droid APK 母體、可稽核 weak authorization labels、gold-reviewed component paths 與 SLB label revision 為核心的 Android exported-component authorization-risk 可行性驗證流程。

不要宣稱：

- 已完整恢復所有 Android IPC 攻擊路徑；
- revised label 就是 ground truth；
- malware label 可以代表越權 label；
- 現有 F1=1.0 證明真實越權辨識成功。

---

## 七、停止條件（Decision Gates）

### Gate A：Pilot 解析不穩定

若 300 APK pilot 的成功率過低或 timeout 過多：

```text
停止全量分析
→ 先修 parser／checkpoint／timeout
```

### Gate B：可用資料不足

若 50 APK Golden Set 經人工覆核後，binary positive／negative 任一類過少，或原 247 APK weak-training candidate pool 在 package/lineage isolation 後不足以訓練，則把成果定位為 pipeline feasibility，不強調模型效能；不得把 human unknown 強迫轉成 positive／negative。

### Gate C：Path coverage 太低

若 exported entry → sensitive sink 的可辨識覆蓋率太低：

```text
退回 Manifest + sensitive-caller weak evidence
```

完整 reachability 列入 future work。

### Gate D：Reviewer ambiguity 太高

若指定 reviewer 對大量 units 無法取得足夠 R/I/S/A evidence，保留 unknown，先修 evidence schema／工具輸出或 annotation guide；不得為了湊二分類數量而強迫標成 0 或 1。Configuration lock 後不得因 Golden metrics 不理想而回頭挑 feature、threshold 或 model。

---

## 八、你本人現在需要做的事情

你目前不需要理解或實作 EMA、Continuous Revision 或神經網路細節。

現在只需要確認並追蹤以下三件事：

1. Canonical CSV 是唯一 APK membership authority。
2. 300 APK pilot 已完成；下一個工程交付物是 FlowDroid／MobSF bounded PoC 與 6 APK reviewer-workload benchmark。
3. Gold label 必須標在可稽核的 component/path unit，不是直接使用 MalDroid benign/non-benign label。

建議第一個開發工作項目寫成：

> 固定工具版本、設定、toy truth 與 6 APK membership；先完成 FlowDroid CLI PoC，再完成 MobSF Docker sidecar PoC。只有在工具提供可追溯且非重複 evidence、並實際降低人工工作量後，才套用到 50 APK Golden Set。

完成這一步後，再根據 pilot 報告決定第二步。現在不需要同時處理整個 14 週計畫。

---

## 九、範圍與時間重估原則

本 Schedule 不再以前版雙 reviewer、240～360 Gold rows 或 2,000～5,000 APK 深度分析估算作為承諾。正式工期須在 6 APK baseline-vs-assisted benchmark 後，依 MobSF／FlowDroid machine time、failure/timeout rate、每 APK review units 與人工時間重新估算。

本版固定範圍是：

```text
300 APK pilot（已完成；297 parse-success）
+ 50 APK Golden Set（單一指定 reviewer）
+ 最多 247 APK weak-training candidate pool（lineage isolation 後可能更少）
+ 1 個 Vanilla DNN baseline
+ 1 個 Genuine SLB DNN
+ 3 fixed seeds，合計 6 training runs
```
