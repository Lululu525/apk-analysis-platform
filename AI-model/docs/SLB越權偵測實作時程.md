# SLB 越權偵測實作時程

- **建立日期**：2026-08-22
- **預定開始日**：2026-08-24
- **主要開發截止日**：2026-11-30
- **資料來源**：MalDroid-2020 與 F-Droid APK
- **Canonical membership authority**：`C:\Users\s1002\Documents\ChatGPT\資料集處理\maldroid_pipeline\outputs\final\canonical_balanced_dataset.csv`

---

## 先看這一段：現在只需要做什麼？

現在**不要先寫 SLB trainer，也不要直接分析全部 25,358 個 APK**。

目前第一個任務只有一個：

> 建立一個唯讀的 canonical dataset consumer，從 `canonical_balanced_dataset.csv` 選出 300 個 APK，逐筆驗證 `source_path` 與 SHA-256，跑一輪小型 pilot，測量解析時間、成功率與可產生的 component/path 證據量。

為什麼要先做 pilot：

1. 我們已經有可信的 APK 母體，但還不知道 `AI-model` 分析一個 APK 實際要多久。
2. 我們不知道 25,358 個 APK 中，有多少能產生可用的 exported component、sensitive sink 與 runtime guard 證據。
3. 沒有這些數字，就無法決定後續應深度分析 2,000、5,000 或全部 APK。
4. SLB 需要的是 component/path-level weak authorization labels，不是 MalDroid 的 benign/non-benign label。

第一週完成後，只要能回答以下問題，就算成功：

- 300 個 APK 有多少成功／失敗？
- 每個 APK 平均與最慢需要多少時間？
- 產生多少 component rows？
- 其中多少是 exported components？
- 有多少敏感 API caller？
- 目前能否把 component entry 與 sensitive API caller 串起來？
- 哪些證據目前仍只能標成 `unknown/abstain`？

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
300 APK pilot
        ↓
全量 Manifest screening
        ↓
選出 2,000～5,000 APK 深度分析子集
        ↓
Component → entry → guard → sink evidence
        ↓
Weak labeling functions
        ↓
observed_authz_label
        ↓
Gold review + package-group split
        ↓
Baseline models
        ↓
SLB Data Split
        ↓
EMA + Continuous Revision
        ↓
revised_authz_label
        ↓
封存的 gold test 最終評估
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
- 定義 reviewer disagreement 的處理方式。
- 定義 label 欄位不可互相覆寫。

交付物：

```text
docs/authz_label_spec.md
docs/authz_annotation_guide.md
```

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

**目標：建立 Gold set**

Gold component-path rows 目標：240～360 筆。

建議來源：

| 類型 | 目標數量 |
| --- | ---: |
| Toy／答案已知 | 40～60 |
| F-Droid real-world | 60～90 |
| MalDroid benign | 40～60 |
| MalDroid non-benign | 60～90 |
| LF disagreement／unknown 補強 | 40～60 |

交付物：

```text
dataset/authz_v2/gold_labels.csv
dataset/authz_v2/gold_review_log.jsonl
dataset/authz_v2/gold_disagreements.csv
```

Gold test 不得參與：

- LF threshold 調整；
- SLB clean/noisy split；
- pseudo-label；
- EMA；
- Continuous Revision；
- model selection。

### Week 8：2026-10-12～2026-10-18

**目標：資料凍結與 package-group split**

切分單位：

```text
package_name / package lineage
```

禁止 row-level split。

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
| R0 | `exported && !protected` exact rule |
| M1 | 現有 leakage Random Forest |
| M2 | Vanilla context-only model |

Feature profiles：

```text
strict_no_rule_features
full_context_features
```

交付物：

```text
dataset/authz_v2/experiments/r0_rule/
dataset/authz_v2/experiments/m1_leakage_rf/
dataset/authz_v2/experiments/m2_context_only/
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
dataset/authz_v2/experiments/m3_slb_context_only/
dataset/authz_v2/label_revision_audit.jsonl
```

注意：Random Forest ensemble 不能稱為 genuine SLB。

### Week 12：2026-11-09～2026-11-15

**目標：正式 Gold test evaluation**

至少比較：

```text
R0
M1
M2
M3
```

有餘裕再加入：

```text
M4：SLB + full-context features
```

至少報告：

- Precision；
- Recall；
- positive F1；
- Macro F1；
- AUPRC；
- confusion matrix；
- 5 random seeds 的 mean ± standard deviation；
- observed label vs gold；
- revised label vs gold；
- SLB 修對與修壞的數量。

### Week 13：2026-11-16～2026-11-22

**目標：錯誤分析與報告**

要完成：

- False positive 案例；
- False negative 案例；
- SLB correct revision 案例；
- SLB harmful revision 案例；
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
5. Gold test 完全隔離。
6. R0／M1／M2／M3 比較。
7. SLB revision audit。

### 可以先刪減

1. 全量 25,358 APK 的 DEX 深度分析。
2. 完整跨方法 taint analysis。
3. 所有 reflection／native-code 支援。
4. M4 full-context ablation。
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

到 2026-10-11 若仍少於：

```text
500 筆可用 weak component-path rows
或
gold positive / negative 任一類少於 40 筆
```

則把成果定位為 pipeline feasibility，不強調模型效能。

### Gate C：Path coverage 太低

若 exported entry → sensitive sink 的可辨識覆蓋率太低：

```text
退回 Manifest + sensitive-caller weak evidence
```

完整 reachability 列入 future work。

### Gate D：Reviewer disagreement 太高

若 gold reviewer 無法一致：

```text
保留 unknown
→ 修 annotation guide
→ 重標 disagreement subset
```

不得為了湊二分類數量而強迫標成 0 或 1。

---

## 八、你本人現在需要做的事情

你目前不需要理解或實作 EMA、Continuous Revision 或神經網路細節。

現在只需要確認並追蹤以下三件事：

1. Canonical CSV 是唯一 APK membership authority。
2. 第一個工程交付物是 300 APK pilot，不是 SLB model。
3. Gold label 必須標在 component/path，不是直接使用 MalDroid benign/non-benign label。

建議第一個開發工作項目寫成：

> 實作唯讀 canonical dataset consumer，依固定 seed 從 F-Droid Benign、MalDroid Benign、Adware、Banking、Riskware、SMS 各抽 50 個 APK；逐筆驗證 source path 與 SHA-256，執行 Manifest/component 與 sensitive API caller pilot，輸出 parse ledger、benchmark 與 coverage summary。不得修改或複製原始 APK，且單筆失敗不得中止整批。

完成這一步後，再根據 pilot 報告決定第二步。現在不需要同時處理整個 14 週計畫。

---

## 九、預估總時間

### 一人負責程式、另一人平行協助 Gold review

```text
12～15 週
```

### 一個人負責全部程式與人工標註

```text
15～18 週
```

### 只完成工程 MVP

```text
6～8 週
```

### 對 25,358 APK 全部做深度 DEX/path analysis

```text
至少 16～22 週，且必須依 300 APK pilot 實測重新估算
```

本 Schedule 採用的建議範圍是：

```text
全量 Manifest screening
+ 2,000～5,000 APK 深度分析子集
+ 240～360 筆 Gold component-path rows
+ Genuine SLB
+ 封存 Gold test
```
