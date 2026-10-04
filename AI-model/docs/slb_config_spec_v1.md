# M2／M3 訓練與 SLB 設定規格 v1

狀態：**設定全部凍結，6 次正式執行已完成**（2026-10-04）。執行順序第 5c 項（ADR-0002）。
第 1–5 項皆已定案，§7 為實作前的最後校正，§8／§9 為 M2／M3 的執行紀錄。
全部 6 次執行**未讀取 Gold**；與 Gold 的比對是獨立步驟，見 §9.7。

本文件凍結 M2（vanilla MLP）與 M3（MLP + SLB）的全部訓練設定。依
`authz_label_spec.md` §10 與時程表 `:453`，**Gold 授權標籤不得用於選擇 epoch、
threshold 或任何超參數**。

| # | 項目 | 狀態 |
|--:|---|---|
| 1 | Epoch 預算與 early stopping | **已定案**（2026-10-02）`TOTAL_EPOCHS = 100` |
| 1b | Optimizer 與其餘訓練超參數 | **已定案**（2026-10-02）；class weight 於 2026-10-03 改為 CB loss |
| 2 | 兩階段結構與三個 epoch 參數 | **已定案**（2026-10-03）`e=20`、`m=5`、`T=100`。取代原「Warm-up 長度」 |
| 3 | Consistency ratio 的定義 | **已定案**（2026-10-03）依論文 Eq. (3) |
| 4 | Clean／noisy 的切分方式 | **已定案**（2026-10-03）嚴格門檻 `r_i = 1`，依論文 Eq. (4) |
| 5 | Audit log 的欄位（四個產物） | **已定案**（2026-10-04） |
| 6 | 與論文原文的對照與修正紀錄 | **2026-10-03** 新增 |
| 7 | 實作前的最後校正（原文 pseudocode、順序揭露、機械細節） | **2026-10-04** 新增；§2、§5 的敘述有五處由 §7.1 校正 |
| 8 | M2 正式執行（3 seed × 100 epoch） | **已完成**（2026-10-04） |
| 9 | M3 正式執行（3 seed × (20 + 100) epoch） | **已完成**（2026-10-04）；§4.4、§5.5 的預先登記預測有兩處與實測相反 |

> **來源論文**：Alotaibi et al., *Deep Learning from Imperfectly Labeled Malware Data*,
> CCS '25。第 2、3、4 項依原文 Algorithm 1／2 與 Eq. (3)(4)(5)(6)(9) 定案；
> 其中三項推翻了 2026-10-02 的既有決定，新舊對照與「為何這不是先射箭再畫靶」見 §6。

## 0. 程序：事先登記的是規則，不是數字

本文件的每一項都必須在執行之前 commit。**規則先凍結，數字之後才由規則機械地算出。**
這避免「先射箭再畫靶」——即看到結果之後才選擇讓結果好看的設定。

沿用已執行兩次的同一模式，git 歷史即為順序的證據：

| | 先 commit 的東西 | 之後才算的東西 |
|---|---|---|
| `e40bb10` | sink 先驗權重 | 規則基準線分數 |
| `a7a8327` | LF 的全部規則 | 對 Gold 的噪音率 |
| 本文件 | 設定的決定規則 | 由規則算出的具體數值 |

常數的選擇（例如下方的 `3×`、`0.01`）本身是任意的。可接受的理由是：它們在執行前即已
凍結，且整個決定過程不會觀察 Gold，因此無法朝「Gold 分數更好看」的方向調整。

## 1. Epoch 預算與 early stopping

### 1.1 不做 early stopping

Early stopping 需要一把不屬於訓練資料的尺。三個候選全部不可用：

| 候選 | 問題 |
|---|---|
| Gold | §10 明文禁止。Gold 是唯一誠實的評估尺，用它選 epoch 等於報告一個已對它調過的數字 |
| 訓練池切出的 weak-label validation | **循環論證**。該批標籤噪音率 66.7%（`authz_lf_spec_v1.md` §6.1），以它為停止依據等於「最貼近 LF 時就停」，而修正 LF 的錯誤正是 SLB 的目的 |
| SLB 內部的 clean set 比例收斂 | M2 沒有 SLB，無法產生此訊號。兩者 epoch 預算不同即**破壞控制變數**，M3 與 M2 的差距無法歸因於 SLB |

因此採固定 epoch 數，**M2 與 M3 的全部 6 次正式執行共用同一個數字**。

**不做 checkpoint selection。** 報告與評估一律使用最後一個 epoch 的模型，不取「最佳
checkpoint」——「最佳」同樣需要一把尺，會從後門把 validation 放回來。

### 1.2 失去 early stopping 的代價在本資料上有界

訓練池 1,417 筆只落在 **113 個相異 feature vector**（86 個標籤一致、27 個衝突）。
模型對同一個 feature vector 必然輸出同一個機率，因此它最多只能學到「每格的多數標籤」，
無法記住個別樣本。由此：

- **訓練準確率的硬上限為 0.852**（格子多數決）。衝突格子中的少數類共 210 筆（14.8%），
  在任何只用這 31 維的模型下都必然答錯，訓練多久都一樣。
- 過了收斂點之後，繼續訓練只會把 softmax 機率推得更尖，不會記住更多噪音。
  因此寬鬆的 epoch 預算是安全的，而非將就。
- **0.852 同時是 sanity check**：訓練準確率若超過它，格子結構說那不可能，
  必為程式錯誤或洩漏。

### 1.3 決定規則（本節在執行前凍結）

```
診斷執行：M2、seed 20260823、單次、固定跑 600 epoch、只用訓練池的 1,417 筆弱標籤
          全程不計算、不讀取、不輸出任何 Gold 相關指標

E_plateau    = 訓練準確率的 5-epoch 移動平均，首次進入其全程最大值 0.01 以內的 epoch 編號
TOTAL_EPOCHS = min(600, 向上取至 50 的倍數(3 × E_plateau))
```

診斷執行的長度固定為 600，`E_plateau` 才有定義（「全程最大值」需要已知的執行長度）。
最大值必然在某個 epoch 被取到，因此 `E_plateau` 必定存在。

`TOTAL_EPOCHS` 算出後寫入本節並 commit，才執行正式的 6 次（M2、M3 各
seed `20260823`、`20260824`、`20260825`）。正式執行不得再改動此數字。

### 1.4 診斷執行結果（2026-10-02）

規則於 `517187e` 先 commit，之後才執行。產物：
`dataset/authz_v2/experiments/epoch_budget_diagnostic.json`。

```
1,417 筆 × 31 維（positive 387、27.3%），裝置 cuda，600 epoch，耗時 24.4 秒

平滑後峰值準確率  0.8493
門檻              0.8393
E_plateau         18
TOTAL_EPOCHS      min(600, 取50倍數(3 × 18)) = 100
```

**TOTAL_EPOCHS = 100。** 正式的 6 次執行（M2、M3 各 3 seed）一律使用此數字，不得更改。

曲線取樣：

| epoch | 1 | 5 | 10 | 20 | 30 | 50 | 100 | 200 | 400 | 600 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| accuracy | .778 | .830 | .835 | .849 | .826 | .849 | .819 | .842 | — | .842 |
| loss | .655 | .477 | .444 | .411 | .402 | .388 | .380 | .377 | — | .369 |

兩點與 §1.2 的預測一致：

- **收斂極快**，第 1 個 epoch 就到 0.778，第 20 個 epoch 已達 0.849。113 格的結構使模型
  很快把每格的多數標籤學完。
- **峰值 0.8493 未超過 0.852 的硬上限**，sanity check 通過。

### 1.5 收斂後的震盪，以及它對第 3 項的意義

收斂後準確率並未持平，而是在約 0.816–0.849 之間來回約 3 個百分點。這不是單一樣本的雜訊：
**格子是一起翻的**。最大的格子有 219 筆，一旦該格的決策翻面，數百筆樣本同時改變預測。

這對第 3 項（consistency ratio）是關鍵前提，待該項展開時以 per-sample 預測軌跡實測，
此處先記錄現象，不先下結論。

### 1.6 已知限制：規則的輸出不是裝置穩定的

同一個 seed、同一份資料、同一份程式，在 CPU 上執行得到
`E_plateau = 15`、`TOTAL_EPOCHS = 50`，與 CUDA 的 `18`／`100` 相差兩倍
（最終訓練準確率兩者皆為 0.8419，差異來自收斂後的震盪使平滑序列跨越門檻的時點對微小
數值差異敏感）。

採用 CUDA 的數值，因為 `裝置 = CUDA` 已於 §1b 在執行前凍結，CPU 那次僅為 `--dry-run`
對照、未產生任何 artifact。協議因此成立；但這是 §1b.1「可重現性有環境條件」的具體實例，
報告須一併揭露，不可只說結論數字。

也記錄實測的執行時間，以免報告出現「GPU 加速」的錯誤敘述：

| 裝置 | 600 epoch 耗時 | 每 epoch |
|---|--:|--:|
| CUDA（RTX 3070） | 24.4 秒 | 40.6 ms |
| CPU | **14.7 秒** | 24.5 ms |

CPU 比 GPU 快約 1.66 倍，與 §1b.1 的說明一致：此規模下每個 step 的 kernel 發射與同步
開銷主導總時間。選用 GPU 是專案決定，不是效能考量。

## 1b. Optimizer 與其餘訓練超參數

原待決定清單未列出這些，但它們同樣是超參數，同樣需要凍結，否則「沒有調參」的說法不成立。

**全部採用標準預設值，刻意不調。** 理由與 1.1 相同：調參需要一把尺，而這裡沒有可用的尺。
報告須明載「這些值未經任何搜尋」。

| 項目 | 值 | 依據 |
|---|---|---|
| Optimizer | Adam | 已於模型設計定案 |
| Learning rate | `1e-3` | PyTorch `Adam` 預設值 |
| Batch size | 64 | 1,417 筆下約 22 個 batch／epoch，足以產生 SLB 需要的 minibatch 隨機性 |
| Loss | **Class-Balanced CrossEntropy**（Cui et al. 2019，`β = 0.9999`） | 論文 Eq. (6)，見 §4.3。**【2026-10-03 修正】** |
| ~~Class weight~~ | ~~反比於訓練池實際頻率（positive 387、negative 1,030）~~ | **【已廢止 2026-10-03】** 與論文的 CB loss 不符，原文與理由見 §6 |
| Dropout | 0.3（兩層隱藏層） | 已於模型設計定案 |
| 架構 | 31 → 128 → 64 → 2，ReLU，softmax | 已於模型設計定案 |
| Seeds | `20260823`、`20260824`、`20260825` | 已於模型設計定案 |
| 執行裝置 | **CUDA**（NVIDIA GeForce RTX 3070、sm_86） | 2026-10-02 決定 |
| torch 版本 | `2.14.1+cu126` | CUDA 版不在 PyPI 預設 wheel 內，安裝方式見 `requirements.txt` |

### 1b.1 可重現性設定與其已知限制

全部鎖定並將 fingerprint 寫入 audit log：`torch`、`numpy`、`random` 的 seed、
`torch.backends.cudnn.deterministic = True`、`cudnn.benchmark = False`、
`torch.use_deterministic_algorithms(True)`、環境變數
`CUBLAS_WORKSPACE_CONFIG=:4096:8`（deterministic cuBLAS matmul 的前提）、
DataLoader worker seed。

**已知限制：在 CUDA 上執行，可重現性只在同一張卡與同一組驅動／CUDA 版本下成立。**
換卡或換驅動版本可能產生數值差異，因此 Week 13 凍結的 artifact fingerprint 必須連同
GPU 型號、驅動版本與 torch build 一併記錄。CPU 執行可免除此限制，但本專案已決定使用 GPU；
此限制列入報告的已知限制，不以「結果不可重現」描述，而是「可重現性有環境條件」。

本模型規模（約 12,300 參數、1,417 筆、batch 64）遠低於 GPU 的飽和點，**選擇 GPU 不是
為了速度**；實際執行時間會與 CPU 相當或更慢，因為每個 step 的 kernel 發射與同步開銷
主導總時間。此事實應在報告中如實說明，不宣稱 GPU 加速。

## 2. 兩階段結構與三個 epoch 參數

> **【2026-10-03 修正】** 本節取代原「Warm-up 長度，`WARM_UP_EPOCHS = 20`」的決定。
> 原決定把 SLB 當成單一 warm-up，與論文的兩階段結構不符。原文與修正理由見 §6。

### 2.1 論文的兩階段結構

依 Alotaibi et al.（CCS '25）Algorithm 1 與 Algorithm 2，SLB 有兩個階段、各自一個 warm-up：

```
階段一 Data Split（Algorithm 1）
  用全部 1,417 筆觀測標籤訓練一個模型 f^DS，跑 e 個 epoch
  每個 epoch 記下每筆的硬預測 → 預測集 P_i
  算 consistency ratio（§3）、切 clean／noisy（§4）、算 pseudo-label
  f^DS 是拋棄式的，不是最終模型

階段二 Continuous Revision（Algorithm 2）
  EMA 初始值取自階段一的 softmax 輸出   ← 精確定義見 §7.1 第 1 項：e 個 epoch 的平均
  訓練一個全新模型 f̂，跑 T 個 epoch，每輪只用當時的 D_c
  前 m 個 epoch 為 revision warm-up，期間不重組資料集
  第 m 個 epoch 後首次重組，之後逐輪重組並在 ỹ_i 與 y_i^maj 之間翻標籤
  f̂ 才是最終模型
```

### 2.2 三個參數的值

| 參數 | 值 | 依據 |
|---|--:|---|
| `e`（data split epochs） | **20** | 由 §1.3 已凍結的規則推出：`向上取至10倍數(E_plateau) = 向上取至10倍數(18) = 20`。恰為論文搜尋空間 `{2,5,10,15,20}` 的上界 |
| `T`（revision stage 總 epoch） | **100** | 等於 M2 的 `TOTAL_EPOCHS`，使兩個**最終模型**的訓練預算相同（見 §2.3） |
| `m`（首次重組前的 warm-up） | **5** | 論文搜尋空間 `{0,1,3,5}` 的上界。選上界的先驗理由：本專題噪音率 66.7% 遠高於論文的一般設定，且嚴格門檻 `r=1` 可能使 `D_c` 很小，首次重組前多累積 EMA 證據可降低早期誤判連鎖的風險 |
| `α`（EMA 平滑） | **0.95** | 論文固定值，原文稱「due to minimal impact」，不搜尋 |
| `β`（CB loss） | **0.9999** | 論文搜尋空間 `{0.0, 0.9999}`，`0.0` 等於不加權。選 `0.9999` 的先驗理由見 §4.3 |
| 權重初始化 | **Xavier** | 論文明載 |

`m < T` 成立（5 < 100），符合 Algorithm 2 的前提。

### 2.3 Epoch 預算如何對齊，以保住控制變數

這一點必須講清楚，否則 M2 與 M3 的比較會被混淆：

```
M2   全部 1,417 筆弱標籤，訓練 100 epoch                      → 最終模型訓練 100 epoch
M3   階段一：f^DS 訓練 20 epoch（拋棄式，只為算 r_i）
     階段二：f̂  訓練 100 epoch（前 5 個為 warm-up）            → 最終模型訓練 100 epoch
```

**兩個最終模型都訓練 100 epoch。** 階段一那 20 個 epoch 是 SLB 機制本身的成本
（為了算出 clean／noisy 切分），不屬於最終模型的訓練預算；把它算進去會讓 M3 的最終模型
只訓練 80 epoch，差距就不再只來自 SLB。M3 的總計算量為 120 epoch，這是 SLB 的額外代價，
應在報告中如實列出。

### 2.4 論文中一處語意不明與本專題的採用方式

Algorithm 2 的 `Require` 寫 `total epochs T, warm-up m < T`（暗示 `m` 包含在 `T` 內），
但正文寫「After the first reassembly, SLB continues in iterative fashion for `T` revision
epochs」（暗示 `T` 在 `m` 之後另計）。

**本專題採前者**：revision 階段總共 `T = 100` 個 epoch，其中前 `m = 5` 個為首次重組前的
warm-up。理由是這個讀法同時滿足 `m < T` 的前提，並使最終模型的訓練預算恰與 M2 相同。
此處的歧義與採用理由必須寫進報告。

### 2.5 軌跡記錄範圍

per-sample 預測自**階段一的 epoch 1 起全程記錄**，階段二的 EMA 另行記錄。
階段一的記錄是 `r_i` 的計算基礎（§3），階段二的 EMA 是重組與翻標籤的依據。

## 3. Consistency ratio 的定義

> **【2026-10-03 修正】** 本節採用論文 Eq. (3)。原先規劃討論的三種候選定義中，
> 桌面紀錄傾向的「預測類別不變的 epoch 比例」**是錯的**，與論文不符。詳見 §6。

論文 Eq. (3)：consistency ratio 是「模型預測等於**觀測標籤**」的 epoch 比例。

$$r_i = \frac{\left|\{\hat{y} \in \mathcal{P}_i : \hat{y} = \tilde{y}_i\}\right|}{e}$$

原文：

> To measure the consistency of predictions, we define a consistency ratio $r_i$ as the
> fraction of epochs in which the model's predicted label matches the observed
> (potentially noisy) label $\tilde{y}_i$.

三件要點：

1. **是與給定標籤比較，不是看預測穩不穩。** 一筆樣本若在 20 個 epoch 中都穩定地預測成
   與觀測標籤相反的類別，`r_i = 0`，判為 noisy。若改用「預測類別不變的比例」，
   同一筆會得到 1.0 並判為 clean，**結果完全相反**。
2. **對全部 `e` 個 epoch 計算**，不是固定長度的滑動視窗，因此沒有額外的視窗長度參數。
3. 使用**硬預測**（argmax），不是 softmax 機率。機率只在階段二的 EMA 中使用。

## 4. Clean／noisy 的切分方式

> **【2026-10-03 修正】** 論文已定義此項，原先列為待討論並傾向「per-class 分別取比例」
> 的規劃作廢。論文用嚴格門檻加 CB loss，不是 per-class 切分。詳見 §6。

### 4.1 嚴格門檻 `r_i = 1`

$$\mathcal{D}_c = \{i : r_i = 1\}, \qquad \mathcal{D}_n = \{i : r_i < 1\}$$

> Samples with complete prediction consistency across all epochs ($r_i = 1$) are confidently
> labeled as clean and form the clean set $\mathcal{D}_c$. Conversely, samples with any
> inconsistency ($r_i < 1$) are considered noisy.

**不是固定比例、不是 per-class 門檻。** 每一個 epoch 都預測對才算 clean，有任何一次
不一致即為 noisy。因此沒有「取前 15%」這類需要凍結的比例參數。

### 4.2 Pseudo-label（Eq. 5）

對 `D_n` 的樣本計算 `y_i^maj = majority(P_i)`，即 `e` 個 epoch 中最常被預測的類別。
觀測標籤與 pseudo-label **兩者都保留**，階段二可在兩者之間來回切換。

### 4.3 類別不平衡由 CB loss 處理，不是由切分方式處理

論文 §Class-Balanced Loss 明確描述了與本專題一致的失效模式：

> the model may show high consistency on the majority class and, in some cases, even
> overfit to its noisy labels. Meanwhile, truly correct samples in underrepresented
> classes may never achieve perfect consistency

本專題的處境正是如此：positive 僅 27.3%，而 `authz_lf_spec_v1.md` §6.2 量到噪音
**高度集中在多數類 negative**（65 筆真 positive 被標成 negative）。

論文的處方是 Class-Balanced loss（Cui et al. 2019），以 effective number 加權（Eq. 6）：

$$\text{EN}_{y_b} = \frac{1 - \beta^{n_{y_b}}}{1 - \beta}, \qquad
\text{每筆 loss 權重} = \frac{1}{\text{EN}_{\tilde{y}_i}}$$

**採 `β = 0.9999`**（論文搜尋空間的兩個值之一，另一個 `0.0` 等於不加權）。先驗理由：
本專題同時具備類別不平衡與「噪音集中於多數類」兩個條件，正是論文設計 CB loss 要處理的
情形；若取 `0.0`，多數類很可能呈現高 consistency 並把其噪音標籤帶進 `D_c`。
此選擇**未經任何搜尋**，與 §1b 的原則一致。

### 4.4 要預先登記的預測

`r_i = 1` 是嚴格門檻，而 §1.5 量到收斂後**格子會整片翻面**（準確率震盪約 3 個百分點）。
只要某個格子在 `e = 20` 個 epoch 中翻過一次，**該格全部樣本的 `r_i` 都會 < 1**，整格進入
`D_n`。最大的格子有 219 筆。

因此 `D_c` 可能很小，而階段二只用 `D_c` 訓練。這是可量測的，應在正式 6 次執行之前先以
階段一量出 `r_i` 的分布與 `|D_c|`，並與本預測對照。

## 5. Audit log 的欄位

### 5.1 目的不是模型的可解釋性

這份 log 解釋的是 **SLB 這個程序對標籤做了什麼**，不是模型對某一筆輸入為什麼給出某個預測。
後者在本專題幾乎不需要工具：1,417 筆只落在 113 個格子，任一筆的預測完全由「它落在哪一格」
決定，查 `features_training.jsonl` 即可。

三個用途：

| 用途 | 性質 | 回答 |
|---|---|---|
| 可稽核性 | 事後驗證 | 這個程序實際做了什麼、報告的數字怎麼來 |
| 錯誤分析 | 研究問題本身 | `authz_lf_spec_v1.md` §6.1 那 65 筆漏判，SLB 有沒有救回來 |
| 絆索 | 訓練中的即時檢查 | 有沒有發生 revision collapse（見 §5.5） |

報告用詞應為「可稽核性與錯誤分析」，不宜寫成「可解釋性」——後者會引來「那你的 SHAP 呢」
這類與本專題無關的質疑。

### 5.2 不變量

1. **寫 log 時不得讀取 Gold。** audit log 必須能在完全不接觸 Gold 的情況下寫出；
   與 Gold 的 join 是之後獨立的分析步驟。這維持 §0 的協議。
2. **以 `review_unit_id` 為唯一 join key**，與 feature、observed label、Gold 都對得上。
3. **一次寫出就是最終版**，不得在分析階段回頭補欄位。理由見 §5.6。

### 5.3 四個產物與各自的粒度

粒度不同的東西不放同一個檔案，否則任何分析都得掃全檔。

| 檔案 | 粒度 | 模型 |
|---|---|---|
| `dataset/authz_v2/label_revision_audit.jsonl` | (run, stage, epoch, unit) | **M3 密集** |
| `dataset/authz_v2/experiments/slb_epoch_metrics.jsonl` | (run, stage, epoch) | M2 與 M3 |
| `dataset/authz_v2/experiments/slb_run_manifest.json` | run | M2 與 M3 |
| `dataset/authz_v2/experiments/predictions_<run>.jsonl` | (run, unit) | M2 與 M3，訓練池與 Gold 評估集各一份 |

`label_revision_audit.jsonl` 的檔名與路徑沿用 `SLB越權偵測實作時程.md` 既有的交付物指定。

**M2 不寫 per-unit-per-epoch log**：它沒有標籤修正，該檔對 M2 按定義為空。M2 的逐 epoch
聚合指標與最終預測仍照寫。需要「vanilla 的預測軌跡」時，M3 階段一本身就是一次 20 epoch 的
vanilla 執行（全部資料、原始標籤），可直接用。

### 5.4 `label_revision_audit.jsonl` 的欄位

| 欄位 | 階段 | 說明 |
|---|---|---|
| `run_id` | 兩者 | 例 `m3-seed20260823` |
| `model` | 兩者 | `M3` |
| `seed` | 兩者 | |
| `stage` | 兩者 | `data_split`（階段一）｜`revision`（階段二） |
| `epoch` | 兩者 | 階段內的 1-based 編號 |
| `review_unit_id` | 兩者 | join key |
| `observed_authz_label` | 兩者 | LF 產生的原始標籤。每列重複存，使本檔對錯誤分析自足 |
| `predicted_label` | 階段一 | 該 epoch 的硬預測（argmax）。`r_i` 的計算基礎，也是驗證「格子一起翻」的唯一證據 |
| `predicted_prob_positive` | 階段一 | 該 epoch 的 softmax `P(positive)`，階段二 EMA 的初始值來源 |
| `consistency_ratio` | 兩者 | 階段一算出的 `r_i`；階段二每列重複存 |
| `pseudo_label` | 兩者 | `majority(P_i)`；階段二每列重複存 |
| `ema_prob_positive` | 階段二 | 本 epoch 更新後的 EMA 值 |
| `ema_label` | 階段二 | `argmax` EMA |
| `set_membership` | 兩者 | `clean`｜`noisy`。階段一為初始切分結果 |
| `training_label` | 階段二 | **本 epoch 實際進入 loss 的標籤**。這才是「revised label」的操作定義 |
| `label_source` | 階段二 | `observed`｜`pseudo`，指出 `training_label` 來自哪一個 |
| `included_in_training` | 階段二 | 階段二只用 `D_c` 訓練，`D_n` 的樣本雖仍計算 EMA 但不進 loss，必須記下 |
| `membership_changed` | 階段二 | 與前一 epoch 相比是否變動（可推導，但materialise 以便查詢） |
| `training_label_changed` | 階段二 | 同上 |

`observed_authz_label`、`consistency_ratio`、`pseudo_label` 在階段二是每筆固定值，逐列重複
存屬刻意的反正規化：錯誤分析發生在數週之後，此檔應只需與 Gold join 即可完成，不必再回頭
串接其他檔案。

### 5.5 線索必須改寫——原設計在這裡會退化

報告 §10.6 原本指定兩個 per-epoch 指標：`revised` 對 `observed` 的一致率（修了多少）、
以及 `revised` 對 **LF 公式直接輸出**的一致率（往哪個方向修）。

**在本專題這兩者是同一個東西。** 我們只有一條 LF，`observed_authz_label` 就是 LF 公式的
直接輸出，所以第二個指標退化成第一個，偵測不到任何東西。

實際在這裡會發生的 collapse 是另一種形狀。推論如下，待實測驗證：

```
模型的輸出是 per-cell 的（113 格）
  → 某筆的逐 epoch 預測 = 該格的逐 epoch 預測
  → pseudo_label = majority(該格的預測) ≈ 該格 observed 標籤的多數
  → 把樣本改標成 pseudo_label = 把它的標籤換成「它所在格子的多數 observed 標籤」
```

也就是說 **SLB 在這份資料上能做的最大動作，是把每個格子內的標籤同質化**。這不是往 LF
公式收斂，而是往「LF 輸出的格內多數」收斂。而那 210 筆衝突格少數類正是會被翻的對象——
若其所在格子的多數是 negative（依 LF 的分布很可能如此），被漏判的真 positive 會**被翻成
negative，等於強化錯誤**。

因此改用這個指標作為線索：

```
agreement_training_label_vs_cell_majority
  = training_label 等於「該 unit 所在 feature 格子的 observed 多數標籤」的比例
```

隨 epoch 單調上升且趨近 1.0，即為格內同質化，當場停下來檢查。此指標**只需 feature 與
observed label，不需要 Gold**，可即時計算。

一併記錄 `distinct_training_labels_per_cell` 的分布，作為同質化程度的直接量測。

原 §10.6 的兩個指標仍照寫（`agreement_revised_vs_observed` 保留，另一個標註為與前者等價、
在單一 LF 下不具獨立資訊），但報告中須說明其退化原因，不得假裝有兩個獨立防線。

### 5.6 `slb_epoch_metrics.jsonl` 的欄位

| 欄位 | 說明 |
|---|---|
| `run_id`、`model`、`seed`、`stage`、`epoch` | |
| `train_loss`、`train_accuracy` | 在該 epoch 實際用於訓練的集合上計算 |
| `trained_on_units` | 該 epoch 進入 loss 的筆數（階段二等於 `\|D_c\|`） |
| `clean_set_size`、`noisy_set_size` | |
| `promoted_count`、`demoted_count` | 本 epoch 的 `D_n→D_c`、`D_c→D_n` 筆數 |
| `flips_to_pseudo`、`flips_to_observed` | 本 epoch 的標籤翻轉筆數 |
| `agreement_revised_vs_observed` | §10.6 原指標 |
| **`agreement_training_label_vs_cell_majority`** | §5.5 的線索 |
| `distinct_training_labels_per_cell_mean` | 同質化程度 |
| `positive_share_of_training_labels` | 監看 SLB 是否把 positive 整批抹掉 |

### 5.7 `slb_run_manifest.json` 的欄位

| 欄位 | 說明 |
|---|---|
| `run_id`、`model`、`seed` | |
| `config` | `e`、`m`、`T`、`α`、`β`、lr、batch、dropout、架構 的實際值 |
| `config_spec_commit` | 本規格文件當時的 commit SHA，使設定可回溯 |
| `input_files` | feature、observed label 檔的路徑與 SHA-256 |
| `environment` | torch 版本、CUDA build、GPU 型號與 capability、`CUBLAS_WORKSPACE_CONFIG`、determinism 旗標（沿用 `train_authz_mlp.environment_fingerprint`） |
| `wall_clock_seconds` | |
| `output_row_counts` | 各產物的列數，供完整性檢查 |
| `gold_consulted` | 固定為 `false`，明示此執行未讀取 Gold |

### 5.8 為什麼採密集記錄而非 event-sourced

資料量：M3 每個 seed 為 `1,417 × (20 + 100) = 170,040` 列，3 個 seed 共約 51 萬列，
估計 70–80 MB。repo 既有的 `sensitive_api_callers.jsonl` 為 47.8 MB，同一量級。

Event-sourced（只在狀態改變時寫）可大幅縮小檔案，但有兩個代價：重建「第 t 個 epoch 的狀態」
需要額外的 replay 程式，而 EMA 是每個 epoch 都在變的連續值，本質上無法事件化。

在「漏了補不回來」的前提下，簡單與完整優先於儲存效率。

### 5.9 漏欄位的真正代價

不是資料遺失——理論上可以重跑補記錄。問題是**重跑出來的是另一次執行**：報告的分數來自第一次、
錯誤分析來自第二次。而 §1.6 已實測到同一份程式在不同裝置上得出不同結果
（`E_plateau` 15 vs 18），「重跑應該一樣」在本專案已被證明不能照單全收。

因此欄位寧可多記。

---

## 6. 與論文原文的對照與修正紀錄（2026-10-03）

本節存在的目的是讓修正紀錄**本身就是證據**，不必要求讀者去翻 git log。

### 6.1 事情的經過

論文來源原本不在 repo 內：`docs/SLB越權偵測實作時程.md:565` 只把 `consistency ratio`
列在必須實作的元件清單中，**沒有公式、沒有引用**；全 repo 只有
`docs/2026-08-25_進度報告.md` 提到全名「Selective Label Bootstrapping（SLB）」。

2026-10-03 由使用者指出來源為 **Alotaibi et al., "Deep Learning from Imperfectly
Labeled Malware Data", CCS '25**（`https://www.doc.ic.ac.uk/~maffeis/papers/ccs25.pdf`、
DOI `10.1145/3719027.3765197`、程式碼 `https://zenodo.org/records/16924658`）。
取得原文後，三項已凍結或已規劃的設定與論文不符，予以修正。

### 6.2 新舊對照

| 項目 | 舊（已廢止） | 新（依論文） | 論文依據 |
|---|---|---|---|
| **Consistency ratio** | 傾向「預測類別**不變**的 epoch 比例」，理由是「最好解釋也最好畫圖」 | 「預測**等於觀測標籤**」的 epoch 比例 | Eq. (3) |
| **Clean／noisy 切分** | 規劃「per-class 分別取比例」，以免 positive 整批被判 noisy | **嚴格門檻 `r_i = 1`**，非比例、非 per-class | Eq. (4) 及其正文 |
| **類別不平衡的處理** | 以 per-class 切分比例處理 | **Class-Balanced loss**（effective number，`β = 0.9999`） | Eq. (6)、§Class-Balanced Loss |
| **Class weight** | 反比於訓練池頻率 | CB loss 的 `1/EN` 加權 | Eq. (6) |
| **Warm-up** | 單一參數 `WARM_UP_EPOCHS = 20` | 兩階段、兩個 warm-up：`e = 20`、`m = 5`，另有 `T = 100` | Algorithm 1、Algorithm 2 |
| **EMA 平滑 `α`** | 未列入 | **0.95**（論文固定值，不搜尋） | Eq. (9) |
| **權重初始化** | 未列入 | Xavier | 論文附錄 |

舊「Warm-up 長度」一節的原文（已由 §2 取代）：

> **WARM_UP_EPOCHS = 20**（2026-10-02 定案）。
> `WARM_UP_EPOCHS = 向上取至 10 的倍數(E_plateau) = 向上取至10倍數(18) = 20`
> 即約等於收斂點，佔總預算 20%（常見區間的下緣），SLB 仍有 80 個 epoch 可供修正。
> warm-up 期間（epoch 1–20）以原始 `observed_authz_label` 正常訓練，不做任何 label 修正；
> warm-up 之後（epoch 21–100）SLB 機制啟動。

注意舊決定的 `20` 本身**沒有被推翻**——它成為階段一的 `e`，而且恰為論文搜尋空間
`{2,5,10,15,20}` 的上界。被推翻的是「只有一個 warm-up」這個結構假設。

### 6.3 為什麼這不是「先射箭再畫靶」

凍結協議要防的是一件特定的事：**看到結果之後，回頭挑讓結果好看的設定。**
那件事有個前提——必須先看到結果。本次修正時：

- **沒有執行過任何模型評估。** M2 只跑過 §1.4 的 epoch 預算診斷，該次執行不讀取 Gold、
  不輸出任何 Gold 指標。
- **沒有讀取 Gold。** 最後一次接觸 Gold 是 `bde50f4`（量 LF 噪音率），在那之後至本次修正
  之間沒有任何 Gold 相關計算。
- 改動的是**實作對所研究方法的忠實度**，不是評估結果的呈現方式。

這一點可由 git 歷史驗證，不需採信任何說法：

```
517187e  凍結 epoch 決定規則
8f594e8  跑診斷、填入 TOTAL_EPOCHS = 100
a02a36f  凍結 warm-up = 20
<本次>   取得論文原文，依 Algorithm 1／2 修正
         ← 以上區間內不存在任何評估 commit
```

若此修正真有問題，歷史會呈現另一種形狀：「凍結 → 評估得到 Gold 分數 → 改設定 → 再評估」。
兩種形狀可以直接分辨。

### 6.4 不修正的代價更大

若為保住一份乾淨的凍結紀錄而維持舊設定，訓練出來的**就不是 SLB**。本專案對此已有明文立場：

- `docs/SLB越權偵測實作時程.md:528`：「Random Forest ensemble 不能稱為 genuine SLB」
- 同文件 Week 10–11 的目標：「實作 **Genuine** SLB」

維持舊設定會換來一個更難回答的問題：「你的 consistency ratio 為什麼與論文 Eq. (3) 不同？」

### 6.5 明確偏離論文、且無法消除的部分

**論文以 grid search 選超參數，本專題不能。** 原文：

> We performed a grid search to determine the optimal hyperparameters for each method.
> Our search criterion was the highest mF1 score obtained using seed 1.

論文的搜尋空間為 `e ∈ {2,5,10,15,20}`、`m ∈ {0,1,3,5}`、`β ∈ {0.0, 0.9999}`。

本專題依 `authz_label_spec.md` §10 與時程表 `:453`，**Gold 不得用於選超參數**，
而 Gold 是唯一可用的尺（weak-label validation 為循環論證，見 §1.1）。因此 `e`、`m`、`β`
全部先驗固定，理由逐項記錄於 §2.2 與 §4.3。

**後果必須如實報告**：本專題的 SLB 超參數可能不是最佳值，因此 M3 的表現可能低於論文方法
的潛力。緩解（非免責）是論文自身的敏感度分析：

> it remains robust even under suboptimal hyperparameter settings

以及 §4.5.4 指出 `e` 的影響「measurable but modest」、`m` 在多數資料集上最大與最小表現
差距「modest」。

另外，論文使用 seed 1–10 共 10 個 seed，本專題依既有決定使用 3 個
（`20260823`／`20260824`／`20260825`），統計力較弱，此差異亦須載明。

---

## 7. 實作前的最後校正（2026-10-04）

§1–§6 是設定的決定。本節是把這些決定寫成程式時，發現**必須再凍結一次**的東西：
原文細節的校正（§7.1）、一處順序瑕疵的揭露（§7.2），以及 spec 沒寫但程式非選不可的
機械細節（§7.3）。一律在執行之前 commit，仍未讀取 Gold。

### 7.1 依 Algorithm 1／2 原文校正五處實作細節

§6 修正設定時引用的是論文正文。實作時取得 Algorithm 1 與 Algorithm 2 的完整 pseudocode
（來源同 §6.1），其中五處比 §2 的敘述更精確，或與之不同：

| # | §2 的敘述 | 原文 pseudocode | 處置 |
|--:|---|---|---|
| 1 | §2.1「EMA 初始值取自階段一的 softmax 輸出」 | Eq. (8)：`p̄⁽⁰⁾ᵢ = (1/e) Σₜ₌₁ᵉ pᵢ,ₜ`，即**階段一全部 e 個 epoch 的 softmax 平均** | 依原文改為平均。不是最後一個 epoch |
| 2 | §2.2「`α`（EMA 平滑）0.95」 | Eq. (9)：`p̄⁽ʳ⁾ᵢ = α·p⁽ʳ⁾ᵢ + (1−α)·p̄⁽ʳ⁻¹⁾ᵢ`，`α` 乘在**新的** prediction 上 | 依原文字面實作。後果見下 |
| 3 | §2.1、§5.4 未提及 | Algorithm 2 `Require` 有 **origin flag `oᵢ ∈ {c, n}`**，取自階段一且**全程不更新**。line 15／31 的 `oᵢ = n ∧ ŷ⁽ᵗ⁾ᵢ = y^majᵢ` 表示**只有階段一判為 noisy 的樣本才可以帶 pseudo-label 進 `D_c`** | 補上。階段一判 clean 的樣本永遠只能以 observed 標籤進 `D_c` |
| 4 | §2.4 記為「論文語意不明」，本專題選「`T` 含 `m`」 | Algorithm 2 line 2 `for r = 1 to m`、line 21 `for t = m+1 to T`：**pseudocode 毫無歧義，`T` 確實含 `m`** | §2.4 的選擇與 pseudocode 一致。歧義只存在於正文敘述，報告改以此陳述，不再寫成「我們在兩個讀法中選一個」 |
| 5 | §4.3 只定義階段一的 CB loss | Algorithm 2 未重述 loss；`n_{y_b}` 在階段二沒有定義 | 見 §7.3 第 4 項 |

**第 2 項的後果必須寫進報告。** `α = 0.95` 乘在新 prediction 上，意味 EMA 的半衰期約為
1 個 epoch——它幾乎跟隨當下 epoch 的 softmax，**不是強平滑**。這直接放大 §4.4 預先登記的
那個風險：§1.5 已實測格子會整片翻面，而 EMA 既然緊跟當下預測，`ema_label` 也會整片翻，
重組與翻標籤因此可能逐 epoch 大幅震盪。此處不預判結果，只指出 §4.4 的預測在這個 `α`
的語意下更可能成立。

**第 3 項的後果**是 `D_c` 的成長被限制住：階段一的 `D_c` 只能縮小或換成員，
`pseudo_label` 只對階段一的 `D_n` 有效。`label_source = pseudo` 因此永遠只出現在
`oᵢ = n` 的樣本上，這是 audit log 的一條不變量，可用於驗證實作。

### 7.2 揭露：epoch 預算的診斷早於 loss 與初始化的修正

**順序上有一處瑕疵，必須自己講出來。** §1.4 的診斷執行於 2026-10-02，當時的 loss 是
反比於頻率的 class weight、初始化是 PyTorch 預設的 Kaiming uniform。§6 在 2026-10-03 把
loss 改為 CB loss、把初始化改為 Xavier。因此 **`E_plateau = 18`、`TOTAL_EPOCHS = 100`、
`e = 20` 這三個數字是在與正式執行不同的設定下量出來的。**

處置**先於觀察**登記如下，本節連同程式一併 commit，之後才執行：

```
採用的數字：TOTAL_EPOCHS = 100、e = 20、T = 100。不因任何後續量測而改變。

敏感度檢查：以修正後的設定（CB loss + Xavier）重跑一次 §1.3 的診斷規則，
            產物寫入 experiments/epoch_budget_diagnostic_corrected_config.json。
            此檢查只為揭露，不觸發任何數字變更。無論它算出什麼，正式執行一律用 100／20。
```

為什麼不改用新數字？因為 `100` 與 `20` 已經 commit 在 `8f594e8`、`a02a36f`，而
§0 的協議保護的正是「已 commit 的數字不得事後替換」。重跑之後挑一個用，就是把一個
已凍結的數字換成另一個——即使兩次都沒碰 Gold，這個動作本身會讓「凍結」失去意義。
反過來說，**預先宣告「無論結果如何都用舊值」，再去量**，是這個協議允許的唯一做法：
它只能讓紀錄變得更完整，不可能讓數字朝任何方向偏移。

#### 敏感度檢查的結果（2026-10-04，於上述規則 commit 之後才執行）

產物：`dataset/authz_v2/experiments/epoch_budget_diagnostic_corrected_config.json`
（CUDA、seed 20260823、600 epoch、CB loss + Xavier，未讀取 Gold）。

| | 2026-10-02（inverse-frequency + 預設初始化） | 2026-10-04（CB loss + Xavier） |
|---|--:|--:|
| 平滑後峰值準確率 | 0.8493 | 0.8498 |
| `E_plateau` | 18 | **12** |
| 規則算出的 `TOTAL_EPOCHS` | 100 | **50** |
| 最終訓練準確率 | 0.8419 | 0.8419 |
| 600 epoch 耗時 | 24.4 秒 | 26.5 秒 |

**依預先登記，正式執行仍用 `TOTAL_EPOCHS = 100`、`e = 20`、`T = 100`，不改。**

兩點值得記錄：峰值 0.8498 仍未超過 0.852 的硬上限，sanity check 在新設定下同樣通過；
而兩次的最終訓練準確率完全相同（0.8419），差別只在收斂的前 20 個 epoch——
新設定收斂更快（第 10 個 epoch 已達 0.8412），所以 `E_plateau` 由 18 降到 12。
`100` 相對於 12 是更寬鬆的預算，§1.2 的論證（過了收斂點繼續訓練不會記住更多噪音）
因此只是更站得住，不受影響。

§1.6 已經記載同一個規則在 CPU 與 CUDA 上得出 `15` 與 `18`。本節是同一件事的第二個實例：
**這條規則的輸出對設定與環境都敏感，`100` 應當被讀成「一個寬鬆且事先固定的預算」，
而不是一個有意義的估計值。** §1.2 已論證寬鬆的預算在本資料上無害，該論證不依賴
`E_plateau` 的精確值。

### 7.3 spec 沒指定但程式必須選的機械細節

以下七項，spec §1–§6 都沒有規定，但程式不可能不選。先登記，避免事後被誤認為是調過的。

1. **`majority(Pᵢ)` 平手 → 取 observed 標籤。** `e = 20` 為偶數，10:10 可能發生。
   取 observed 的理由：平手代表沒有證據支持改標籤，保守處置。等價的說法是
   `pseudo_label ≠ observed` 恰好發生在 `rᵢ < 0.5` 時。平手筆數寫入 manifest。
2. **格子多數決平手 → 取 negative。** `cell_majority` 用於 §5.5 的
   `agreement_training_label_vs_cell_majority`。訓練池 113 格中有 **3 格平手、共 16 筆**
   （此數字只用訓練池的 feature 與 observed label 算出，未觸及 Gold）。
   取 negative 的理由：它是多數類，與 §1.2「格子多數決上限 0.852」的計算採同一規則——
   實測此規則下的上限恰為 0.8518，與 §1.2 一致，可互相驗證。
3. **§5.6 的聚合指標只在「該 epoch 實際進入 loss 的集合」上計算**，與 `train_accuracy`
   的母體相同。涵蓋 `agreement_revised_vs_observed`、
   `agreement_training_label_vs_cell_majority`、
   `distinct_training_labels_per_cell_mean`、`positive_share_of_training_labels`。
   理由：這些指標問的是「進入 loss 的標籤長什麼樣」，母體不一致會使 M2 與 M3 的數字不可比。
   `distinct_training_labels_per_cell_mean` 的分母為「該 epoch 至少有一筆進 loss 的格子數」。
4. **階段二 CB loss 的 `n_{y_b}` 每個 epoch 由當時 `D_c` 的 training label 重算。**
   論文的 `n_{y_b}` 定義為「該類別的樣本數」，而階段二實際訓練的集合是 `D_c^t`，
   其類別組成逐 epoch 改變；用固定的 1,030／387 會使權重與實際訓練集脫節。
   逐 epoch 的 `n_{y_b}` 寫入 `slb_epoch_metrics.jsonl`，可稽核。
   `D_c` 中某類別為 0 筆時該類別權重設為 0（`1/EN` 在 `n = 0` 時未定義，而該類別沒有樣本
   進 loss，權重無作用）。
5. **CB 權重正規化為「總和等於出現的類別數」**（Cui et al. 原實作）。
   `nn.CrossEntropyLoss(reduction="mean")` 算的是加權平均 `Σwᵢlᵢ / Σwᵢ`，對 `w` 的整體
   縮放不變，**此正規化不改變 loss 與梯度**（有單元測試），只讓寫進 log 的權重可讀
   （未正規化時 `1/EN` 約 1e-3 量級）。
6. **`D_c` 變成空集合時中止執行並回報，不退回用全部資料。** §4.4 已預先登記 `D_c` 可能很小。
   若 `|D_c^0| = 0` 或某個 `|D_c^t| = 0`，程式以錯誤中止並記下 epoch 編號。
   這是研究結果（revision collapse 的極端形式），不是待修的 bug，不得以「沒資料就用全部」
   這類 fallback 掩蓋。
7. **M2 的 `stage` 欄位固定為 `vanilla`。** §5.6 的 `stage` 只定義了 `data_split` 與
   `revision`，兩者都是 M3 的階段。M2 需要一個值才能與 M3 共用同一個檔案。
8. **`promoted_count`／`demoted_count`／`membership_changed`／`training_label_changed`
   一律比較「epoch *t* 用來訓練的集合」與「epoch *t−1* 用來訓練的集合」。**
   §5.6 只寫「本 epoch 的 `D_n→D_c`」，但 Algorithm 2 的重組發生在 epoch 結束之後
   （line 27–36 產生的是 `D_c^{t+1}`），所以「本 epoch 的變動」有兩個讀法。
   採此讀法的理由：每一列的計數因此描述**該列自己的集合**是怎麼來的，與同一列的
   `trained_on_units`、`train_accuracy` 指同一個集合；另一個讀法會讓同一列的欄位
   分別指向兩個不同的集合。`t = 1` 的變動量為 0（階段一的切分即為 `D_c^0`）。
   `t ≤ m` 全部為 0（warm-up 期間不重組）。
9. **`flips_to_pseudo`／`flips_to_observed` 比較的是「本 epoch 的 `label_source`」與
   「該筆最近一次非 null 的 `label_source`」，從未進過 loss 的樣本視為 `observed`。**
   離開與回到 `D_c` 由 `membership_changed` 表達；`training_label_changed` 仍會因 null
   而為 true，這是刻意的：它問的是「這一列進 loss 的標籤和上一列一樣嗎」。

   > **【2026-10-04 修正，並據實記載發現過程】** 本項原先定義為「只在**前一個 epoch**與
   > 本 epoch 的 `label_source` 皆非 null 時計算」，理由是避免與 `promoted`／`demoted`
   > 重複計算。**該定義是錯的，而且錯得剛好把本專題唯一真正發生的標籤修正記成 0。**
   >
   > 原因是 Algorithm 2 的樣本是**帶著 pseudo-label 從 `D_n` 被提拔進 `D_c`** 的
   > （line 15–16、31–32），所以它前一個 epoch 的 `label_source` 必然是 null，
   > 於是這類翻標籤一律不被計入。M3 三次執行的 `total_flips_to_pseudo` 全部為 0，
   > 而 audit log 顯示實際上有 **176／188／207 筆**以 pseudo-label 進 loss。
   >
   > **這是在跑完第一輪 M3、檢查產物時才發現的，不是事先想到的。** 修正後重跑三次。
   > 修正不涉及 Gold（這些計數只用 observed label 與 pseudo-label），也不改變任何
   > 訓練行為——`flips_*` 是純記錄欄位，不進 loss、不影響重組——因此重跑的模型與原本
   > 完全相同，差別只在 `slb_epoch_metrics.jsonl` 這兩個欄位記對了。

### 7.5 階段二輸出的 `D̂`（revised dataset）不另存檔

論文 Algorithm 2 line 38 回傳 `D_c^{T+1}`，即第二個研究目標「較乾淨的資料集」。
本專題**不另存一份 revised label 檔**，因為它可由 audit log 完全還原：
`D̂` 是以 epoch `T` 那一列的 `ema_label` 對 `observed_authz_label`、`pseudo_label` 與
origin flag（由 epoch 1 的 `set_membership` 給出）套用同一條重組規則的結果，四個欄位
都已逐列存在。另存一檔只會多出一個必須與 log 保持同步的產物。

### 7.4 產物的檔名與儲存格式

§5.3 的四個產物在實作上作三處具名化，內容與粒度完全依 §5.3–§5.7，不增刪欄位：

| §5.3 的指定 | 實際檔名 | 理由 |
|---|---|---|
| `experiments/slb_run_manifest.json` | `slb_run_manifest_<run_id>.json` | 粒度是 run，6 次執行需要 6 份；單一檔名會被後一次覆寫 |
| `experiments/predictions_<run>.jsonl` | 同名，訓練池與 Gold 評估集合併於一檔，以 `split` 欄位區分 | §5.3 的粒度是 (run, unit)，兩個 split 的 unit 不重疊，`split` 即可分辨；分兩檔會讓 join 多一步 |
| `label_revision_audit.jsonl` | `label_revision_audit_<run_id>.jsonl.gz` | 見下 |

**audit log 分檔並壓縮的理由是 git，不是儲存成本。** §5.8 估計 51 萬列、70–80 MB，但該估計
沒算 `review_unit_id` 的長度（76 字元），實測每列約 470 bytes，三個 seed 合計約 **240 MB**。
repo 目前最大的追蹤檔案是 2.2 MB（§5.8 引用的 47.8 MB 檔案並未被 git 追蹤），而單一檔案
240 MB 無法 push。分 run 並 gzip 後每份約數 MB。

**這不是 §5.8 的退讓**：§5.8 拒絕的是 event-sourced（只在狀態改變時寫），因為那需要 replay
程式、且 EMA 無法事件化。本處仍然每個 (run, stage, epoch, unit) 都寫一列，欄位一個不少，
只是換了容器。manifest 記錄未壓縮的列數與壓縮檔的 SHA-256，完整性檢查不受影響。

## 8. M2 正式執行（2026-10-04）

3 次，seed `20260823`／`20260824`／`20260825`，各 `TOTAL_EPOCHS = 100` 個 epoch，
CUDA、CB loss、Xavier。**未讀取 Gold**：Gold 評估集只載入 feature 與 `review_unit_id`
（該檔不含標籤欄位），輸出預測，不計算任何指標。

| seed | 最終訓練準確率 | 最終 loss | 耗時 | 訓練池預測 positive | Gold 評估集預測 positive |
|---|--:|--:|--:|--:|--:|
| 20260823 | 0.8405 | 0.3800 | 5.4 秒 | 0.334 | 0.385 |
| 20260824 | 0.8419 | — | 4.2 秒 | 0.332 | 0.383 |
| 20260825 | 0.8419 | — | 4.1 秒 | 0.332 | 0.378 |

**三個 sanity check 都通過：**

1. 格子數實測 **113**，與 §1.2 一致。
2. 格子多數決上限實測 **0.8518**，與 §1.2 的 0.852 一致；三個 seed 的訓練準確率
   皆低於它（0.8405／0.8419／0.8419），沒有洩漏跡象。
3. 三個 seed 的差異極小（0.0014），與 §1.2「有效容量由 113 格決定」的推論一致。

產物（spec §5.3、§7.4）：

```
experiments/slb_epoch_metrics.jsonl          300 列（3 run × 100 epoch）
experiments/predictions_m2-seed<s>.jsonl     各 1,801 列（訓練池 1,417 + Gold 評估集 384）
experiments/slb_run_manifest_m2-seed<s>.json 各 1 份
models/m2-seed<s>.pt                         最後一個 epoch 的模型（不做 checkpoint selection）
label_revision_audit                         0 列（M2 沒有標籤修正，按定義為空，§5.3）
```

此處**不解讀** Gold 評估集的預測 positive 比例（0.378–0.385）代表什麼：那需要與 Gold
標籤比對，屬於另一個獨立的評估步驟。本節只記錄執行本身。

## 9. M3 正式執行（2026-10-04）

3 次，同樣的三個 seed，階段一 `e = 20` + 階段二 `T = 100`（含 `m = 5` warm-up），
`α = 0.95`、`β = 0.9999`，CUDA。**未讀取 Gold。** 每次約 7–8 秒。

### 9.1 階段一的切分

| seed | `\|D_c\|` | 佔比 | clean 中 positive／negative | `\|D_n\|` | 整格落入 `D_n` 的格子 | `y^maj ≠ ỹ` | `r_i` 平均 |
|---|--:|--:|--:|--:|--:|--:|--:|
| 20260823 | 1,039 | 73.3% | 252／787 | 378 | 26 / 113 | 224 | 0.8329 |
| 20260824 | 1,056 | 74.5% | 279／777 | 361 | 26 / 113 | 223 | 0.8283 |
| 20260825 | 786 | 55.5% | 279／507 | 631 | 30 / 113 | 256 | 0.8099 |

`majority(P_i)` 平手 **0 筆**（三個 seed 皆然），§7.3 第 1 項的 tie-break 規則實際未被觸發。

`r_i` 的分布是雙峰的：大量落在 `1.00`（即 `D_c`）與 `0.00`（143–171 筆，模型在
20 個 epoch 中**每次**都預測成與觀測標籤相反的類別）。中間地帶稀疏。

### 9.2 §4.4 的預先登記預測：方向錯了

§4.4 預測「`D_c` 可能很小」，理由是 `r_i = 1` 是嚴格門檻而 §1.5 量到格子會整片翻面。
**實測 `D_c` 佔 55.5%–74.5%，不小。** 預測錯在哪：

- 格子翻面確實發生——26–30 個格子（113 個中的 23%–27%）整格落入 `D_n`，
  §4.4 的機制描述正確。
- 但**翻面的格子不是大格子**。最大的格子（219 筆）顯然穩定，否則 `D_c` 不可能超過 70%。
  §4.4 以「最大的格子有 219 筆」推論風險，推論的是上界而非實際值，而上界沒有發生。

**`|D_c|` 的 seed 間差異很大**（786 vs 1,056，相差 270 筆、19 個百分點），
這與 §1.5 的震盪一致：切分對初始化敏感。3 個 seed 不足以描述這個分散度，
此為 §6.5 已載明的統計力限制的具體後果。

### 9.3 §5.5 的線索：格內同質化成立，但觸發條件抓不到它

§5.5 預先登記了一條線索：`agreement_training_label_vs_cell_majority`
「隨 epoch 單調上升且趨近 1.0，即為格內同質化，當場停下來檢查」。

| | M2（常數） | M3 warm-up（epoch 1–5） | M3 首次重組後（epoch 6–100） |
|---|--:|--:|--:|
| `agreement_training_label_vs_cell_majority` | 0.8518 | 0.998 | 0.949／0.964／0.882 |
| `distinct_training_labels_per_cell_mean` | 1.239 | **1.000** | **1.000** |

**兩件事同時成立，而且 §5.5 寫的那個觸發條件沒有被滿足：**

1. **格內同質化是完全的，而且從階段二第一個 epoch 就是。**
   `distinct_training_labels_per_cell_mean` 恆為 **1.000**——每個格子內進 loss 的樣本
   標籤完全一致。這不是逐漸演化出來的，而是**重組規則的結構後果**：模型對同一格輸出
   同一個 EMA 標籤，而重組只留下標籤與 EMA 一致的樣本，因此同一格內進 loss 的樣本
   必然同標籤。§5.5 的推論正確，但它低估了程度——不是「趨近」，是立即且恆為 1.000。
2. **`agreement_training_label_vs_cell_majority` 並未單調上升趨近 1.0，而是在首次重組時
   下降**（0.998 → 0.88–0.96）。原因是這個指標比的是「格內 **observed** 多數」，
   而重組後標籤收斂到的是「模型對該格的 EMA 標籤」，兩者並不總是相同。

因此必須記載：**§5.5 設計的觸發條件若照字面執行，不會在這次執行中觸發，
而真正抓到同質化的是 `distinct_training_labels_per_cell_mean`。**
報告應以後者為主要證據，並說明前者為何失效——它預設了收斂目標是 LF 的格內多數，
但實際的收斂目標是模型自己的格內判定。

### 9.4 翻標籤的方向：也與 §5.5 的預測相反

§5.5 預測被翻的會是衝突格的少數類，且「若其所在格子的多數是 negative（依 LF 的分布
很可能如此），被漏判的真 positive 會**被翻成 negative，等於強化錯誤**」。

實測（只用 `observed_authz_label` 與 `pseudo_label`，未讀 Gold）：

| seed | 以 pseudo 進 loss | negative → positive | positive → negative | `positive_share_of_training_labels` |
|---|--:|--:|--:|---|
| 20260823 | 176 | **102** | 74 | 0.273 → 0.288 |
| 20260824 | 188 | **120** | 68 | 0.273 → 0.329 |
| 20260825 | 207 | **169** | 38 | 0.273 → 0.472 |

**翻的方向以 negative → positive 為主（58%／64%／82%），與預測相反。**
`→observed` 的翻回 **0 筆**：176／188／207 筆全部在 epoch 6（首次重組）進來，
之後 100 個 epoch 內沒有任何一筆翻回 observed。

這個方向**恰好對應** `authz_lf_spec_v1.md` §6.1 量到的噪音結構：LF 的錯誤集中在
把真 positive 標成 negative（65 筆漏判、recall 僅 0.177）。SLB 把標籤往 positive 推，
方向上與已知的噪音方向一致。

**但這不等於 SLB 修對了。** 方向正確與「翻到的是對的那幾筆」是兩件事，後者必須與 Gold
比對才知道，屬於下一個獨立步驟。本節只記錄方向，不作效果宣稱。

### 9.5 階段二的 `train_accuracy` 恆為 1.0000，而它沒有診斷力

三個 seed 的階段二訓練準確率都是 **1.0000**，高於 §1.2 的格子多數決上限 0.8518。
**這不是洩漏，是重組規則的恆真式**：

```
重組只把「標籤與模型 EMA 判定一致」的樣本留在 D_c（Algorithm 2 line 29–32）
α = 0.95 使 EMA 幾乎等於當下的預測（§7.1 第 2 項）
→ D_c 內每一筆的標籤本來就等於模型的預測
→ 在 D_c 上量訓練準確率必然接近 1.0
```

母體也不同：§1.2 的 0.8518 是 1,417 筆全體的格子多數決上限，階段二只在 `D_c`
（1,058–1,300 筆）上訓練，且標籤已被修正。

**後果：`train_accuracy` 在 M3 階段二是一個無資訊的欄位**，不得與 M2 的 0.8419 並列比較，
也不得作為 sanity check。程式因此把它降級為 warning 而非中止（M2 仍然中止），
並在訊息中說明理由。M3 可用的 sanity check 是階段一的訓練準確率——它與 M2 同母體、
同標籤，應落在 0.852 以下。

### 9.6 產物

```
experiments/slb_epoch_metrics.jsonl              +360 列（3 run × 120 epoch），全檔 660 列
experiments/predictions_m3-seed<s>.jsonl         各 1,801 列
experiments/slb_run_manifest_m3-seed<s>.json     各 1 份，含 audit 檔的 SHA-256 與未壓縮列數
models/m3-seed<s>.pt                             最後一個 epoch 的模型
label_revision_audit_m3-seed<s>.jsonl.gz         各 170,040 列（1,417 × 120）、約 9.0 MB
```

audit log 三份合計 27 MB，壓縮前約 240 MB，與 §7.4 的估計一致。

### 9.7 下一步不屬於本文件

M2 與 M3 的 6 次執行到此完成，**全程未讀取 Gold**。接下來的評估（與 Gold 比對、
對照第九章的三條參考線 0.439／0.519／0.695、以及 `authz_lf_spec_v1.md` §6.1 那 65 筆
漏判有沒有被救回）是獨立步驟，不在本規格範圍內。本文件的任務——把設定凍結、
把執行做完、把程序記錄下來——已結束。
