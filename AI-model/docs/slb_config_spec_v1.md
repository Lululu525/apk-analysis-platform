# M2／M3 訓練與 SLB 設定規格 v1

狀態：**逐項討論中**。執行順序第 5c 項（ADR-0002）。

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
| 5 | `label_revision_audit.jsonl` 的欄位 | 待討論 |
| 6 | 與論文原文的對照與修正紀錄 | **2026-10-03** 新增 |

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
  EMA 初始值取自階段一的 softmax 輸出
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

## 5. `label_revision_audit.jsonl` 的欄位

待討論。

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
