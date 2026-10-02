# M2／M3 訓練與 SLB 設定規格 v1

狀態：**逐項討論中**。執行順序第 5c 項（ADR-0002）。

本文件凍結 M2（vanilla MLP）與 M3（MLP + SLB）的全部訓練設定。依
`authz_label_spec.md` §10 與時程表 `:453`，**Gold 授權標籤不得用於選擇 epoch、
threshold 或任何超參數**。

| # | 項目 | 狀態 |
|--:|---|---|
| 1 | Epoch 預算與 early stopping | **已定案**（2026-10-02） |
| 1b | Optimizer 與其餘訓練超參數 | **已定案**（2026-10-02） |
| 2 | Warm-up 長度 | 待討論 |
| 3 | Consistency ratio 的定義 | 待討論 |
| 4 | Clean／noisy 的切分方式 | 待討論 |
| 5 | `label_revision_audit.jsonl` 的欄位 | 待討論 |

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

**TOTAL_EPOCHS = 待診斷執行後填入。**

## 1b. Optimizer 與其餘訓練超參數

原待決定清單未列出這些，但它們同樣是超參數，同樣需要凍結，否則「沒有調參」的說法不成立。

**全部採用標準預設值，刻意不調。** 理由與 1.1 相同：調參需要一把尺，而這裡沒有可用的尺。
報告須明載「這些值未經任何搜尋」。

| 項目 | 值 | 依據 |
|---|---|---|
| Optimizer | Adam | 已於模型設計定案 |
| Learning rate | `1e-3` | PyTorch `Adam` 預設值 |
| Batch size | 64 | 1,417 筆下約 22 個 batch／epoch，足以產生 SLB 需要的 minibatch 隨機性 |
| Loss | CrossEntropy + class weight | 已於模型設計定案 |
| Class weight | 反比於訓練池實際頻率（positive 387、negative 1,030） | 不以 Gold 分布設定 |
| Dropout | 0.3（兩層隱藏層） | 已於模型設計定案 |
| 架構 | 31 → 128 → 64 → 2，ReLU，softmax | 已於模型設計定案 |
| Seeds | `20260823`、`20260824`、`20260825` | 已於模型設計定案 |

可重現性：`torch`、`numpy`、`random` seed、`cudnn.deterministic`、DataLoader worker seed
全部鎖定，並將 fingerprint 寫入 audit log。

## 2. Warm-up 長度

待討論。

## 3. Consistency ratio 的定義

待討論。

> 已知的關鍵問題，待第 3 項展開：那 210 筆落在衝突格子少數類的樣本，模型對它們是
> **穩定地答錯**，不是搖擺。「預測類別不變的 epoch 比例」會把它們判為高 consistency、
> 因而 clean、因而永不修正；「預測與給定標籤一致的 epoch 比例」則會判為 noisy。
> 兩種定義在本資料上導致相反的結果，不是風格差異。

## 4. Clean／noisy 的切分方式

待討論。

## 5. `label_revision_audit.jsonl` 的欄位

待討論。
