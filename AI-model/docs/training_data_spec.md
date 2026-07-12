# Training Data Specification v1（訓練資料規格 v1）

本文件定義 APK row-level ML 任務的 v1 訓練資料格式。訓練資料由 dataset
builder 在呼叫 `build_model_features()` 之後產出。

## 1. 訓練樣本格式

每個訓練樣本是一筆 JSONL record：

```json
{
  "sample_id": "com.example.app__v1.0__abc123",
  "row_type": "filter",
  "features": {
    "component_type": "service",
    "permission": "<NONE>",
    "exported": true,
    "protected": false,
    "has_action_android_intent_action_view": true
  },
  "label": 1,
  "label_source": "rule_weak_label",
  "split": "train"
}
```

頂層欄位：

| 欄位 | 型別 | 可能值 | 說明 |
| --- | --- | --- | --- |
| `sample_id` | `str` | `{package_name}__{version_name}__{apk_sha256[:8]}` | 由 dataset builder 在蒐集 APK 時產生。 |
| `row_type` | `str` | `filter`, `resolution` | `intent` row 不納入 v1 訓練資料。 |
| `features` | `object` | 見第 2 節 | row 層級的模型輸入特徵。 |
| `label` | `int` | `0`, `1` | 由 dataset builder 產生的 weak label。 |
| `label_source` | `str` | `rule_weak_label` | v1 僅使用 rule-based 的 weak label。 |
| `split` | `str` | `train`, `val`, `test` | 在 APK 層級指定的資料集切分。 |

## 2. 特徵

### 2.1 filter_row 特徵

`filter` 訓練樣本使用以下固定欄位，加上從 `build_model_features()` 輸出
複製而來的動態 multi-hot 欄位。

固定欄位：

| 欄位 | 型別 | 缺值時的值 | 說明 |
| --- | --- | --- | --- |
| `component_type` | `str` | `<NONE>` | `activity`、`service`、`provider`、`receiver` 其中之一。 |
| `permission` | `str` | `<NONE>` | 元件的 `android:permission` 值。 |
| `exported` | `bool` | 必填 | 該元件是否為 exported。 |
| `protected` | `bool` | 必填 | 該元件是否具備 permission 保護。 |

動態 multi-hot 欄位：

| 前綴 | 型別 | 缺欄位時的語意 |
| --- | --- | --- |
| `has_action_*` | `bool` | 缺欄位視為 `False`。 |
| `has_category_*` | `bool` | 缺欄位視為 `False`。 |
| `has_data_type_*` | `bool` | 缺欄位視為 `False`。 |

`exported` 與 `protected` 同時出現在 `features` 與 label 定義中，這是已知
的 data leakage 風險。v1 模型接受此限制，Task 8 的實驗報告中必須明確揭露
此點。

### 2.2 resolution_row 特徵

`resolution` 訓練樣本使用：

| 欄位 | 型別 | 缺值時的值 | 說明 |
| --- | --- | --- | --- |
| `match_action` | `bool` | 必填 | intent 與 filter 的 action 是否相符。 |
| `match_category` | `bool` | 必填 | intent 與 filter 的 category 是否相符。 |
| `match_type` | `bool` | 必填 | intent 與 filter 的 MIME type 是否相符。 |
| `caller_permission` | `str` | `<NONE>` | 呼叫端（caller）的 permission。 |
| `callee_permission` | `str` | `<NONE>` | 接收端（receiver）的 permission。 |
| `risk_hint` | `str` | `<NONE>` | 弱風險提示，例如 `IPC_SERVICE_HIJACK`。 |

resolution_row 模型框架已於 Task 6 實作，但仍列為 pending v2。在 v1 中，
`intent_row` record 是由 `filter_row` record 以 1:1 方式推斷而來，sender
固定為 `<UNKNOWN>`，因此 `match_*` 欄位恆為 `True`，不具鑑別力。

## 3. Label 轉換規則

Label 由 dataset builder 產生。Parser 與 encoder 程式碼不得自行產生
label。

### filter_row

```python
label = 1 if (row["exported"] == True and row["protected"] == False) else 0
```

**已知限制 — `IPC_PROVIDER_URI_GRANT_BYPASS` 無法被這個 label 公式表達。**
這個 finding 發生在 ContentProvider 已設定 `readPermission`/
`writePermission`（`protected == True`）、但同時 `grantUriPermissions=true`
可能繞過該保護的情境。在上述公式下，只要 `protected == True`，該 row 的
label 恆為 `0`，無論 `grant_uri_permissions` 為何——即使 Stage 2 report
已正確標記出這個 finding，這個 pattern 也永遠不會成為 `filter_row` 模型的
正樣本。Toy scenario E-5 就是具體案例：它在規則引擎中觸發了
`IPC_PROVIDER_URI_GRANT_BYPASS`，但其 `filter_row` label 仍是 `0`。

**決策（2026-07-12）：** v1 階段**不**擴充 label 公式，也不修改
`feature_schema.json`；`grant_uri_permissions` 維持排除在 encoder 特徵集
之外（依循 2026-07-07 的決策紀錄）。理由：

- 此規則的 confidence 僅 `0.5`（「manifest-only 分析無法確認是否真的被
  濫用」），信心度過低，不足以提升為硬性正樣本 label。
- 若只擴充 label 而不同步把 `grant_uri_permissions` 加進特徵，模型將完全
  無法區分這類 row 與真正安全的 protected row；而僅為了這個目的才新增
  特徵，會把兩個原本各自獨立決策的設計選項綁在一起。
- 依本專題規則引擎與 ML 的分工原則，規則引擎（Stage 2 report）已經以
  完整可解釋的方式呈現這個 finding；`filter_row` 模型只是輔助角色，
  不需要覆蓋所有 finding 類型才算有效。

此落差必須在實驗報告中明確揭露（與第 2.1 節既有的 leakage note 一併
說明），並以 toy scenario E-5 作為示範案例。

### resolution_row

```python
label = 1 if (row["risk_hint"] is not None and row["risk_hint"] != "<NONE>") else 0
```

### intent_row

v1 不為 `intent_row` 產生 label，`intent_row` record 也不會進入訓練資料集。

## 4. 切分規則（Split Rules）

切分在 APK 層級指定：

- 切分單位：整個 APK。同一個 APK 的所有 row 必須留在同一個 split。
- 比例：`train` 70%、`val` 15%、`test` 15%。
- 方法：先將 APK 清單 shuffle，再依比例切分。
- 隨機種子：`random_state=42`。
- 禁止事項：不得以 row 為單位切分。以 row 為單位切分可能讓同一個 APK 的
  row 同時出現在 train 與 test set 中，造成 data leakage。

## 5. 類別不平衡處理

v1 資料集預期正樣本比例低於 50%，因為真實 APK 不會讓每一個元件都在無保護
狀態下 exported。

所有 v1 模型訓練皆使用：

```python
class_weight='balanced'
```

這是固定的 trainer 預設值，不依觀察到的資料集分布而調整。