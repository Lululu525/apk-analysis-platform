# Hidden Privilege Vector Spec v1

**版本**：v1.0  
**日期**：2026-05-20  
**適用階段**：Task 2（Parser）、Task 4（資料格式）、Task 6（Model MVP）

---

## 概述

本文件定義三種 row-level feature schema，作為 Parser、Dataset、Model 的**共用規格**。

任何模組（Extractor、Feature Builder、Encoder、Trainer）都應以本文件為唯一的欄位定義依據。
欄位名稱、型別、缺值策略一旦在此確定，不得在模組間各自解釋。

**來源論文**：El-Zawawy & Hamdy,
*"Detection of Hidden Privilege Escalations in Android"*,
Automated Software Engineering 2025, 32:68

論文原始 feature vector（intent 側 / filter 側共用同一組欄位）：
```
[component, action, category, data_scheme, data_type, permission]
```

本 spec 將其**拆為三種語意不同的 row 型別**，對應論文 Section 3.2 中描述的三層分析結構：

| row_type | 語意 | 對應論文概念 | 資料來源 |
|----------|------|-------------|---------|
| `intent_row` | 某 component 發出的一個 Intent（呼叫端） | Intent vector (sender side) | manifest 推斷 + bytecode（v2） |
| `filter_row` | 某 component 宣告的 intent-filter entry（接收端） | Filter vector (receiver side) | manifest |
| `resolution_row` | 一個 intent × filter 的解析配對（IPC 事件） | Resolution = sender+receiver combined | manifest 內部 matching |

---

## 通用規則

1. **encoder 核心欄位**：v1 模型 encoder 只使用 `action`、`category`、`data_type`、`permission`
   四個欄位（論文對齊），其餘欄位用於 dataset 管理、可解釋性、filtering。
2. **缺值編碼**：所有 categorical 欄位缺值一律轉為 `"<NONE>"`，由 `OneHotEncoder(handle_unknown="ignore")` 處理。
3. **`data_scheme`**：保留為輔助欄位（v1 encoder 不使用），未來 v2 可加入。
4. **`sample_id`** 規格：格式為 `{job_id}` 或 `{sha256_8hex}`，pipeline 注入，不由 Parser 產生。

---

## 1. intent_row

代表「某 App/Component **發出**的一個 Intent（呼叫端視角）」。

在 manifest-only 解析階段，intent_row 是**從 filter_row 反向推斷**的：若某 component 宣告了
intent-filter，則系統中必然存在對應的呼叫者；此時 `source="manifest_only"`，
`is_explicit=False`（manifest 不揭露呼叫者是誰）。
Bytecode extractor（v2）可補強真實的呼叫端 component。

### Schema

| 欄位 | 型別 | 說明 | 來源 | 缺值策略 |
|------|------|------|------|---------|
| `sample_id` | `str` | APK 唯一識別碼（pipeline 注入） | pipeline | 必填，不得缺值 |
| `package_name` | `str` | 呼叫端 App 的 package name | manifest | 必填，不得缺值 |
| `component_name` | `str` | 發起 intent 的 component 全名（FQCN） | manifest / bytecode | manifest-only 時填 `"<UNKNOWN>"` |
| `component_type` | `str` | `activity` / `service` / `provider` / `receiver` | manifest | manifest-only 時填 `"<UNKNOWN>"` |
| `action` | `str \| None` | Intent action（如 `android.intent.action.VIEW`） | manifest / bytecode | `None` → encoder 轉 `"<NONE>"` |
| `category` | `str \| None` | Intent category | manifest / bytecode | `None` → encoder 轉 `"<NONE>"` |
| `data_type` | `str \| None` | MIME type（如 `image/*`） | manifest / bytecode | `None` → encoder 轉 `"<NONE>"` |
| `data_scheme` | `str \| None` | URI scheme（如 `content`、`http`）— 輔助欄位 | manifest | `None`，v1 encoder 不使用 |
| `permission` | `str \| None` | Caller 持有的 permission（用於 resolution matching） | manifest permissions[] | `None` → encoder 轉 `"<NONE>"` |
| `is_explicit` | `bool` | 是否為 explicit intent（直接指名 component） | bytecode | manifest-only 時固定 `False` |
| `source` | `str` | `"manifest_only"` / `"bytecode"` | pipeline | 必填 |

**v1 encoder 輸入欄位**（順序固定）：`action`, `category`, `data_type`, `permission`

---

## 2. filter_row

代表「某 component **宣告**的一個 intent-filter entry（接收端視角）」。

每個 intent-filter XML 元素的每個 (action, category, data_type) 組合**各產生一筆 row**
（笛卡爾積展開，與現行 `_flatten_intents()` 邏輯一致）。

### Schema

| 欄位 | 型別 | 說明 | 來源 | 缺值策略 |
|------|------|------|------|---------|
| `sample_id` | `str` | APK 唯一識別碼（pipeline 注入） | pipeline | 必填 |
| `package_name` | `str` | 接收端 App 的 package name | manifest | 必填 |
| `component_name` | `str` | 宣告此 filter 的 component 全名（FQCN） | manifest | 必填 |
| `component_type` | `str` | `activity` / `service` / `provider` / `receiver` | manifest | 必填 |
| `action` | `str \| None` | filter 接受的 action | manifest `<action>` | `None` → encoder 轉 `"<NONE>"` |
| `category` | `str \| None` | filter 接受的 category | manifest `<category>` | `None` → encoder 轉 `"<NONE>"` |
| `data_type` | `str \| None` | filter 接受的 MIME type | manifest `<data android:mimeType>` | `None` → encoder 轉 `"<NONE>"` |
| `data_scheme` | `str \| None` | filter 接受的 URI scheme — 輔助欄位 | manifest `<data android:scheme>` | `None`，v1 encoder 不使用 |
| `permission` | `str \| None` | Callee 要求 caller 持有的 permission | manifest `android:permission` 屬性 | `None` → encoder 轉 `"<NONE>"` |
| `exported` | `bool` | component 是否 exported（有 intent-filter 時視為 True） | manifest `android:exported` | 有 intent-filter 時強制 `True` |
| `protected` | `bool` | component 是否有 `android:permission` 保護 | manifest | `permission is None` → `False` |

**v1 encoder 輸入欄位**（順序固定）：`action`, `category`, `data_type`, `permission`

**重要識別模式**：`exported=True AND protected=False` 是以下攻擊的前提條件：
- `IPC_SERVICE_HIJACK`（service）
- `IPC_BROADCAST_THEFT`（receiver）
- `IPC_CONFUSED_DEPUTY`（activity + dangerous permissions held）
- `IPC_PROVIDER_REDELEGATION`（provider）

---

## 3. resolution_row

代表「一個 intent 與一個 filter 的 matching 結果（App 內部 IPC 配對）」。

v1 只做**同一 APK 內**的 implicit intent matching（intent_row × filter_row 的笛卡爾積，
篩選符合 action/category/type 的配對）。跨 App n-order chain 不在 v1 範圍內。

### Schema

| 欄位 | 型別 | 說明 | 缺值策略 |
|------|------|------|---------|
| `sample_id` | `str` | APK 唯一識別碼 | 必填 |
| `intent_component_name` | `str` | 發起 intent 的 component | `"<UNKNOWN>"` |
| `intent_component_type` | `str` | 發起 component 類型 | `"<UNKNOWN>"` |
| `intent_action` | `str \| None` | Intent 的 action | `None` → `"<NONE>"` |
| `intent_category` | `str \| None` | Intent 的 category | `None` → `"<NONE>"` |
| `intent_data_type` | `str \| None` | Intent 的 MIME type | `None` → `"<NONE>"` |
| `intent_permission` | `str \| None` | Caller 持有的 permission | `None` → `"<NONE>"` |
| `filter_component_name` | `str` | 接收 filter 的 component | 必填 |
| `filter_component_type` | `str` | 接收 component 類型 | 必填 |
| `filter_action` | `str \| None` | filter 宣告的 action | `None` → `"<NONE>"` |
| `filter_category` | `str \| None` | filter 宣告的 category | `None` → `"<NONE>"` |
| `filter_data_type` | `str \| None` | filter 宣告的 MIME type | `None` → `"<NONE>"` |
| `filter_permission` | `str \| None` | Callee 要求的 permission | `None` → `"<NONE>"` |
| `filter_exported` | `bool` | 接收端是否 exported | 必填 |
| `filter_protected` | `bool` | 接收端是否有 permission 保護 | 必填 |
| `match_action` | `bool` | `intent_action == filter_action` 或雙方皆 None | 必填 |
| `match_category` | `bool` | `intent_category ∈ filter.categories` 或雙方皆 None | 必填 |
| `match_type` | `bool` | `intent_data_type` 符合 filter MIME pattern 或雙方皆 None | 必填 |
| `caller_permission` | `str \| None` | Caller 持有的 permission（= intent_permission） | `None` |
| `callee_permission` | `str \| None` | Callee 要求的 permission（= filter_permission） | `None` |
| `risk_hint` | `str \| None` | 由 `privilege_rules.py` 注入的弱標註 hint | `None` |

**`risk_hint` 可能值**（來自 `privilege_rules.check_combinations()`）：

| 值 | 觸發條件 |
|----|---------|
| `IPC_SERVICE_HIJACK` | filter_type=service, exported=True, protected=False |
| `IPC_BROADCAST_THEFT` | filter_type=receiver, exported=True, protected=False, sensitive action |
| `IPC_CONFUSED_DEPUTY` | filter_type=activity, exported=True, protected=False, app 持有 dangerous perms |
| `IPC_PROVIDER_REDELEGATION` | filter_type=provider, exported=True, protected=False |
| `None` | 無上述條件 |

**v1 encoder 輸入欄位**（順序固定）：
`intent_action`, `intent_category`, `intent_data_type`, `intent_permission`,
`filter_action`, `filter_category`, `filter_data_type`, `filter_permission`

---

## 4. parse_manifest.py 輸出差異表

現行 `build_features()` 的 `intents` 陣列在語意上最接近 **filter_row（接收端）**，
因為資料來源是 manifest 中各 component 的 `<intent-filter>` 元素。

### intent_row 差異

| 欄位 | 需求 | 現況 | 狀態 |
|------|------|------|------|
| `sample_id` | 必填 | 無 | ❌ 缺少 |
| `package_name` | 必填 | `result.package_name` 存在但未放入 row | ❌ 缺少 |
| `component_name` | 必填 | `component` 欄位（字串，僅名稱） | ⚠️ 欄位名稱需改為 `component_name` |
| `component_type` | 必填 | `ComponentInfo.type` 存在但未輸出 | ❌ 缺少 |
| `action` | 核心 | ✓ `action` | ✅ 已支援 |
| `category` | 核心 | ✓ `category` | ✅ 已支援 |
| `data_type` | 核心 | ✓ `data_type` | ✅ 已支援 |
| `data_scheme` | 輔助 | ✓ `data_scheme` | ✅ 已支援 |
| `permission` | 核心 | ✓ `permission`（component-level） | ✅ 已支援 |
| `is_explicit` | 必填 | 無 | ❌ 缺少（manifest-only 固定 False） |
| `source` | 必填 | 無 | ❌ 缺少（固定 "manifest_only"） |

### filter_row 差異

| 欄位 | 需求 | 現況 | 狀態 |
|------|------|------|------|
| `sample_id` | 必填 | 無 | ❌ 缺少 |
| `package_name` | 必填 | 無（已有 result.package_name） | ❌ 缺少 |
| `component_name` | 必填 | `component` 欄位 | ⚠️ 欄位名稱需改為 `component_name` |
| `component_type` | 必填 | 未輸出（ComponentInfo 有） | ❌ 缺少 |
| `action` | 核心 | ✓ | ✅ |
| `category` | 核心 | ✓ | ✅ |
| `data_type` | 核心 | ✓ | ✅ |
| `data_scheme` | 輔助 | ✓ | ✅ |
| `permission` | 核心 | ✓ | ✅ |
| `exported` | 必填 | 未輸出（ComponentInfo 有 `comp.exported`） | ❌ 缺少 |
| `protected` | 必填 | 未輸出（可由 `comp.permissions_required` 推導） | ❌ 缺少 |

### resolution_row 差異

| 欄位 | 需求 | 現況 | 狀態 |
|------|------|------|------|
| 全部欄位 | 必填 | 完全未實作 | ❌ 缺少（整個 resolution_row 層） |

### 其他缺口

| 缺口 | 說明 |
|------|------|
| encoder schema | `feature_schema.json` 尚未定義；OneHotEncoder 的輸入欄位順序未固定 |
| label schema | `label`（0/1）、`label_source`（`"rule_weak_label"` 等）尚未定義 |
| `row_type` 欄位 | training format 需要 `row_type` 欄位區分 intent/filter/resolution |

---

## 5. Task 2 Parser 實作需求摘要

依本 spec，`build_model_features(apk_path)` 需要新增下列能力：

1. **filter_row 補齊**：在現有 `_flatten_intents()` 基礎上加入
   `component_type`、`exported`、`protected`；由呼叫方注入 `sample_id`、`package_name`。

2. **intent_row 產生**：v1 從 filter_row 反推（每個 filter_row 對應一個推斷的 intent_row），
   固定 `is_explicit=False`、`source="manifest_only"`，`component_name/type="<UNKNOWN>"`。

3. **resolution_row 產生**：在同一 APK 的 intent_row × filter_row 中執行 implicit matching，
   輸出符合 action/category/type 三項條件的配對，並由 `privilege_rules` 注入 `risk_hint`。

4. **`app_summary`** 保持與現行 `build_features()` 相容，不影響現有測試。

---

## 6. 版本歷程

| 版本 | 日期 | 異動 |
|------|------|------|
| v1.0 | 2026-05-20 | 初版，定義三種 row schema；完成 parse_manifest.py 差異表 |
