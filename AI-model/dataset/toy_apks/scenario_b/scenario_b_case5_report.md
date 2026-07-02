# Scenario B Case 5 — APK 靜態分析報告

## 基本資訊

| 欄位 | 值 |
|------|-----|
| **Job ID** | `scenario_b_case5` |
| **Package** | `com.toyapk.scenario_b.case5` |
| **SHA-256** | `40c24fb1454adb99b3460d5b33cd1ffc2349270f40d9e083db9ae013ab8e50de` |
| **APK 大小** | 7,060,888 bytes (6.73 MB) |
| **檔案總數** | 1,007 |
| **掃描檔案數** | 156 |
| **字串數量** | 5,000 (上限截斷) |
| **字串擷取方式** | `dex_parser+per_file` |
| **Status** | `success` |
| **Min SDK** | 23 |
| **Target SDK** | 37 |
| **Version** | 1.0 (code=1) |

---

## 風險摘要

| 風險分數 | 風險等級 | Critical | High | Medium | Low | Info |
|----------|----------|----------|------|--------|-----|------|
| **83** | **Critical** | 1 | 1 | 2 | 0 | 0 |

---

## 元件清單

### Activities

| 元件名稱 | Exported | Protected |
|-----------|----------|-----------|
| `com.toyapk.scenario_b.case5.MainActivity` | `true` | `false` |

### Services

| 元件名稱 | Exported | Protected | Intent Filter (Action) |
|-----------|----------|-----------|------------------------|
| `com.toyapk.scenario_b.case5.DataSyncService` | `true` | `false` | `com.toyapk.scenario_b.case5.action.SYNC_DATA` |
| `com.toyapk.scenario_b.case5.FileUploadService` | `true` | `false` | `com.toyapk.scenario_b.case5.action.UPLOAD_FILE` |

### Providers

| 元件名稱 | Exported | Protected |
|-----------|----------|-----------|
| `androidx.startup.InitializationProvider` | `true` | `false` |

### Receivers

| 元件名稱 | Exported | Protected |
|-----------|----------|-----------|
| `androidx.profileinstaller.ProfileInstallReceiver` | `true` | `false` |

---

## 權限

| 權限 |
|------|
| `com.toyapk.scenario_b.case5.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` |

---

## Findings（發現）

### 1. EXPORTED_UNPROTECTED_ACTIVITY

| 欄位 | 值 |
|------|-----|
| **Severity** | `medium` |
| **Confidence** | 0.95 |
| **Category** | `privilege_escalation` |
| **CWE** | CWE-926 |
| **Tags** | `exported_component`, `unprotected_component`, `activity` |

**Evidence:**

| Component | Intent Filters |
|-----------|----------------|
| `com.toyapk.scenario_b.case5.MainActivity` | action: `android.intent.action.MAIN`, category: `android.intent.category.LAUNCHER` |

**Score Breakdown:**

| base | confidence | exploitability | impact | exposure | **final** |
|------|------------|----------------|--------|----------|-----------|
| 3.0 | 0.95 | 1.4 | 1.0 | 1.512 | **6.033** |

---

### 2. EXPORTED_UNPROTECTED_RECEIVER

| 欄位 | 值 |
|------|-----|
| **Severity** | `medium` |
| **Confidence** | 0.95 |
| **Category** | `privilege_escalation` |
| **CWE** | CWE-926 |
| **Tags** | `exported_component`, `unprotected_component`, `receiver` |

**Evidence:**

| Component | Intent Filters |
|-----------|----------------|
| `androidx.profileinstaller.ProfileInstallReceiver` | `INSTALL_PROFILE`, `SKIP_FILE`, `SAVE_PROFILE`, `BENCHMARK_OPERATION` |

**Score Breakdown:**

| base | confidence | exploitability | impact | exposure | **final** |
|------|------------|----------------|--------|----------|-----------|
| 3.0 | 0.95 | 1.4 | 1.0 | 1.633 | **6.516** |

---

### 3. IPC_SERVICE_HIJACK

| 欄位 | 值 |
|------|-----|
| **Severity** | `high` |
| **Confidence** | 0.90 |
| **Category** | `ipc_privilege_escalation` |
| **CWE** | CWE-926, CWE-927 |
| **Reference** | El-Zawawy & Hamdy 2025, Section 3.2 |

**Evidence（2 個 service）：**

| Service | Intent Filter Action | Attack Type |
|---------|----------------------|-------------|
| `com.toyapk.scenario_b.case5.DataSyncService` | `action.SYNC_DATA` | Service Hijacking |
| `com.toyapk.scenario_b.case5.FileUploadService` | `action.UPLOAD_FILE` | Service Hijacking |

> 兩個 service 各自在 `resolution_rows` 中產生 `risk_hint: "IPC_SERVICE_HIJACK"`，pipeline 將其**合併為單一 finding**，evidence 中以列表形式列出全部受影響元件。

**Score Breakdown:**

| base | confidence | exploitability | impact | exposure | **final** |
|------|------------|----------------|--------|----------|-----------|
| 4.0 | 0.90 | 1.48 | 1.25 | 1.0 | **6.660** |

---

### 4. IPC_PROVIDER_REDELEGATION

| 欄位 | 值 |
|------|-----|
| **Severity** | `critical` |
| **Confidence** | 0.95 |
| **Category** | `ipc_privilege_escalation` |
| **CWE** | CWE-926, CWE-276 |
| **Reference** | El-Zawawy & Hamdy 2025, Section 3.2 |

**Evidence:**

| Provider | Attack Type |
|----------|-------------|
| `androidx.startup.InitializationProvider` | Permission Re-delegation via ContentProvider |

**Score Breakdown:**

| base | confidence | exploitability | impact | exposure | **final** |
|------|------------|----------------|--------|----------|-----------|
| 5.0 | 0.95 | 1.4 | 1.4 | 1.0 | **9.310** |

---

## 預期結果驗證

| 檢查項目 | 預期 | 實際 | 結果 |
|----------|------|------|------|
| DataSyncService 存在且 exported=true, protected=false | 是 | exported=true, 無 permission | PASS |
| FileUploadService 存在且 exported=true, protected=false | 是 | exported=true, 無 permission | PASS |
| 兩者各有 intent filter | 是 | SYNC_DATA / UPLOAD_FILE | PASS |
| 兩者在 resolution_rows 中均有 `risk_hint=IPC_SERVICE_HIJACK` | 是 | 兩列 risk_hint 均為 IPC_SERVICE_HIJACK | PASS |
| Finding evidence 同時列出兩個 service | 是 | evidence.services 含兩個名稱 | PASS |
| 風險分數 = 83 / Critical | 83 | 83 / Critical | PASS |

---

## 備註

Case 5 為**雙 unprotected service + 各帶 intent filter** 的情境，是 Case 4（單一帶 intent filter 的 unprotected service）的擴展版。兩個 service 均可透過隱式 Intent 被任意外部 app 觸達：

- `DataSyncService`：可接收 `SYNC_DATA` action，可能遭攻擊者觸發非預期的資料同步行為。
- `FileUploadService`：可接收 `UPLOAD_FILE` action，可能遭攻擊者觸發非預期的檔案上傳行為，具資料外洩風險。

Pipeline 正確將兩筆 `IPC_SERVICE_HIJACK` risk_hint **合併為單一 finding**，evidence.services 列表完整呈現兩個受影響元件，驗證了多元件批次彙整能力。

各 Case 風險分數對照：

| Case | Services 狀況 | Intent Filter | IPC_SERVICE_HIJACK | 風險分數 |
|------|--------------|--------------|-------------------|---------|
| Case 0 | MyService exported=false | — | 未觸發 | 75 / High |
| Case 1 | MyService exported=true, 無保護 | 無 | 觸發（1 service） | 83 / Critical |
| Case 2 | MyService exported=true, 有保護 | 無 | 未觸發 | 75 / High |
| Case 3 | ProtectedService + UnprotectedService | 無 | 觸發（1 service） | 83 / Critical |
| Case 4 | MyService exported=true, 無保護 | `action.PROCESS` | 觸發（1 service） | 83 / Critical |
| Case 5 | DataSyncService + FileUploadService（均無保護） | `SYNC_DATA` / `UPLOAD_FILE` | 觸發（2 services） | 83 / Critical |

Findings #2 和 #4 仍為 AndroidX library 元件誤報（同前各 Case）。
