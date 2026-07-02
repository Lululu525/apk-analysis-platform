# Scenario B Case 4 — APK 靜態分析報告

## 基本資訊

| 欄位 | 值 |
|------|-----|
| **Job ID** | `scenario_b_case4` |
| **Package** | `com.toyapk.scenario_b.case4` |
| **SHA-256** | `727fafeeab15c109ccadeda8152a666ef41c970b5e8fae646df78950a85694e9` |
| **APK 大小** | 7,060,693 bytes (6.73 MB) |
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
| `com.toyapk.scenario_b.case4.MainActivity` | `true` | `false` |

### Services

| 元件名稱 | Exported | Protected | Intent Filter (Actions) |
|-----------|----------|-----------|------------------------|
| `com.toyapk.scenario_b.case4.MyService` | `true` | `false` | `com.toyapk.scenario_b.case4.action.PROCESS` |

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
| `com.toyapk.scenario_b.case4.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` |

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
| `com.toyapk.scenario_b.case4.MainActivity` | action: `android.intent.action.MAIN`, category: `android.intent.category.LAUNCHER` |

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

**Evidence:**

| Service | Intent Filter Action | Attack Type |
|---------|----------------------|-------------|
| `com.toyapk.scenario_b.case4.MyService` | `com.toyapk.scenario_b.case4.action.PROCESS` | Service Hijacking |

> `MyService` 同時具有 intent filter（`action.PROCESS`），任何外部 app 均可透過**隱式 Intent** 直接觸達此 service，無需知道元件全名，攻擊門檻低於 Case 1。

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
| MyService 存在且 exported=true, protected=false | 是 | exported=true, permission=null | PASS |
| MyService 含 intent filter（隱式可達） | 是 | action: `action.PROCESS` | PASS |
| 觸發 IPC_SERVICE_HIJACK | 觸發 | 已觸發（severity=high, score=6.660） | PASS |
| resolution_row 中 risk_hint=IPC_SERVICE_HIJACK | 是 | `risk_hint: "IPC_SERVICE_HIJACK"` | PASS |
| 風險分數 = 83 / Critical | 83 | 83 / Critical | PASS |

---

## 備註

Case 4 與 Case 1 的結構幾乎相同（`MyService` exported=true 且無保護），核心差異在於 Case 4 的 `MyService` 宣告了 **intent filter**（`action.PROCESS`）。這使得 service 可透過隱式 Intent 被任意外部 app 觸及，而不需要明確指定元件名稱，實際攻擊難度更低。

Pipeline 正確捕捉此 finding，resolution_row 中 `risk_hint=IPC_SERVICE_HIJACK` 指向 `MyService`，且 intent filter action 完整記錄於 filter_rows。

各 Case 風險分數對照（含 Case 4）：

| Case | MyService 狀態 | Intent Filter | IPC_SERVICE_HIJACK | 風險分數 |
|------|---------------|--------------|-------------------|---------|
| Case 0 | exported=false | — | 未觸發 | 75 / High |
| Case 1 | exported=true, 無保護 | 無 | 觸發（explicit only） | 83 / Critical |
| Case 2 | exported=true, 有保護 | 無 | 未觸發 | 75 / High |
| Case 3 | 2 services（1 保護 + 1 未保護） | 無 | 觸發（UnprotectedService） | 83 / Critical |
| Case 4 | exported=true, 無保護 | `action.PROCESS`（隱式可達） | 觸發 | 83 / Critical |

Findings #2 和 #4 仍為 AndroidX library 元件誤報（同前各 Case）。
