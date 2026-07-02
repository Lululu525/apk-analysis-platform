# Scenario B Case 3 — APK 靜態分析報告

## 基本資訊

| 欄位 | 值 |
|------|-----|
| **Job ID** | `scenario_b_case3` |
| **Package** | `com.toyapk.scenario_b.case3` |
| **SHA-256** | `6e2b6b1bb2d4cb4e99bd5ec2e18c27cac9ce62713b4551d5c94abd01c35d08b7` |
| **APK 大小** | 7,060,811 bytes (6.73 MB) |
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
| `com.toyapk.scenario_b.case3.MainActivity` | `true` | `false` |

### Services

| 元件名稱 | Exported | Protected | Permission |
|-----------|----------|-----------|------------|
| `com.toyapk.scenario_b.case3.ProtectedService` | `true` | `true` | `com.toyapk.scenario_b.case3.permission.BIND_PROTECTED` |
| `com.toyapk.scenario_b.case3.UnprotectedService` | `true` | `false` | — |

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
| `com.toyapk.scenario_b.case3.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` |

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
| `com.toyapk.scenario_b.case3.MainActivity` | action: `android.intent.action.MAIN`, category: `android.intent.category.LAUNCHER` |

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

| Service | Attack Type |
|---------|-------------|
| `com.toyapk.scenario_b.case3.UnprotectedService` | Service Hijacking |

> `ProtectedService` 有 `android:permission` 保護，pipeline 正確略過，**僅對 `UnprotectedService` 觸發**。

**Score Breakdown:**

| base | confidence | exploitability | impact | exposure | **final** |
|------|------------|----------------|--------|----------|-----------|
| 4.0 | 0.90 | 1.68 | 1.25 | 1.0 | **7.560** |

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
| ProtectedService 存在且 exported=true, protected=true | 是 | exported=true, permission=BIND_PROTECTED | PASS |
| UnprotectedService 存在且 exported=true, protected=false | 是 | exported=true, 無 permission | PASS |
| IPC_SERVICE_HIJACK 僅對 UnprotectedService 觸發 | 僅 UnprotectedService | evidence 中只列 UnprotectedService | PASS |
| IPC_SERVICE_HIJACK 不對 ProtectedService 觸發 | 不觸發 | ProtectedService 未出現於 evidence | PASS |
| 風險分數 = 83 / Critical | ≥ 83 | 83 / Critical | PASS |

---

## 備註

Case 3 為**混合情境**：同一 APK 內同時存在一個有權限保護的 service（`ProtectedService`）與一個無保護的 service（`UnprotectedService`）。Pipeline 正確區分兩者，僅對 `UnprotectedService` 觸發 `IPC_SERVICE_HIJACK`，驗證了逐元件精確分析的能力。

`IPC_SERVICE_HIJACK` 的 exploitability 分數（1.68）高於 Case 1（1.48），反映此 APK 存在兩個 exported service，攻擊面相對更大。

五個 Case 風險分數對照：

| Case | 說明 | IPC_SERVICE_HIJACK | 風險分數 |
|------|------|--------------------|---------|
| Case 0 | MyService exported=false | 未觸發 | 75 / High |
| Case 1 | MyService exported=true, 無保護 | 觸發 | 83 / Critical |
| Case 2 | MyService exported=true, 有保護 | 未觸發 | 75 / High |
| Case 3 | ProtectedService + UnprotectedService | 觸發（僅 UnprotectedService） | 83 / Critical |

Findings #2 和 #4 仍為 AndroidX library 元件誤報（同前各 Case）。
