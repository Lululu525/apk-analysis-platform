# Scenario B Case 2 — APK 靜態分析報告

## 基本資訊

| 欄位 | 值 |
|------|-----|
| **Job ID** | `scenario_b_case2` |
| **Package** | `com.toyapk.scenario_b.case2` |
| **SHA-256** | `9192c7099e2b121258537acb0d031e3eba87a16285eb845f945d6630e8760a75` |
| **APK 大小** | 7,060,700 bytes (6.73 MB) |
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
| **75** | **High** | 1 | 0 | 2 | 0 | 0 |

---

## 元件清單

### Activities

| 元件名稱 | Exported | Protected |
|-----------|----------|-----------|
| `com.toyapk.scenario_b.case2.MainActivity` | `true` | `false` |

### Services

| 元件名稱 | Exported | Protected | Permission |
|-----------|----------|-----------|------------|
| `com.toyapk.scenario_b.case2.MyService` | `true` | `true` | `com.toyapk.scenario_b.case2.permission.BIND_SERVICE` |

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
| `com.toyapk.scenario_b.case2.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` |

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
| `com.toyapk.scenario_b.case2.MainActivity` | action: `android.intent.action.MAIN`, category: `android.intent.category.LAUNCHER` |

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

### 3. IPC_PROVIDER_REDELEGATION

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
| MyService 存在且 exported=true | exported=true | 存在且 exported=true | PASS |
| MyService 有 permission 保護 | protected=true | `android:permission=BIND_SERVICE` | PASS |
| 無 IPC_SERVICE_HIJACK finding | 不觸發 | 未觸發（service 已受權限保護） | PASS |
| 風險分數低於 Case 1 | < 83 | 75（High），Case 1 為 83/Critical | PASS |

---

## 備註

Case 2 為 Case 1 的「修正版」：`MyService` 同樣設定 `android:exported="true"`，但加上了 `android:permission="com.toyapk.scenario_b.case2.permission.BIND_SERVICE"`，使 pipeline 將其標記為 `protected=true`，因此 **IPC_SERVICE_HIJACK 未觸發**，風險分數回落至 75（High），與 Case 0 相同。

三個 Case 的對比如下：

| Case | MyService exported | MyService protected | IPC_SERVICE_HIJACK | 風險分數 |
|------|--------------------|--------------------|--------------------|---------|
| Case 0 | `false` | — | 未觸發 | 75 / High |
| Case 1 | `true` | `false` | **觸發** | 83 / Critical |
| Case 2 | `true` | `true` | 未觸發 | 75 / High |

Findings #2 和 #3 仍由 AndroidX 標準 library 元件觸發（同 Case 0），屬已知誤報來源。
