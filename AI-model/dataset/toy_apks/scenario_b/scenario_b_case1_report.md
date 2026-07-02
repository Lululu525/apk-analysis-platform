# Scenario B Case 1 — APK 靜態分析報告

## 基本資訊

| 欄位 | 值 |
|------|-----|
| **Job ID** | `scenario_b_case1` |
| **Package** | `com.toyapk.scenario_b.case1` |
| **SHA-256** | `02cb7eef97098e5ab6023c7008b18001976cc0602a0bcea751e0f4ab79a6a5c7` |
| **APK 大小** | 7,060,660 bytes (6.73 MB) |
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
| `com.toyapk.scenario_b.case1.MainActivity` | `true` | `false` |

### Services

| 元件名稱 | Exported | Protected |
|-----------|----------|-----------|
| `com.toyapk.scenario_b.case1.MyService` | `true` | `false` |

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
| `com.toyapk.scenario_b.case1.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` |

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
| `com.toyapk.scenario_b.case1.MainActivity` | action: `android.intent.action.MAIN`, category: `android.intent.category.LAUNCHER` |

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
| `com.toyapk.scenario_b.case1.MyService` | Service Hijacking |

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
| MyService 存在且 exported=true | exported=true | exported=true，無 permission 保護 | PASS |
| 觸發 IPC_SERVICE_HIJACK finding | 觸發 | 已觸發（severity=high, score=6.660） | PASS |
| Label = 1（惡意樣本） | 1 | 風險分數 83/Critical，含 Service Hijacking finding | PASS |

---

## 備註

與 Case 0 相比，Case 1 的核心差異為 `MyService` 設定了 `android:exported="true"`，導致 pipeline 額外觸發 **IPC_SERVICE_HIJACK** finding（CWE-926/927），風險分數從 75（High）上升至 83（Critical）。此行為符合 Scenario B 的設計目標：驗證 pipeline 能正確偵測 exported service 的 hijacking 風險。Findings #2 和 #4 仍為 AndroidX library 元件誤報（同 Case 0）。
