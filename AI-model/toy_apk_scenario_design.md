# Toy APK 場景設計藍圖

**專案**：NSTC 大專生研究計畫 — Android APK 越權行為靜態分析  
**版本**：v1.3  
**更新日期**：2026-07-12  
**總 APK 數**：30 個（5 種場景 × 6 個 APK）

> **v1.1 修訂紀錄（2026-07-09）**：修正場景 E 的 E-2/E-5 設計矛盾。原本 E-2 只設定
> `readPermission`，manifest 屬性與 E-3 完全相同卻標了不同 label，且與本節的
> 觸發規則定義自相矛盾——manifest-only 分析無法區分「write 端點沒實作」與
> 「write 端點確實開放」。E-2 改為 readPermission+writePermission 皆保護，成為
> 名副其實的「完整保護」對照案例。同時 `androguard_analyzer.py`/`privilege_rules.py`
> 已完成 read/write 分側判斷的修補，並新增 `IPC_PROVIDER_URI_GRANT_BYPASS` finding
> （有保護但 `grantUriPermissions=true` 可能被繞過）。E-5 原本完全無保護，會跟
> E-1 產生一模一樣的 finding，測不到「URI 授權誤用」的設計初衷，故改為兩側皆
> 保護 + `grantUriPermissions=true`，才能真正測到「保護被繞過」的情境。

> **v1.2 修訂紀錄（2026-07-10）**：修正場景 C 的 C-3 設計缺陷。原始設計只對
> `ContactsActivity` 加了 permission 保護，`MainActivity` 仍是 `exported="true"`
> 且無保護——但 `IPC_CONFUSED_DEPUTY` 的觸發條件是「持有危險權限 AND 存在任一
> exported 且無保護的 component」，並不會判斷哪個 component 語意上對應該權限。
> 實際建置驗證後，C-3 因為 `MainActivity` 未受保護而被規則正確判定為觸發，
> 與預期的 label=0 不符（規則本身沒有 bug，是案例設計沒把所有 exported
> component 都保護到）。已修正為 `MainActivity` 與 `ContactsActivity` 皆套用
> 同一個自訂 permission，重跑驗證後 PASS（`IPC_CONFUSED_DEPUTY` 與
> `EXPORTED_UNPROTECTED_ACTIVITY` 皆不再觸發）。

> **v1.3 修訂紀錄（2026-07-12）**：Scenario D 驗證時發現 `androguard_analyzer.py`
> 的 `_extract_components()` 存在 exported 屬性解析 bug，與 v1.1 修正的 Provider
> exported-override 屬同一類問題，但這次出現在 Activity/Service/Receiver 三個
> 解析區塊：只要元件有 `<intent-filter>`，就無條件把 `exported` 覆寫成 `true`，
> 完全無視 manifest 是否已明確宣告 `exported="false"`。D-0 的 `CustomReceiver`
> 明確宣告 `exported="false"` 且帶 intent-filter，是第一個曝出此 bug 的案例——
> 之前 A/B/C/E 的既有設計都沒有出現「明確 `exported=false` + 有 intent-filter」
> 這個屬性組合，才沒有更早發現。已修復：`android:exported` 屬性明確存在時以
> 明確值為準，屬性缺席時才套用「有 intent-filter 則預設 `exported=true`」的
> Android 原生規則。修復範圍僅限 Activity/Service/Receiver 三段解析邏輯（line
> 232 起），Provider 解析區塊、`_extract_intent_filters()`、`privilege_rules.py`
> 皆未修改；新增 6 個 regression test 於 `test_androguard_analyzer.py`（line 53
> 起）。修復前後重跑 Scenario A/B/C/E 全數案例的風險分數與 finding 數量完全
> 一致，確認零 regression；D-0 風險分數由 58 降為 34（`EXPORTED_UNPROTECTED_
> RECEIVER` 誤報消除，只留下正確的 `EXPORTED_UNPROTECTED_ACTIVITY`），
> `IPC_BROADCAST_THEFT` 六案例維持全數 PASS。此 bug 對真實世界 APK 蒐集階段的
> `exported` 特徵正確性影響較大（Android 12+ 強制要求明確宣告 exported，「顯式
> false + 有 intent-filter」在真實 App 中會很常見），已於 AndroZoo 蒐集開始前
> 修復完成。詳見 `STATUS_2026-07-12.md`。

---

## 共用規格

| 項目 | 規格 |
|------|------|
| Language | Kotlin |
| Min SDK | API 23（Android 6.0 Marshmallow） |
| Target SDK | API 37 |
| compileSdk | 37 |
| versionCode | 1 |
| versionName | `"1.0"` |
| 專案名稱格式 | `ToyApk{場景}{編號}`，例如 `ToyApkA0`、`ToyApkB3` |
| Package name 格式 | `com.toyapk.scenario_{小寫場景}.case{編號}` |
| 原始碼位置 | `toy_apk_sources/scenario_{場景小寫}/case{編號}/` |
| APK 輸出位置 | `dataset/toy_apks/scenario_{場景小寫}/scenario_{場景小寫}_case{編號}.apk` |
| 標籤表 | `dataset/labels/ground_truth.csv` |
| label_source | `manual`（手工標記 ground truth） |

### 空殼 Kotlin Class 實作規則

| Component 類型 | 繼承 | 必要實作 |
|--------------|------|---------|
| `Service` | `android.app.Service` | `onBind()` 回傳 `null` |
| `BroadcastReceiver` | `android.content.BroadcastReceiver` | `onReceive()` 空實作 |
| `ContentProvider` | `android.content.ContentProvider` | `onCreate()`、`query()`、`insert()`、`update()`、`delete()`、`getType()` 均回傳 `null` 或 `0` |

---

## 五種場景總覽

| 場景 | 偵測目標 | label=1 觸發條件 |
|------|---------|----------------|
| A | `OVER_PRIVILEGE` | 宣告超出功能需求的危險權限 |
| B | `IPC_SERVICE_HIJACK` | Service `exported=true` 且無 `android:permission` |
| C | `IPC_CONFUSED_DEPUTY` | App 持有危險權限 + exported component 無 permission 保護 |
| D | `IPC_BROADCAST_THEFT` | Receiver 監聽敏感系統 action 且 `exported=true` 無保護 |
| E | `IPC_PROVIDER_REDELEGATION` / `IPC_PROVIDER_URI_GRANT_BYPASS` | Provider `exported=true` 且讀/寫任一側缺少保護；或兩側皆保護但 `grantUriPermissions=true` |

---

## 場景 A：OVER_PRIVILEGE（過度宣告危險權限）

**漏洞本質**：App 在 `AndroidManifest.xml` 中宣告了超出其實際功能需求的 Dangerous Permission，雖然 App 功能正常，但不必要的權限宣告擴大了攻擊面與隱私洩露風險。

**審查意見對應**：體現「功能正當但權限配置不當」的越權現象，越權判定標準為「宣告權限與 App 功能語意不符」。

**觸發規則**：`COMBO_SMS_EXFIL`、`COMBO_CONTACT_EXFIL`、`COMBO_CALL_INTERCEPT`（危險權限組合超過閾值）

### APK 設計表

| APK | Package | Manifest 關鍵設定 | label | note |
|-----|---------|-----------------|-------|------|
| **A-0** | `com.toyapk.scenario_a.case0` | 只宣告 `INTERNET`，無任何危險權限 | **0** | 對照組 |
| **A-1** | `com.toyapk.scenario_a.case1` | `READ_SMS` + `INTERNET`（計算機 App，不需要簡訊） | **1** | 典型越權：功能與權限語意不符 |
| **A-2** | `com.toyapk.scenario_a.case2` | `READ_CONTACTS` + `CAMERA` + `INTERNET`（靜態工具 App） | **1** | 多重越權：宣告三個不必要的危險權限 |
| **A-3** | `com.toyapk.scenario_a.case3` | `ACCESS_FINE_LOCATION`（無任何地圖或定位功能） | **1** | 位置權限越權：無對應功能 |
| **A-4** | `com.toyapk.scenario_a.case4` | `RECORD_AUDIO` + `READ_CALL_LOG`（筆記 App） | **1** | 敏感組合：錄音 + 通話記錄 |
| **A-5** | `com.toyapk.scenario_a.case5` | `READ_CONTACTS`，且 Activity 有 `android:permission` 保護 | **0** | 邊界案例：有保護，不觸發規則 |

### A-0 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_a.case0">

    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk A0"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### A-1 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_a.case1">

    <!-- 漏洞：計算機 App 宣告了 READ_SMS，功能語意不符 -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk A1"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### A-2 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_a.case2">

    <!-- 漏洞：靜態工具 App 宣告多個不必要的危險權限 -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.CAMERA"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk A2"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### A-3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_a.case3">

    <!-- 漏洞：無地圖或定位功能的 App 卻宣告精確位置權限 -->
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk A3"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### A-4 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_a.case4">

    <!-- 漏洞：筆記 App 宣告錄音 + 通話記錄（敏感危險組合） -->
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk A4"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### A-5 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_a.case5">

    <uses-permission android:name="android.permission.READ_CONTACTS"/>

    <permission
        android:name="com.toyapk.scenario_a.case5.ACCESS"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk A5"
        android:theme="@style/Theme.AppCompat">
        <!-- 邊界案例：有 permission 保護，不觸發 OVER_PRIVILEGE 規則 -->
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:permission="com.toyapk.scenario_a.case5.ACCESS">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

---

## 場景 B：IPC_SERVICE_HIJACK（未保護的 exported Service）

**漏洞本質**：Service 設定 `exported="true"` 但沒有 `android:permission`，任何外部 App 都能直接呼叫此 Service，造成服務劫持風險。

**觸發規則**：`IPC_SERVICE_HIJACK`（exported=true AND permission=null）

### APK 設計表

| APK | Package | Manifest 關鍵設定 | label | note |
|-----|---------|-----------------|-------|------|
| **B-0** | `com.toyapk.scenario_b.case0` | Service `exported="false"` | **0** | 對照組 |
| **B-1** | `com.toyapk.scenario_b.case1` | Service `exported="true"`，無 permission | **1** | 基本漏洞 |
| **B-2** | `com.toyapk.scenario_b.case2` | Service `exported="true"`，有 `android:permission` | **0** | 正確保護 |
| **B-3** | `com.toyapk.scenario_b.case3` | 兩個 Service：一個有保護、一個無保護（皆 exported） | **1** | 混合案例 |
| **B-4** | `com.toyapk.scenario_b.case4` | Service `exported="true"` + `<intent-filter>`，無 permission | **1** | 隱含公開 |
| **B-5** | `com.toyapk.scenario_b.case5` | 兩個 Service 皆有自訂 intent-filter，均 exported 且無 permission | **1** | 多服務裸露 |

### B-0 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_b.case0">

    <application
        android:allowBackup="true"
        android:label="ToyApk B0"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：exported=false，外部 App 無法呼叫 -->
        <service
            android:name=".SafeService"
            android:exported="false"/>
    </application>
</manifest>
```

### B-1 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_b.case1">

    <application
        android:allowBackup="true"
        android:label="ToyApk B1"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：exported=true 但沒有任何 permission 保護 -->
        <service
            android:name=".ExposedService"
            android:exported="true"/>
    </application>
</manifest>
```

### B-2 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_b.case2">

    <permission
        android:name="com.toyapk.scenario_b.case2.BIND_SERVICE"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk B2"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：exported=true 但有 permission 保護 -->
        <service
            android:name=".ProtectedService"
            android:exported="true"
            android:permission="com.toyapk.scenario_b.case2.BIND_SERVICE"/>
    </application>
</manifest>
```

### B-3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_b.case3">

    <permission
        android:name="com.toyapk.scenario_b.case3.BIND_SAFE"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk B3"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全的那個 -->
        <service
            android:name=".SafeService"
            android:exported="true"
            android:permission="com.toyapk.scenario_b.case3.BIND_SAFE"/>
        <!-- 漏洞：沒有保護 -->
        <service
            android:name=".LeakyService"
            android:exported="true"/>
    </application>
</manifest>
```

### B-4 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_b.case4">

    <application
        android:allowBackup="true"
        android:label="ToyApk B4"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：有 intent-filter 代表隱含公開，且無 permission 保護 -->
        <service
            android:name=".ImplicitService"
            android:exported="true">
            <intent-filter>
                <action android:name="com.toyapk.scenario_b.case4.DO_WORK"/>
            </intent-filter>
        </service>
    </application>
</manifest>
```

### B-5 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_b.case5">

    <application
        android:allowBackup="true"
        android:label="ToyApk B5"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：兩個 Service 皆裸露，開發者誤以為自訂 action 已足夠安全 -->
        <service
            android:name=".WorkerServiceA"
            android:exported="true">
            <intent-filter>
                <action android:name="com.toyapk.scenario_b.case5.ACTION_SYNC"/>
            </intent-filter>
        </service>
        <service
            android:name=".WorkerServiceB"
            android:exported="true">
            <intent-filter>
                <action android:name="com.toyapk.scenario_b.case5.ACTION_UPLOAD"/>
            </intent-filter>
        </service>
    </application>
</manifest>
```

---

## 場景 C：IPC_CONFUSED_DEPUTY（Confused Deputy / Intent Spoofing）

**漏洞本質**：App 持有危險權限（如 `READ_SMS`），但同時有 exported component 沒有 permission 保護。外部惡意 App 可透過 Intent 呼叫此 exported component，間接借用本 App 的危險權限，在不持有該權限的情況下存取敏感資料。

**審查意見對應**：體現「功能執行正常但結構允許越權委派」的場景。

**觸發規則**：`IPC_CONFUSED_DEPUTY`（持有危險權限 AND exported component 無保護）

### APK 設計表

| APK | Package | Manifest 關鍵設定 | label | note |
|-----|---------|-----------------|-------|------|
| **C-0** | `com.toyapk.scenario_c.case0` | 持有 `READ_SMS`，但所有 Activity `exported="false"` | **0** | 對照組 |
| **C-1** | `com.toyapk.scenario_c.case1` | 持有 `READ_SMS` + exported Activity 無 permission | **1** | 典型 Confused Deputy |
| **C-2** | `com.toyapk.scenario_c.case2` | 持有 `CAMERA` + exported Activity 無 permission | **1** | 相機權限委派 |
| **C-3** | `com.toyapk.scenario_c.case3` | 持有 `READ_CONTACTS` + **兩個** exported Activity（MainActivity、ContactsActivity）皆**有** permission 保護 | **0** | 正確保護，不觸發 |
| **C-4** | `com.toyapk.scenario_c.case4` | 持有 `READ_SMS` + `READ_CALL_LOG` + 多個 exported Activity 無保護 | **1** | 高嚴重度：多重危險權限 |
| **C-5** | `com.toyapk.scenario_c.case5` | 只持有 `INTERNET`（非危險權限）+ exported Activity 無保護 | **0** | 邊界案例：INTERNET 不觸發規則 |

### C-0 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_c.case0">

    <uses-permission android:name="android.permission.READ_SMS"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk C0"
        android:theme="@style/Theme.AppCompat">
        <!-- 安全：有危險權限，但所有 Activity 皆 exported=false -->
        <activity
            android:name=".MainActivity"
            android:exported="false"/>
        <activity
            android:name=".SmsActivity"
            android:exported="false"/>
    </application>
</manifest>
```

### C-1 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_c.case1">

    <uses-permission android:name="android.permission.READ_SMS"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk C1"
        android:theme="@style/Theme.AppCompat">
        <!-- 漏洞：持有 READ_SMS 且有 exported Activity 無 permission 保護 -->
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity
            android:name=".SmsViewerActivity"
            android:exported="true"/>
    </application>
</manifest>
```

### C-2 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_c.case2">

    <uses-permission android:name="android.permission.CAMERA"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk C2"
        android:theme="@style/Theme.AppCompat">
        <!-- 漏洞：持有 CAMERA 且有 exported Activity 無保護 -->
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity
            android:name=".CameraActivity"
            android:exported="true"/>
    </application>
</manifest>
```

### C-3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_c.case3">

    <uses-permission android:name="android.permission.READ_CONTACTS"/>

    <permission
        android:name="com.toyapk.scenario_c.case3.ACCESS_CONTACTS"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk C3"
        android:theme="@style/Theme.AppCompat">
        <!-- 安全：MainActivity 也有 permission 保護，不觸發規則 -->
        <!-- 原始設計只保護了 ContactsActivity，MainActivity 仍 exported 且無保護，
             導致 IPC_CONFUSED_DEPUTY 規則（任一 exported component 無保護即觸發）
             實際跑出來是誤判為觸發（規則本身沒錯，是案例設計沒把所有 exported
             component 都保護到）。已修正為兩個 Activity 皆套用同一個 permission。 -->
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:permission="com.toyapk.scenario_c.case3.ACCESS_CONTACTS">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：exported Activity 有 permission 保護，不觸發規則 -->
        <activity
            android:name=".ContactsActivity"
            android:exported="true"
            android:permission="com.toyapk.scenario_c.case3.ACCESS_CONTACTS"/>
    </application>
</manifest>
```

### C-4 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_c.case4">

    <!-- 高嚴重度：多重危險權限 -->
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk C4"
        android:theme="@style/Theme.AppCompat">
        <!-- 漏洞：多個 exported Activity 均無 permission 保護 -->
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity
            android:name=".SmsViewerActivity"
            android:exported="true"/>
        <activity
            android:name=".CallLogActivity"
            android:exported="true"/>
    </application>
</manifest>
```

### C-5 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_c.case5">

    <!-- INTERNET 不是 Dangerous Permission，不觸發 CONFUSED_DEPUTY 規則 -->
    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk C5"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity
            android:name=".WebActivity"
            android:exported="true"/>
    </application>
</manifest>
```

---

## 場景 D：IPC_BROADCAST_THEFT（未保護的敏感廣播接收器）

**漏洞本質**：`BroadcastReceiver` 設定 `exported="true"` 且 `intent-filter` 包含敏感系統 action（如 `SMS_RECEIVED`、`BOOT_COMPLETED`），惡意 App 可攔截這些廣播或注入偽造廣播，竊取敏感事件資訊。

**觸發規則**：`IPC_BROADCAST_THEFT`（exported=true AND intent-filter 含敏感 action AND 無 permission）

> ⚠️ **注意**：D-0 的 `CustomReceiver` 明確宣告 `exported="false"` 且帶
> intent-filter，這個屬性組合曾在 2026-07-12 曝出 `androguard_analyzer.py` 的
> exported 解析 bug（詳見文件開頭 v1.3 修訂紀錄），目前已修復並驗證。

### APK 設計表

| APK | Package | Manifest 關鍵設定 | label | note |
|-----|---------|-----------------|-------|------|
| **D-0** | `com.toyapk.scenario_d.case0` | Receiver 監聽自訂 action，`exported="false"` | **0** | 對照組 |
| **D-1** | `com.toyapk.scenario_d.case1` | Receiver 監聽 `SMS_RECEIVED`，`exported="true"` 無 permission | **1** | 短訊廣播竊取 |
| **D-2** | `com.toyapk.scenario_d.case2` | Receiver 監聽 `BOOT_COMPLETED`，`exported="true"` 無 permission | **1** | 開機廣播竊取 |
| **D-3** | `com.toyapk.scenario_d.case3` | Receiver 監聽 `SMS_RECEIVED`，有 `android:permission` 保護 | **0** | 正確保護 |
| **D-4** | `com.toyapk.scenario_d.case4` | Receiver 監聽自訂非敏感 action，`exported="true"` 無保護 | **0** | 非敏感 action，不觸發規則 |
| **D-5** | `com.toyapk.scenario_d.case5` | 兩個 Receiver：一個敏感有保護、一個敏感無保護 | **1** | 混合案例 |

### D-0 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_d.case0">

    <application
        android:allowBackup="true"
        android:label="ToyApk D0"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：監聽自訂 action 且 exported=false -->
        <receiver
            android:name=".CustomReceiver"
            android:exported="false">
            <intent-filter>
                <action android:name="com.toyapk.scenario_d.case0.CUSTOM_EVENT"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### D-1 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_d.case1">

    <uses-permission android:name="android.permission.RECEIVE_SMS"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk D1"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：監聽敏感系統廣播且無 permission 保護 -->
        <receiver
            android:name=".SmsReceiver"
            android:exported="true">
            <intent-filter android:priority="999">
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### D-2 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_d.case2">

    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk D2"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：監聽開機廣播且無 permission 保護 -->
        <receiver
            android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### D-3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_d.case3">

    <uses-permission android:name="android.permission.RECEIVE_SMS"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk D3"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：監聽敏感廣播但有 permission 保護 -->
        <receiver
            android:name=".SmsReceiver"
            android:exported="true"
            android:permission="android.permission.BROADCAST_SMS">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### D-4 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_d.case4">

    <application
        android:allowBackup="true"
        android:label="ToyApk D4"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 邊界案例：exported=true 但監聽自訂非敏感 action，不觸發規則 -->
        <receiver
            android:name=".NotificationReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.toyapk.scenario_d.case4.NOTIFY"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### D-5 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_d.case5">

    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk D5"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：敏感廣播有 permission 保護 -->
        <receiver
            android:name=".ProtectedSmsReceiver"
            android:exported="true"
            android:permission="android.permission.BROADCAST_SMS">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
        <!-- 漏洞：敏感廣播無保護 -->
        <receiver
            android:name=".ExposedBootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

---

## 場景 E：IPC_PROVIDER_REDELEGATION（未保護的 ContentProvider）

**漏洞本質**：`ContentProvider` 設定 `exported="true"` 但缺少 `android:readPermission` 或 `android:writePermission`，任何外部 App 皆可直接讀寫其資料，造成權限重新委派（Re-delegation）風險。

**審查意見對應**：越權判定標準（`readPermission`/`writePermission` 是否存在）需在實驗中驗證與調整。

**觸發規則**：
- `IPC_PROVIDER_REDELEGATION`（exported=true AND（readPermission=null OR writePermission=null））
- `IPC_PROVIDER_URI_GRANT_BYPASS`（exported=true AND read/write 兩側皆有保護 AND grantUriPermissions=true）——與上者互斥，manifest-only 分析僅能確認「具備繞過能力」，無法確認 app 是否實際不安全地轉發 URI，故 severity/confidence 明顯低於前者。

> ✅ **已修補**（2026-07-09）：`androguard_analyzer.py`/`privilege_rules.py`/`parse_manifest.py` 已完成 read/write 分側判斷與 `IPC_PROVIDER_URI_GRANT_BYPASS` 規則，測試套件 137 passed。詳見 `STATUS_2026-07-07.md`。

### APK 設計表

| APK | Package | Manifest 關鍵設定 | label | note |
|-----|---------|-----------------|-------|------|
| **E-0** | `com.toyapk.scenario_e.case0` | Provider `exported="false"` | **0** | 對照組 |
| **E-1** | `com.toyapk.scenario_e.case1` | Provider `exported="true"`，無 readPermission / writePermission | **1** | 完全裸露 |
| **E-2** | `com.toyapk.scenario_e.case2` | Provider `exported="true"`，同時設定 `android:readPermission` 與 `android:writePermission`（兩側皆保護） | **0** | 完整保護 |
| **E-3** | `com.toyapk.scenario_e.case3` | Provider `exported="true"`，有 readPermission 但**無** writePermission | **1** | 部分保護（寫入漏洞） |
| **E-4** | `com.toyapk.scenario_e.case4` | 兩個 Provider：一個完整保護、一個完全裸露 | **1** | 混合案例 |
| **E-5** | `com.toyapk.scenario_e.case5` | Provider `exported="true"`，readPermission+writePermission 皆保護，但 `grantUriPermissions="true"` | **1** | URI 授權誤用（繞過既有保護） |

### E-0 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_e.case0">

    <application
        android:allowBackup="true"
        android:label="ToyApk E0"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：exported=false -->
        <provider
            android:name=".SafeProvider"
            android:authorities="com.toyapk.scenario_e.case0.provider"
            android:exported="false"/>
    </application>
</manifest>
```

### E-1 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_e.case1">

    <application
        android:allowBackup="true"
        android:label="ToyApk E1"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：exported=true 且無任何讀寫保護 -->
        <provider
            android:name=".ExposedProvider"
            android:authorities="com.toyapk.scenario_e.case1.provider"
            android:exported="true"/>
    </application>
</manifest>
```

### E-2 AndroidManifest.xml

> **v1.1 修正**：原版本只設 `readPermission`，與 E-3 的 manifest 屬性完全相同卻標了
> 不同 label，manifest-only 分析無法區分兩者。改為兩側皆保護，作為名副其實的
> 「完整保護」對照案例。

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_e.case2">

    <permission
        android:name="com.toyapk.scenario_e.case2.READ"
        android:protectionLevel="signature"/>
    <permission
        android:name="com.toyapk.scenario_e.case2.WRITE"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk E2"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：readPermission + writePermission 皆設定，兩側完整保護 -->
        <provider
            android:name=".ProtectedProvider"
            android:authorities="com.toyapk.scenario_e.case2.provider"
            android:exported="true"
            android:readPermission="com.toyapk.scenario_e.case2.READ"
            android:writePermission="com.toyapk.scenario_e.case2.WRITE"/>
    </application>
</manifest>
```

### E-3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_e.case3">

    <permission
        android:name="com.toyapk.scenario_e.case3.READ"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk E3"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：有 readPermission 但無 writePermission（寫入仍可被濫用） -->
        <provider
            android:name=".PartialProvider"
            android:authorities="com.toyapk.scenario_e.case3.provider"
            android:exported="true"
            android:readPermission="com.toyapk.scenario_e.case3.READ"/>
    </application>
</manifest>
```

### E-4 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_e.case4">

    <permission
        android:name="com.toyapk.scenario_e.case4.READ"
        android:protectionLevel="signature"/>
    <permission
        android:name="com.toyapk.scenario_e.case4.WRITE"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk E4"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 安全：完整保護 -->
        <provider
            android:name=".FullyProtectedProvider"
            android:authorities="com.toyapk.scenario_e.case4.provider.safe"
            android:exported="true"
            android:readPermission="com.toyapk.scenario_e.case4.READ"
            android:writePermission="com.toyapk.scenario_e.case4.WRITE"/>
        <!-- 漏洞：完全裸露 -->
        <provider
            android:name=".ExposedProvider"
            android:authorities="com.toyapk.scenario_e.case4.provider.leak"
            android:exported="true"/>
    </application>
</manifest>
```

### E-5 AndroidManifest.xml

> **v1.1 修正**：原版本完全無保護，會跟 E-1 在規則引擎下產生一模一樣的
> finding，測不到「URI 授權誤用」的設計初衷。改為兩側皆保護 + `grantUriPermissions=true`，
> 才能真正測到「保護被繞過」這個情境，觸發獨立的 `IPC_PROVIDER_URI_GRANT_BYPASS`。

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.toyapk.scenario_e.case5">

    <permission
        android:name="com.toyapk.scenario_e.case5.READ"
        android:protectionLevel="signature"/>
    <permission
        android:name="com.toyapk.scenario_e.case5.WRITE"
        android:protectionLevel="signature"/>

    <application
        android:allowBackup="true"
        android:label="ToyApk E5"
        android:theme="@style/Theme.AppCompat">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <!-- 漏洞：readPermission/writePermission 皆有保護，但 grantUriPermissions=true
             讓 app 仍可將特定 URI 存取權轉授給任意呼叫者，繞過上述保護 -->
        <provider
            android:name=".UriGrantProvider"
            android:authorities="com.toyapk.scenario_e.case5.provider"
            android:exported="true"
            android:readPermission="com.toyapk.scenario_e.case5.READ"
            android:writePermission="com.toyapk.scenario_e.case5.WRITE"
            android:grantUriPermissions="true"/>
    </application>
</manifest>
```

---

## ground_truth.csv 完整內容

```csv
apk_filename,package_name,scenario,case_id,label,label_source,note
scenario_a_case0.apk,com.toyapk.scenario_a.case0,A,0,0,manual,對照組：只宣告INTERNET無危險權限
scenario_a_case1.apk,com.toyapk.scenario_a.case1,A,1,1,manual,過度宣告READ_SMS+INTERNET（計算機App功能語意不符）
scenario_a_case2.apk,com.toyapk.scenario_a.case2,A,2,1,manual,多重越權：READ_CONTACTS+CAMERA+INTERNET（靜態工具App）
scenario_a_case3.apk,com.toyapk.scenario_a.case3,A,3,1,manual,位置權限越權：ACCESS_FINE_LOCATION無對應功能
scenario_a_case4.apk,com.toyapk.scenario_a.case4,A,4,1,manual,敏感組合：RECORD_AUDIO+READ_CALL_LOG（筆記App）
scenario_a_case5.apk,com.toyapk.scenario_a.case5,A,5,0,manual,邊界案例：READ_CONTACTS但Activity有permission保護
scenario_b_case0.apk,com.toyapk.scenario_b.case0,B,0,0,manual,對照組：Service exported=false
scenario_b_case1.apk,com.toyapk.scenario_b.case1,B,1,1,manual,基本漏洞：Service exported=true無permission
scenario_b_case2.apk,com.toyapk.scenario_b.case2,B,2,0,manual,正確保護：Service exported=true有BIND_SERVICE permission
scenario_b_case3.apk,com.toyapk.scenario_b.case3,B,3,1,manual,混合案例：兩個Service一有保護一沒有
scenario_b_case4.apk,com.toyapk.scenario_b.case4,B,4,1,manual,隱含公開：有intent-filter但無permission
scenario_b_case5.apk,com.toyapk.scenario_b.case5,B,5,1,manual,多服務裸露：兩個Service皆exported且無permission
scenario_c_case0.apk,com.toyapk.scenario_c.case0,C,0,0,manual,對照組：持有READ_SMS但所有Activity exported=false
scenario_c_case1.apk,com.toyapk.scenario_c.case1,C,1,1,manual,典型Confused Deputy：READ_SMS+exported Activity無保護
scenario_c_case2.apk,com.toyapk.scenario_c.case2,C,2,1,manual,相機權限委派：CAMERA+exported Activity無保護
scenario_c_case3.apk,com.toyapk.scenario_c.case3,C,3,0,manual,正確保護：READ_CONTACTS，MainActivity與ContactsActivity皆有permission保護
scenario_c_case4.apk,com.toyapk.scenario_c.case4,C,4,1,manual,高嚴重度：READ_SMS+READ_CALL_LOG+多個exported Activity無保護
scenario_c_case5.apk,com.toyapk.scenario_c.case5,C,5,0,manual,邊界案例：只有INTERNET（非危險權限）不觸發規則
scenario_d_case0.apk,com.toyapk.scenario_d.case0,D,0,0,manual,對照組：自訂action且exported=false
scenario_d_case1.apk,com.toyapk.scenario_d.case1,D,1,1,manual,短訊廣播竊取：SMS_RECEIVED無permission保護
scenario_d_case2.apk,com.toyapk.scenario_d.case2,D,2,1,manual,開機廣播竊取：BOOT_COMPLETED無permission保護
scenario_d_case3.apk,com.toyapk.scenario_d.case3,D,3,0,manual,正確保護：SMS_RECEIVED有BROADCAST_SMS permission
scenario_d_case4.apk,com.toyapk.scenario_d.case4,D,4,0,manual,邊界案例：自訂非敏感action不觸發規則
scenario_d_case5.apk,com.toyapk.scenario_d.case5,D,5,1,manual,混合案例：一個敏感Receiver有保護一個無保護
scenario_e_case0.apk,com.toyapk.scenario_e.case0,E,0,0,manual,對照組：Provider exported=false
scenario_e_case1.apk,com.toyapk.scenario_e.case1,E,1,1,manual,完全裸露：exported=true無readPermission/writePermission
scenario_e_case2.apk,com.toyapk.scenario_e.case2,E,2,0,manual,完整保護：readPermission+writePermission皆設定（原設計僅設readPermission與E-3衝突，已修正）
scenario_e_case3.apk,com.toyapk.scenario_e.case3,E,3,1,manual,部分保護：有readPermission但無writePermission
scenario_e_case4.apk,com.toyapk.scenario_e.case4,E,4,1,manual,混合案例：一個完整保護一個完全裸露
scenario_e_case5.apk,com.toyapk.scenario_e.case5,E,5,1,manual,URI授權誤用：readPermission+writePermission皆保護，但grantUriPermissions=true可繞過（IPC_PROVIDER_URI_GRANT_BYPASS）
```

---

## 執行順序建議

```
第一批：場景 B（已在對話中確認設計）→ build → pipeline 驗證 → OK 後繼續
第二批：場景 A
第三批：場景 C
第四批：場景 D
第五批：場景 E
```

> ✅ **場景 E 阻擋項已解除**（2026-07-09）：`androguard_analyzer.py`/`privilege_rules.py`/`parse_manifest.py` 的 read/write 分側判斷與 `IPC_PROVIDER_URI_GRANT_BYPASS` 規則已修補完成並通過測試（137 passed），可直接建置六個 APK。

---

## 驗證指令

每個場景 build 完成後，執行以下驗證：

```bash
# 從 AI-model/ 目錄下執行
cd AI-model/

# 單一 APK 驗證
python -m app.main --in <input.json> --out <output.json> --artifacts <artifacts_dir/>

# 批次場景驗證（若有 toy_apk_validate.py）
python toy_apk_validate.py --scenario B --apk-dir ../dataset/toy_apks/scenario_b/
```

**期待結果**：

| 場景 | 應觸發 finding | 不應觸發的 APK |
|------|--------------|--------------|
| B | `IPC_SERVICE_HIJACK` | B-0、B-2 |
| A | `COMBO_SMS_EXFIL` / `COMBO_CONTACT_EXFIL` 等 | A-0、A-5 |
| C | `IPC_CONFUSED_DEPUTY` | C-0、C-3、C-5 |
| D | `IPC_BROADCAST_THEFT` | D-0、D-3、D-4 |
| E | `IPC_PROVIDER_REDELEGATION`（E-1/E-3/E-4）、`IPC_PROVIDER_URI_GRANT_BYPASS`（E-5） | E-0、E-2 |