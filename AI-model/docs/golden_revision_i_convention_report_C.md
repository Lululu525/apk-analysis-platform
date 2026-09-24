# Golden 修訂：I 慣例重審 批次 C

- Workflow：`golden-review-session-protocol-v1.1`（`append-revision`，supersession）
- 本批修訂 units：4
- Review log SHA-256：`db617c9c0af874dc4c12410a5d5d5fa1306a087090f58bec50bbb763da7c951e`
- Review log events／unique units：425／385
- 人工輸入欄位：`gold_authz_label`、`reviewer_confidence`；舊 event 原樣保留

## 逐筆前後對照

### 第 1 筆 — `review-unit-v1:2f2a526e2d4cdd8ca104c41d16f33a8a2ac7c9eecc93d7bb1cd6c3c2efcb4cd6`

- APK／component：`9807923677bdad15ad73975167887bbbff8a25bca99736b25f88ff02600a382d`／`home.solo.launcher.free.SplashActivity`
- Caller／sink：`b`／`android/content/ContentResolver:query`
- 修訂前 `bf3154eb-dfb5-4b03-8569-35129e0e9919`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `619461ac-4289-4646-a633-dd99822f57dc`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_7fd87cc4-bdb2-56a8-9390-e73a640b9def`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention
- 說明：Manifest evidence re-checked: home.solo.launcher.free.SplashActivity is declared exactly once among 103 components (76 activity, 14 service, 7 receiver, 6 provider); no manifest_name is declared twice in this APK and there is no activity-alias at all. explicit_exported=null, permission=null, application_permission empty, one intent-filter with action MAIN and category LAUNCHER, min_sdk 16 target_sdk 23, so the documented default is exported=true and the Android 12 explicit-exported requirement does not apply. R stays confirmed (confirmed_present) exactly as in the superseded event; this revision does not re-decide R. The full 209-line SplashActivity.java was read again and contains no getIntent, no getExtras and no onNewIntent anywhere. I confirmed under the 2026-09-19 trigger convention: a third-party app starting this exported activity with an explicit Intent is by itself the control flow that runs onCreate (line 46) -> b() (called at line 55) -> getContentResolver().query(ib.f2947a, null, null, null, null) (line 99). No attacker data reaches the sink arguments; trigger only. All five query arguments are constants or null, which is why the superseded event read I as refuted under the literal reading. The home.solo.launcher.free.i.ap.b(getApplicationContext()) test at line 50 is an internal app-state gate, not a proof that no external trigger can reach the sink, so the convention's refuted exception does not apply. S confirmed at evidence level 1: the onCreate:55 -> b():99 chain is a concrete two-edge callsite chain with no security branch between entry and sink. A confirmed absent: the activity carries no android:permission, the application element has no permission, and onCreate and b() contain no caller identity, package, signature or UID check. Limitation: coordinator entry_evidence.linkage_status is component_class_caller, so the onCreate-to-b chain rests on this manual full-file source read; the packet ships decompiled source for only 15 classes, so the provider behind ib.f2947a could not be resolved.

### 第 2 筆 — `review-unit-v1:351e57a8ed892d9625cb494ac81153a2e7de46f29c024cba04e358c904b61a1a`

- APK／component：`9807923677bdad15ad73975167887bbbff8a25bca99736b25f88ff02600a382d`／`home.solo.launcher.free.Launcher`
- Caller／sink：`setupTransparentSystemBarsForLmp`／`java/lang/reflect/Method:invoke`
- 修訂前 `1252d2de-7486-4f63-b185-cba5af374b56`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `5e0cab85-d881-4042-a374-202cc88a345c`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`medium`
- Reviewer／assistant：`hikaru820`／`claude-code/session_7fd87cc4-bdb2-56a8-9390-e73a640b9def`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention
- 說明：Manifest evidence re-checked: home.solo.launcher.free.Launcher is declared exactly once among 103 components (76 activity, 14 service, 7 receiver, 6 provider); no manifest_name is declared twice in this APK and there is no activity-alias at all. explicit_exported=null, permission=null, application_permission empty, one intent-filter with action MAIN and categories DEFAULT and HOME, min_sdk 16 target_sdk 23, so the documented default is exported=true and the Android 12 explicit-exported requirement does not apply. R stays confirmed (confirmed_present) as in the superseded event; this revision does not re-decide R. It does upgrade platform_semantics_status from the superseded event value to verified_primary_source, because the R=confirmed basis is the implicit-intent-filter export rule. I confirmed under the 2026-09-19 trigger convention: a third-party app starting this exported activity with an explicit Intent is by itself the control flow that runs onCreate (line 329) -> setupViews (called line 343, defined line 1231) -> applyTransparentStatusBar (called line 1268, defined line 4434) -> setupTransparentSystemBarsForLmp (called line 4438, defined line 4463) -> the two Method.invoke callsites at line 4472 and line 4473. No attacker data reaches the sink arguments; trigger only. Both invoke calls pass getWindow() and the hardcoded literal 0, which is why the superseded event read I as refuted under the literal reading. The branch conditions home.solo.launcher.free.i.aj.aS(this) at line 4436 (a locally persisted theme setting) and Build.VERSION.SDK_INT >= 21 at line 4437 and 4464 (device OS version) are internal state and device configuration, not a proof that no external trigger can reach the sink, so the convention's refuted exception does not apply. S confirmed at evidence level 1: the four-edge chain above is concrete with a named callsite on every edge. A confirmed absent: the activity carries no android:permission, the application element has no permission, and onCreate, setupViews, applyTransparentStatusBar and setupTransparentSystemBarsForLmp contain no caller identity, package, signature or UID check. Limitations: the reflection targets are fully resolved and are the public API methods Window.setStatusBarColor and Window.setNavigationBarColor (reflection is used only for compile-time compatibility with min_sdk 16), the effect is limited to painting the system bars transparent, so the concrete harm of this candidate is very low even though the decision table derives positive; onCreate lines 332-337 finish this activity and start SplashActivity on the first-run internal state, in which case this chain does not execute; coordinator entry_evidence.linkage_status is component_class_caller, so the chain rests on this manual source read. This unit covers the java/lang/reflect/Method:invoke callsite at call_offset 228, source line 4473 (declaredMethod2 resolving Window.setNavigationBarColor).

### 第 3 筆 — `review-unit-v1:684ca146aa43c3fc8fe3913598ef02c7d7f8ad0c33ea73bcae462d0a1133730e`

- APK／component：`9807923677bdad15ad73975167887bbbff8a25bca99736b25f88ff02600a382d`／`home.solo.launcher.free.Launcher`
- Caller／sink：`setupTransparentSystemBarsForLmp`／`java/lang/reflect/Method:invoke`
- 修訂前 `25c2fb1a-7acf-4cd1-ae06-0896028bdcd6`：R/I/S/A `confirmed`／`refuted`／`confirmed`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `7cf724d6-849a-43ec-8d53-920172eec92d`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`medium`
- Reviewer／assistant：`hikaru820`／`claude-code/session_7fd87cc4-bdb2-56a8-9390-e73a640b9def`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention
- 說明：Manifest evidence re-checked: home.solo.launcher.free.Launcher is declared exactly once among 103 components (76 activity, 14 service, 7 receiver, 6 provider); no manifest_name is declared twice in this APK and there is no activity-alias at all. explicit_exported=null, permission=null, application_permission empty, one intent-filter with action MAIN and categories DEFAULT and HOME, min_sdk 16 target_sdk 23, so the documented default is exported=true and the Android 12 explicit-exported requirement does not apply. R stays confirmed (confirmed_present) as in the superseded event; this revision does not re-decide R. It does upgrade platform_semantics_status from not_needed in the superseded event to verified_primary_source, because the R=confirmed basis is the implicit-intent-filter export rule and that rule needs a primary source. I confirmed under the 2026-09-19 trigger convention: a third-party app starting this exported activity with an explicit Intent is by itself the control flow that runs onCreate (line 329) -> setupViews (called line 343, defined line 1231) -> applyTransparentStatusBar (called line 1268, defined line 4434) -> setupTransparentSystemBarsForLmp (called line 4438, defined line 4463) -> the two Method.invoke callsites at line 4472 and line 4473. No attacker data reaches the sink arguments; trigger only. Both invoke calls pass getWindow() and the hardcoded literal 0, which is why the superseded event read I as refuted under the literal reading. The branch conditions home.solo.launcher.free.i.aj.aS(this) at line 4436 and Build.VERSION.SDK_INT >= 21 at line 4437 and 4464 are internal state and device configuration, not a proof that no external trigger can reach the sink, so the convention's refuted exception does not apply. S stays confirmed at evidence level 1 exactly as in the superseded event: the four-edge chain above is concrete with a named callsite on every edge. A confirmed absent (changed from unknown, which the superseded event had left as not_reviewed_after_decisive_blocker): the activity carries no android:permission, the application element has no permission, and onCreate, setupViews, applyTransparentStatusBar and setupTransparentSystemBarsForLmp contain no caller identity, package, signature or UID check. Limitations: the reflection targets are fully resolved and are the public API methods Window.setStatusBarColor and Window.setNavigationBarColor (reflection is used only for compile-time compatibility with min_sdk 16), the effect is limited to painting the system bars transparent, so the concrete harm of this candidate is very low even though the decision table derives positive; onCreate lines 332-337 finish this activity and start SplashActivity on the first-run internal state, in which case this chain does not execute; coordinator entry_evidence.linkage_status is component_class_caller, so the chain rests on this manual source read. This unit covers the java/lang/reflect/Method:invoke callsite at call_offset 192, source line 4472 (declaredMethod resolving Window.setStatusBarColor).

### 第 4 筆 — `review-unit-v1:357696ee7d51e075cc19ee75faf6d664138c4fa5a30b628e09b41533ba49ff0b`

- APK／component：`9807923677bdad15ad73975167887bbbff8a25bca99736b25f88ff02600a382d`／`home.solo.launcher.free.Launcher`
- Caller／sink：`saveImageToSDCard`／`java/io/FileOutputStream:<init>`
- 修訂前 `0d92b609-2c6a-49b9-81b1-f5f564ca8ece`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `fd0bbd5c-6b12-4411-bc93-88b7387640df`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`medium`
- Reviewer／assistant：`hikaru820`／`claude-code/session_7fd87cc4-bdb2-56a8-9390-e73a640b9def`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention
- 說明：Manifest evidence re-checked: home.solo.launcher.free.Launcher is declared exactly once among 103 components (76 activity, 14 service, 7 receiver, 6 provider); no manifest_name is declared twice in this APK and there is no activity-alias at all. explicit_exported=null, permission=null, application_permission empty, one intent-filter with action MAIN and categories DEFAULT and HOME, min_sdk 16 target_sdk 23, so the documented default is exported=true and the Android 12 explicit-exported requirement does not apply. R stays confirmed (confirmed_present) as in the superseded event; this revision does not re-decide R. I confirmed under the 2026-09-19 trigger convention: a third-party app starting this exported activity with an explicit Intent is by itself the control flow that runs onCreate (line 329) -> initData (called line 340, defined line 477) -> setupThemeSettings (called line 528, defined line 1369) -> saveImageToSDCard (called line 1372, defined line 4790) -> new FileOutputStream(file) at line 4800. No attacker data reaches the sink arguments; trigger only. The target path is the fixed string home.solo.launcher.free.common.c.m.f + "/share.jpg" built at line 4792 and the payload is the bundled resource R.drawable.theme_preview1 opened at line 4798, which is why the superseded event read I as refuted under the literal reading. The guard home.solo.launcher.free.i.aj.F(this) at line 1371 is an internal one-shot completion flag, not a proof that no external trigger can reach the sink, so the convention's refuted exception does not apply. S confirmed at evidence level 1: the four-edge chain above is concrete with a named callsite on every edge and no security branch. A confirmed absent: the activity carries no android:permission, the application element has no permission, and onCreate, initData, setupThemeSettings and saveImageToSDCard contain no caller identity, package, signature or UID check. Limitations: both the write path and the written content are fixed and the aj.F flag is set to true at line 4815 so the write happens at most once, which makes the concrete harm of this candidate low even though the decision table derives positive; onCreate lines 332-337 finish this activity and start SplashActivity on the first-run internal state, in which case this chain does not execute; coordinator entry_evidence.linkage_status is component_class_caller, so the chain rests on this manual source read. This unit covers the java/io/FileOutputStream:<init> callsite at call_offset 116, source line 4800.

## label 變化統計

| 修訂前 | 修訂後 | 筆數 |
| --- | --- | ---: |
| negative | positive | 4 |
| **合計** | | **4** |

## 維持原判定的 unit（不寫入 event）

本批 8 筆中，以下 4 筆依 2026-09-19 觸發慣例重新判定後，R/I/S/A 與 label 完全不變，依 `docs/golden_revision_i_convention_plan.md` 步驟 5 不建立 supersession event，只記錄於本紀錄。

### 1. `review-unit-v1:2b29caa6171860be89d1ab5bd67d61ce4dc69a0af85a7682779d1ea8eaf3b74f`

- APK／component：`9807923677bdad15ad73975167887bbbff8a25bca99736b25f88ff02600a382d`／`home.solo.launcher.free.Launcher`
- Caller／sink：`showRecentlyApp`／`java/lang/Class:forName`（call_offset 4，`Launcher.java:2505`）
- 現行 event `cfb2831f-7633-49e4-87d4-ae271cca1ca5`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 維持理由：`showRecentlyApp()`（`Launcher.java:2503`）在全檔只有一個呼叫點 `onClickSoloShortcut(Intent)`（`Launcher.java:2214`，條件為 extra `LAUNCHER_ACTION` 等於 `SHOW_RECENT_APPS`）；`onClickSoloShortcut` 只被 `handleShortcutIntent`（`Launcher.java:2311`）呼叫；`handleShortcutIntent` 只被 `onClick(View)`（`Launcher.java:2440`）呼叫，且傳入的 `Intent` 取自 `view.getTag()` 的 `jg.b`（launcher 自己資料庫中已放置的捷徑），不是 `Activity.getIntent()`。`onNewIntent`（`Launcher.java:1671-1684`）只處理 `android.intent.action.MAIN`，不會 dispatch 到 `onClickSoloShortcut`；全檔 `getIntent()` 只出現於 `Launcher.java:1993`（`itemAt.getIntent()`，clipboard item）。外部 app 啟動這個 exported activity 不會讓該 sink 執行，符合慣例中「sink 實際上無法由任何外部觸發到達（只有使用者點擊 app 內自建的圖示才會執行）」的 `I=refuted` 例外。I 仍為 decisive blocker，S／A 維持 `not_reviewed_after_decisive_blocker`。

### 2. `review-unit-v1:172b83afd8904917f5e4947df0e4337afeed0d499c265c11752c59269d917af5`

- APK／component：`9807923677bdad15ad73975167887bbbff8a25bca99736b25f88ff02600a382d`／`home.solo.launcher.free.solomarket.activity.LocalWallpaperActivity`
- Caller／sink：`a(Landroid/content/Context; Landroid/net/Uri;)Ljava/lang/String;`／`android/os/Environment:getExternalStorageDirectory`（call_offset 98，`LocalWallpaperActivity.java:168`）
- 現行 event `ac4f9918-c1d3-4962-a8e4-91a60204a73e`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 維持理由：見下方三筆共同理由。

### 3. `review-unit-v1:5a516d1c85c0d9d8c224f0ba162a89167edad1628ea6187ede5650947f49237a`

- APK／component：同上／`home.solo.launcher.free.solomarket.activity.LocalWallpaperActivity`
- Caller／sink：`a(Landroid/content/Context; Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)Ljava/lang/String;`／`android/database/Cursor:getString`（call_offset 74，`LocalWallpaperActivity.java:208`）
- 現行 event `05afca57-05da-4acf-920e-ba96dfde1cc9`：R/I/S/A `confirmed`／`refuted`／`refuted`／`unknown`；label／confidence `negative`／`high`
- 既有 safe group：`safe-group-v1:localwallpaperactivity-a-query-201-220`

### 4. `review-unit-v1:ce31d8ec52b4af2218f1bcc3ab4944c3b4b3e06e606628b69a89d14b49fe20c9`

- APK／component：同上／`home.solo.launcher.free.solomarket.activity.LocalWallpaperActivity`
- Caller／sink：同第 3 筆 caller／`android/content/ContentResolver:query`（call_offset 38，`LocalWallpaperActivity.java:204`）
- 現行 event `7a7b31f9-1868-4b64-843a-d1b039cc9d05`：R/I/S/A `confirmed`／`refuted`／`refuted`／`unknown`；label／confidence `negative`／`high`
- 既有 safe group：`safe-group-v1:localwallpaperactivity-a-query-201-220`

**第 2–4 筆共同維持理由**：`LocalWallpaperActivity.java` 全檔 248 行已重讀。三個 sink 都只能經由 `onActivityResult`（`LocalWallpaperActivity.java:72-73`，requestCode 203 / resultCode 300）到達。`onActivityResult` 只能由 Android framework 在本 Activity 自己先前 `startActivityForResult` 之後回呼，第三方 app 無法偽造；唯一觸發鏈是使用者點擊 app 內 gallery 按鈕（`LocalWallpaperActivity.java:88-92`，`ACTION_GET_CONTENT`，requestCode 202）→ 系統選圖器回傳 → 內部 `CropWallpaperActivity`（`LocalWallpaperActivity.java:59-61`，requestCode 203）→ `a(...)`。外部 app 即使啟動這個 `explicit_exported=true` 的 Activity，走的是 `BaseMarketActivity.onCreate` → 覆寫的 `a()`／`b()`（`LocalWallpaperActivity.java:37-53`）→ `d()` → `c()`，完全到不了上述 sink，符合慣例的 `I=refuted` 例外。Limitation：packet 只提供 15 個類別的反編譯原始碼，`a(Context,Uri,String,String[])` 為 `public static`；在已提供的原始碼中，`LocalWallpaperActivity` 只被 `Launcher.java:5648` 以 explicit Intent 啟動，沒有其他類別呼叫這兩個 static helper，但無法排除未提供原始碼的類別中存在其他 caller。

## R 沿用與 R 錯誤檢查

本批 8 筆的 R 全部沿用原值 `confirmed`，讀碼過程未發現原 R 有明顯錯誤，無需在後續批次修正。唯一 provenance 落差：`review-unit-v1:684ca146aa43…` 的被取代 event `25c2fb1a-7acf-4cd1-ae06-0896028bdcd6` 將 `platform_semantics_status` 記為 `not_needed`，但其 R=confirmed 的依據是 intent-filter 隱含 exported 規則；新 event `7cf724d6-849a-43ec-8d53-920172eec92d` 已補為 `verified_primary_source` 並附上 developer.android.com 一手來源。
