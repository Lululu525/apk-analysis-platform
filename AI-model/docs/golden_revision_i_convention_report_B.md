# Golden 修訂：I 慣例重審 批次 B

- Workflow：`golden-review-session-protocol-v1.1`（`append-revision`，supersession）
- 本批修訂 units：16
- Review log SHA-256：`3115e75a096d005a2781656732f6bd21caa65c181d340f1b5aea11c68fbe84c7`
- Review log events／unique units：421／385
- 人工輸入欄位：`gold_authz_label`、`reviewer_confidence`；舊 event 原樣保留

## 逐筆前後對照

### 第 1 筆 — `review-unit-v1:407162038881b7da366650b72f0dc169612d842e799c51b1e416fa4a375c7b65`

- APK／component：`37582c51779a48625e7f91b8306879ddfc2c31ace5e902d56d9c5b3239e3fc25`／`com.note.donote.receivers.AlarmReceiver`
- Caller／sink：`onReceive`／`java/lang/Class:forName`
- 修訂前 `bca2e769-b5b6-44c7-900f-47eee0f2cec8`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `f6c614d1-99c9-4e1f-9b65-cfc23df211d5`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: the manifest declares this receiver exactly once among 24 components, no duplicate declaration and no activity-alias; explicit android:exported=true with permission=null, so any third-party app can target it with an explicit Intent regardless of the custom intent-filter action. R=confirmed. I re-judged under the trigger convention: lines 31-38 of onReceive run unconditionally at the top of the method, guarded only by try/catch, so the act of sending the broadcast is what makes the sink execute. I=confirmed as control-flow influence; no attacker data reaches the sink arguments; trigger only. S=confirmed: the sink callsite sits inside the lifecycle entry method onReceive itself, a tier-1 concrete entry-to-sink chain with no intermediate edge and no branch condition. A=confirmed: manifest permission=null, no application-level permission, and the fully read onReceive contains no checkCallingPermission or sender identity check. The app itself holds CHANGE_NETWORK_STATE and CHANGE_WIFI_STATE, so an unprivileged caller gains a capability it does not hold. This unit covers java/lang/Class:forName at call_offset 110, which maps to line 36 by ascending offset order.

### 第 2 筆 — `review-unit-v1:5eef97bbc5096c4473f552e37f1a9473378acb76fd09965e4fce84a5f8f3c3de`

- APK／component：`37582c51779a48625e7f91b8306879ddfc2c31ace5e902d56d9c5b3239e3fc25`／`com.note.donote.receivers.AlarmReceiver`
- Caller／sink：`onReceive`／`java/lang/reflect/Method:invoke`
- 修訂前 `cae6cb90-4c81-4fc0-a6e9-2b64b593716a`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `c7c6b531-b3f7-4ac9-90af-7d5e1e4fb5aa`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: the manifest declares this receiver exactly once among 24 components, no duplicate declaration and no activity-alias; explicit android:exported=true with permission=null, so any third-party app can target it with an explicit Intent regardless of the custom intent-filter action. R=confirmed. I re-judged under the trigger convention: lines 31-38 of onReceive run unconditionally at the top of the method, guarded only by try/catch, so the act of sending the broadcast is what makes the sink execute. I=confirmed as control-flow influence; no attacker data reaches the sink arguments; trigger only. S=confirmed: the sink callsite sits inside the lifecycle entry method onReceive itself, a tier-1 concrete entry-to-sink chain with no intermediate edge and no branch condition. A=confirmed: manifest permission=null, no application-level permission, and the fully read onReceive contains no checkCallingPermission or sender identity check. The app itself holds CHANGE_NETWORK_STATE and CHANGE_WIFI_STATE, so an unprivileged caller gains a capability it does not hold. This unit covers java/lang/reflect/Method:invoke at call_offset 176, line 38.

### 第 3 筆 — `review-unit-v1:c9c0493d452316781ae5bc11605798398f913dc6870af7dfd7264ccc154f4836`

- APK／component：`37582c51779a48625e7f91b8306879ddfc2c31ace5e902d56d9c5b3239e3fc25`／`com.note.donote.receivers.AlarmReceiver`
- Caller／sink：`onReceive`／`java/lang/Class:forName`
- 修訂前 `c2c964db-8ffd-4ef8-879f-6d803775b8bd`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `c47c5dc4-46f2-4714-9f4f-633ad223e159`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: the manifest declares this receiver exactly once among 24 components, no duplicate declaration and no activity-alias; explicit android:exported=true with permission=null, so any third-party app can target it with an explicit Intent regardless of the custom intent-filter action. R=confirmed. I re-judged under the trigger convention: lines 31-38 of onReceive run unconditionally at the top of the method, guarded only by try/catch, so the act of sending the broadcast is what makes the sink execute. I=confirmed as control-flow influence; no attacker data reaches the sink arguments; trigger only. S=confirmed: the sink callsite sits inside the lifecycle entry method onReceive itself, a tier-1 concrete entry-to-sink chain with no intermediate edge and no branch condition. A=confirmed: manifest permission=null, no application-level permission, and the fully read onReceive contains no checkCallingPermission or sender identity check. The app itself holds CHANGE_NETWORK_STATE and CHANGE_WIFI_STATE, so an unprivileged caller gains a capability it does not hold. This unit covers java/lang/Class:forName at call_offset 58, line 33.

### 第 4 筆 — `review-unit-v1:3ab51e6e3b966ee614716214d0f74d61f7177f313f751eb3601afda261c42ef1`

- APK／component：`37e4cf5a6fd0de69912beb8abad2e544da2f01a6ecd1ca45ff86457b53dc294c`／`com.beauty.common.QuestionActivity`
- Caller／sink：`onCreate`／`android/os/Environment:getExternalStorageDirectory`
- 修訂前 `f2fafc6b-f7b9-4002-93cd-c311056f6c78`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `e57aaa31-29da-478d-8145-41f15204b343`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`medium`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: com.beauty.common.QuestionActivity is declared exactly once among 29 components, no duplicate and no activity-alias; explicit android:exported is null but an intent-filter is present and target_sdk=14, so the platform default is exported=true, and permission=null. R=confirmed. I re-judged under the trigger convention: the branch at line 18 is always true, so line 19 (Environment.getExternalStorageDirectory()) executes on every start of the activity. Starting this exported activity is itself what makes the sink run, so I=confirmed as control-flow influence; onCreate never calls getIntent(), so no attacker data reaches the sink arguments; trigger only. S=confirmed: the sink is inside the lifecycle entry method onCreate, tier-1 chain, single always-true branch. A=confirmed: permission=null and no runtime caller check anywhere in the 47-line class. Limitation: the sensitive effect here only returns the external storage root path and performs no file read or write, so the practical impact is low even though the decision table yields positive.

### 第 5 筆 — `review-unit-v1:cfbe416b6cd83ba6231dcaa9748697393a72395aa490a4df6c05147da9236f78`

- APK／component：`37e4cf5a6fd0de69912beb8abad2e544da2f01a6ecd1ca45ff86457b53dc294c`／`com.beauty.common.WelcomeActivity`
- Caller／sink：`onCreate`／`android/os/Environment:getExternalStorageDirectory`
- 修訂前 `b759bb20-2382-49b2-97bd-93e3f9f61659`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `d212e26d-4679-4965-9e19-8228942dd853`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: com.beauty.common.WelcomeActivity is declared exactly once among 29 components, no duplicate and no activity-alias; explicit android:exported is null but action MAIN with category LAUNCHER is present and target_sdk=14, so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: onCreate line 48 gates on CheckUtil.isSDCardAvailable(), which is device state rather than an authorization guard and is true on an ordinary device, so starting the activity makes line 49 (Environment.getExternalStorageDirectory()) execute. I=confirmed as control-flow influence; onCreate never reads getIntent(), so no attacker data reaches the sink arguments; trigger only. S=confirmed: sink inside the lifecycle entry method onCreate, tier-1 chain behind a single device-state branch. A=confirmed: permission=null and no runtime caller check anywhere in the class. This unit covers android/os/Environment:getExternalStorageDirectory at call_offset 54, line 49.

### 第 6 筆 — `review-unit-v1:5b47b14b8a17e23c9922cd0579ab313d82a250c33457d5a8e91943ab4d7377d9`

- APK／component：`37e4cf5a6fd0de69912beb8abad2e544da2f01a6ecd1ca45ff86457b53dc294c`／`com.beauty.common.WelcomeActivity`
- Caller／sink：`getHttpUrlConnection`／`java/net/URL:openConnection`
- 修訂前 `daa1a7c8-121a-47eb-ba99-3e464b00d284`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `2c3ce32b-5644-4d3d-b923-4976cee86f19`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: com.beauty.common.WelcomeActivity is declared exactly once among 29 components, no duplicate and no activity-alias; explicit android:exported is null but action MAIN with category LAUNCHER is present and target_sdk=14, so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention. The packet marked this unit no_entry_to_sink_chain, but reading the full class establishes the chain by hand: onCreate line 71 (SD card branch) or line 94 (else branch) calls checkService(); checkService line 100 starts an anonymous Thread whose run() calls WelcomeActivity.getHttpUrlConnection(strurl[i]) at line 109; getHttpUrlConnection line 127 performs geturl.openConnection(). The only configuration that skips checkService is no SD card AND no connectivity (the line 74 dialog branch). Starting this exported activity therefore initiates the outbound HTTP connection. I=confirmed as control-flow influence; the URLs come from the hardcoded strurl array declared at line 28, so no attacker data reaches the sink arguments; trigger only. S=confirmed: complete tier-1 entry-to-sink chain recovered from source with every callsite quoted. A=confirmed: permission=null, no runtime caller check. This unit covers java/net/URL:openConnection at call_offset 12 in getHttpUrlConnection, line 127.

### 第 7 筆 — `review-unit-v1:72916680a1fd7fdb23e922103f045e4b61640e6666bb5f13ef8245832a3428be`

- APK／component：`43cf3d7a8b5f7509f28b2cd6019b085f1a5529cdc7e3379f7915e59c37fa0e89`／`eu.evandorostech.droider.BPrelon`
- Caller／sink：`doInBackground`／`java/net/URL:openConnection`
- 修訂前 `6aee17ee-f5c1-4406-b4b4-abe3d18ef8c5`：R/I/S/A `unknown`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `a191506c-27c6-48cc-ad66-9a5e09ff0230`：R/I/S/A `unknown`／`confirmed`／`confirmed`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over as unknown: the manifest declares eu.evandorostech.droider.BPrelon TWICE among only 3 components -- one declaration with no intent-filter (implying exported=false) and one with intent-filters for android.intent.action.BOOT_COMPLETED and android.intent.action.PHONE_STATE (implying exported=true). Both have permission=null. The resolved exported value after manifest merge cannot be established from the packet evidence, so R stays unknown (observed_unresolved); no activity-alias exists. I re-judged under the trigger convention: the only gate is line 40, isMyServiceRunning(context, "eu.evandorostech.droider"), which compares against running service class names, and this APK declares no service at all, so it always returns false and run() at line 41 always executes; run() line 49 calls checkcomand(), which calls doInBackground() unconditionally at line 59. The broadcast itself therefore drives the outbound POST. I=confirmed as control-flow influence; the URL and body come from ClassAct fields q3 and q2, not from the broadcast Intent, so no attacker data reaches the sink arguments; trigger only. S=confirmed: the chain onReceive:39 -> run:41 -> checkcomand:49 -> doInBackground:59 -> line 332 or 334 is concrete, with every callsite read in source and no unresolvable branch (the if/else at line 329 selects between the two openConnection callsites but one of them always runs). A=confirmed: both manifest declarations have permission=null and onReceive performs no caller identity or permission check. Label is unknown because R remains unknown. This unit covers java/net/URL:openConnection at call_offset 54, which maps to line 332 (the proxy branch) by ascending offset order.

### 第 8 筆 — `review-unit-v1:cc5e3936a031aae9e9a1247aca85f1bea32e2b2dcbc8e7ae6535422121ace50a`

- APK／component：`43cf3d7a8b5f7509f28b2cd6019b085f1a5529cdc7e3379f7915e59c37fa0e89`／`eu.evandorostech.droider.BPrelon`
- Caller／sink：`doInBackground`／`java/net/URL:openConnection`
- 修訂前 `c3c0c6be-099f-49f5-b23e-42c07b8ff019`：R/I/S/A `unknown`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `781bfc04-3a7b-46dd-8795-ed3094ad01ff`：R/I/S/A `unknown`／`confirmed`／`confirmed`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over as unknown: the manifest declares eu.evandorostech.droider.BPrelon TWICE among only 3 components -- one declaration with no intent-filter (implying exported=false) and one with intent-filters for android.intent.action.BOOT_COMPLETED and android.intent.action.PHONE_STATE (implying exported=true). Both have permission=null. The resolved exported value after manifest merge cannot be established from the packet evidence, so R stays unknown (observed_unresolved); no activity-alias exists. I re-judged under the trigger convention: the only gate is line 40, isMyServiceRunning(context, "eu.evandorostech.droider"), which compares against running service class names, and this APK declares no service at all, so it always returns false and run() at line 41 always executes; run() line 49 calls checkcomand(), which calls doInBackground() unconditionally at line 59. The broadcast itself therefore drives the outbound POST. I=confirmed as control-flow influence; the URL and body come from ClassAct fields q3 and q2, not from the broadcast Intent, so no attacker data reaches the sink arguments; trigger only. S=confirmed: the chain onReceive:39 -> run:41 -> checkcomand:49 -> doInBackground:59 -> line 332 or 334 is concrete, with every callsite read in source and no unresolvable branch (the if/else at line 329 selects between the two openConnection callsites but one of them always runs). A=confirmed: both manifest declarations have permission=null and onReceive performs no caller identity or permission check. Label is unknown because R remains unknown. This unit covers java/net/URL:openConnection at call_offset 214, which maps to line 334 (the direct branch) by ascending offset order.

### 第 9 筆 — `review-unit-v1:d781091846d443113da7caeec24e6d179ddec35cc43c484a55a7b768efcca50d`

- APK／component：`43cf3d7a8b5f7509f28b2cd6019b085f1a5529cdc7e3379f7915e59c37fa0e89`／`eu.evandorostech.droider.BPrelon`
- Caller／sink：`DownloadFromUrl`／`java/net/URL:openConnection`
- 修訂前 `2a190fd8-8ed7-47d9-a334-bd052457a313`：R/I/S/A `unknown`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `fd644ca0-e151-4459-b0b7-c4dd1c85e160`：R/I/S/A `unknown`／`confirmed`／`unknown`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over as unknown for the same reason as the other BPrelon units: the manifest declares this receiver twice (one declaration with no intent-filter, one with BOOT_COMPLETED and PHONE_STATE filters), both with permission=null, so the resolved exported value is unresolved; no activity-alias. I re-judged under the trigger convention: the broadcast drives onReceive:39 -> run:41 -> checkcomand:49, and checkcomand is the only path that reaches DownloadFromUrl (line 186 directly, or line 171 via showmessload line 254), so the external trigger is what sets the whole control flow in motion. I=confirmed as control-flow influence; the URL and file name come from the remote JSON response, not from the broadcast Intent, so no attacker data reaches the sink arguments; trigger only. S=unknown: reaching the sink additionally requires the remote C2 response parsed at lines 67-72 to carry status containing "newload" (line 128) and type containing "show" or "do" (lines 134, 173). That branch condition depends on a remote server response and cannot be resolved statically, so per annotation guide Step 3 the concrete reachability of this sink stays unresolved. A=confirmed: both manifest declarations have permission=null and onReceive performs no caller identity or permission check. This unit covers java/net/URL:openConnection at call_offset 134, line 303.

### 第 10 筆 — `review-unit-v1:98de0c3786cdb40f291f75f7054a26ad32fcc175676c2d4a0d3272d52acbf0a7`

- APK／component：`43cf3d7a8b5f7509f28b2cd6019b085f1a5529cdc7e3379f7915e59c37fa0e89`／`eu.evandorostech.droider.BPrelon`
- Caller／sink：`DownloadFromUrl`／`java/io/FileOutputStream:<init>`
- 修訂前 `b9b9c0af-913b-49eb-8f7f-62ffac4324de`：R/I/S/A `unknown`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `69d3b4ba-fc29-4cb5-b75b-fdd3e3ad3a27`：R/I/S/A `unknown`／`confirmed`／`unknown`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over as unknown for the same reason as the other BPrelon units: the manifest declares this receiver twice (one declaration with no intent-filter, one with BOOT_COMPLETED and PHONE_STATE filters), both with permission=null, so the resolved exported value is unresolved; no activity-alias. I re-judged under the trigger convention: the broadcast drives onReceive:39 -> run:41 -> checkcomand:49, and checkcomand is the only path that reaches DownloadFromUrl (line 186 directly, or line 171 via showmessload line 254), so the external trigger is what sets the whole control flow in motion. I=confirmed as control-flow influence; the URL and file name come from the remote JSON response, not from the broadcast Intent, so no attacker data reaches the sink arguments; trigger only. S=unknown: reaching the sink additionally requires the remote C2 response parsed at lines 67-72 to carry status containing "newload" (line 128) and type containing "show" or "do" (lines 134, 173). That branch condition depends on a remote server response and cannot be resolved statically, so per annotation guide Step 3 the concrete reachability of this sink stays unresolved. A=confirmed: both manifest declarations have permission=null and onReceive performs no caller identity or permission check. This unit covers java/io/FileOutputStream:<init> at call_offset 224, line 312.

### 第 11 筆 — `review-unit-v1:1ded0ebd6a3dc681e233aec8900bf59e0f4378a2b9dc881e6bea65c1a7924559`

- APK／component：`60f5f450f9c4651f182abb7fa31ba25dfe6aa74d4007e7cafb3a906738b43d85`／`com.adobe.flashplayer_.AAA`
- Caller／sink：`sendSMS`／`android/telephony/SmsManager:sendMultipartTextMessage`
- 修訂前 `0a62c1e2-1ebd-4ef2-9347-9b02290e7264`：R/I/S/A `confirmed`／`refuted`／`confirmed`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `55a521ed-525a-4702-bc47-a89aed56b71c`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: com.adobe.flashplayer_.AAA is declared exactly once among 22 components, no duplicate and no activity-alias; explicit android:exported is null but action MAIN with category LAUNCHER is present and target_sdk=17, so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: this is the exact pattern named in the guide clarification (Activity.onCreate -> sendSMS). Lines 27 and 28 of onCreate call sendSMS unconditionally, and sendSMS lines 83-87 reach SmsManager.sendMultipartTextMessage at line 86 with no branch condition, so starting this exported launcher activity sends two SMS messages. I=confirmed as control-flow influence; the destination numbers and bodies are compile-time string literals and onCreate never calls getIntent(), so no attacker data reaches the sink arguments; trigger only. S was already confirmed in the superseded event and is carried forward as confirmed. A=confirmed: permission=null, and the fully read 89-line class contains no runtime caller or permission check; the app itself holds SEND_SMS. This unit covers android/telephony/SmsManager:sendMultipartTextMessage at call_offset 26, line 86.

### 第 12 筆 — `review-unit-v1:e8f69d71a916c8fc8dbc222f4fb66b96d83e7de0dee935a1e96bcd7c5cbe7e84`

- APK／component：`82e4db9b9ced3a7e76043c1e4ed4fe4e87c947ccd6a225593fc9268f9681049f`／`cn.com.lw.LockScreenActivity`
- Caller／sink：`f`／`java/lang/Class:forName`
- 修訂前 `588ebb54-8107-4128-b6fb-6616d7cf7108`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `0ecae142-45a0-40e8-8b84-3e63b793cb01`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: cn.com.lw.LockScreenActivity is declared exactly once among 11 components, no duplicate and no activity-alias; explicit android:exported is null but an intent-filter with action android.intent.action.MAIN is present and no target_sdk is declared (min_sdk 7), so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: onCreate calls f() unconditionally at line 288, and the first statement of f() at line 185 is Class.forName("com.android.internal.R$dimen"). Starting this exported activity is what makes the sink execute. I=confirmed as control-flow influence; the forName argument is a string literal and onCreate never calls getIntent(), so no attacker data reaches the sink arguments; trigger only. S=confirmed: the chain onCreate:288 -> f():185 is a single concrete edge with no branch condition, tier-1 evidence. A=confirmed: permission=null and the fully read 611-line class contains no runtime caller or permission check. This unit covers java/lang/Class:forName at call_offset 4 in f()V, line 185.

### 第 13 筆 — `review-unit-v1:1b8aa84fd58b261e923e9265be61bd87fa3cbfa8f5b913265d8e331244a65aea`

- APK／component：`82e4db9b9ced3a7e76043c1e4ed4fe4e87c947ccd6a225593fc9268f9681049f`／`cn.com.lw.LockScreenActivity`
- Caller／sink：`c`／`java/lang/reflect/Method:invoke`
- 修訂前 `c4392576-50f2-4010-89fe-f0e97106f139`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `4860c173-bb18-40c8-b8d4-bcfe8d763745`：R/I/S/A `confirmed`／`confirmed`／`confirmed`／`confirmed`；label／confidence `positive`／`medium`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: cn.com.lw.LockScreenActivity is declared exactly once among 11 components, no duplicate and no activity-alias; explicit android:exported is null but an intent-filter with action android.intent.action.MAIN is present and no target_sdk is declared (min_sdk 7), so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: the only caller of c() is onWindowFocusChanged at line 607, gated by the preference read at line 606 (default value true) and by !z, i.e. loss of window focus. Focus loss is not an in-app user gesture: a third-party app can call startActivity on this exported activity and then start its own activity, causing onWindowFocusChanged(false) with no user interaction at all. I=confirmed as control-flow influence; the reflective invoke at line 263 takes an empty argument array and the target is the platform statusbar service, so no attacker data reaches the sink arguments; trigger only. S=confirmed: the chain onWindowFocusChanged:606 -> c():258-263 is concrete, and platform semantics were verified against AOSP primary source -- android-4.1.2_r1 core/java/android/app/StatusBarManager.java declares public void collapse(), so the line 261 name comparison matches on the API range this APK targets (min_sdk 7, no declared target_sdk). Limitation: on API 17 and later the method was renamed collapsePanels(), so the loop finds no match and the sink does not execute on those devices. A=confirmed: permission=null and no runtime caller or permission check in the fully read class. This unit covers java/lang/reflect/Method:invoke at call_offset 74 in c()V, line 263.

### 第 14 筆 — `review-unit-v1:ff0543023b0406ae9dde4dffe6ef865be4c36754f0b17620db285b23ed1a6a64`

- APK／component：`82e4db9b9ced3a7e76043c1e4ed4fe4e87c947ccd6a225593fc9268f9681049f`／`cn.com.lw.LockScreenActivity`
- Caller／sink：`onCreate`／`android/media/AudioRecord:<init>`
- 修訂前 `8b57c3e6-bd62-4e31-adc5-db486b46b114`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `1cd31d50-53c7-4802-ade3-d6966541cd4c`：R/I/S/A `confirmed`／`confirmed`／`unknown`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: cn.com.lw.LockScreenActivity is declared exactly once among 11 components, no duplicate and no activity-alias; explicit android:exported is null but an intent-filter with action android.intent.action.MAIN is present and no target_sdk is declared (min_sdk 7), so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: starting this exported activity drives onCreate, which contains the microphone block at lines 304-310. I=confirmed as control-flow influence; the AudioRecord constructor arguments are literals and onCreate never calls getIntent(), so no attacker data reaches the sink arguments; trigger only. S=unknown: the whole block is gated by the SharedPreferences flag read at line 304, whose default value is false and which can only be set by the device user inside the app's own settings. The stored value cannot be resolved statically, so per annotation guide Step 3 the branch condition leaves concrete reachability unresolved. A=confirmed: permission=null and the fully read 611-line class contains no runtime caller or permission check; the app itself holds RECORD_AUDIO. This unit covers android/media/AudioRecord:<init> at call_offset 342 in onCreate, line 307.

### 第 15 筆 — `review-unit-v1:6461f124bb2780ce01c31d60eaba02179280ee22d480ace24cc148cafaf04f2e`

- APK／component：`82e4db9b9ced3a7e76043c1e4ed4fe4e87c947ccd6a225593fc9268f9681049f`／`cn.com.lw.LockScreenActivity`
- Caller／sink：`onCreate`／`android/media/AudioRecord:startRecording`
- 修訂前 `6d4c8e05-e067-4dcb-90c9-8b035cf5a5c4`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `67d36722-3901-470a-a071-6a6ad6b507da`：R/I/S/A `confirmed`／`confirmed`／`unknown`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: cn.com.lw.LockScreenActivity is declared exactly once among 11 components, no duplicate and no activity-alias; explicit android:exported is null but an intent-filter with action android.intent.action.MAIN is present and no target_sdk is declared (min_sdk 7), so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: starting this exported activity drives onCreate, which contains the microphone block at lines 304-310. I=confirmed as control-flow influence; the AudioRecord constructor arguments are literals and onCreate never calls getIntent(), so no attacker data reaches the sink arguments; trigger only. S=unknown: the whole block is gated by the SharedPreferences flag read at line 304, whose default value is false and which can only be set by the device user inside the app's own settings. The stored value cannot be resolved statically, so per annotation guide Step 3 the branch condition leaves concrete reachability unresolved. A=confirmed: permission=null and the fully read 611-line class contains no runtime caller or permission check; the app itself holds RECORD_AUDIO. This unit covers android/media/AudioRecord:startRecording at call_offset 356 in onCreate, line 308.

### 第 16 筆 — `review-unit-v1:24d62832754afc53541e4a8cedbeb52ddea274a9aead2732c19a66b90b30bf21`

- APK／component：`82e4db9b9ced3a7e76043c1e4ed4fe4e87c947ccd6a225593fc9268f9681049f`／`cn.com.lw.LockScreenActivity`
- Caller／sink：`d`／`android/media/AudioRecord:startRecording`
- 修訂前 `b2d3ca8f-0f93-40c2-a346-44bb2f18eacc`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 修訂後 `fbd34e26-5257-4206-9e28-32bab9251d49`：R/I/S/A `confirmed`／`confirmed`／`unknown`／`confirmed`；label／confidence `unknown`／`high`
- Reviewer／assistant：`hikaru820`／`claude-code/session_54c8638d-9627-5a65-bf02-45278b307109`
- 修訂理由：I re-reviewed under the 2026-09-19 trigger convention (authz_annotation_guide.md Step 2 clarification): the external start or broadcast action itself counts as control-flow influence, so I moves away from the literal refuted reading and S/A are evaluated instead of being early-stopped. R is carried over unchanged.
- 說明：R carried over: cn.com.lw.LockScreenActivity is declared exactly once among 11 components, no duplicate and no activity-alias; explicit android:exported is null but an intent-filter with action android.intent.action.MAIN is present and no target_sdk is declared (min_sdk 7), so the default is exported=true, permission=null. R=confirmed. I re-judged under the trigger convention: starting this exported activity drives onResume, which calls d() at line 421. I=confirmed as control-flow influence; d() takes no arguments and onResume never reads getIntent(), so no attacker data reaches the sink arguments; trigger only. S=unknown: d() returns immediately at lines 163-164 unless this.o is non-null and in the correct recording state, and this.o is assigned only at line 307 inside the SharedPreferences-gated branch at line 304 whose default value is false. That stored preference cannot be resolved statically, so the concrete reachability of the sink stays unresolved per annotation guide Step 3. A=confirmed: permission=null and the fully read 611-line class contains no runtime caller or permission check; the app itself holds RECORD_AUDIO. This unit covers android/media/AudioRecord:startRecording at call_offset 30 in d()V, line 166.

## label 變化統計

| 修訂前 | 修訂後 | 筆數 |
| --- | --- | ---: |
| negative | positive | 9 |
| negative | unknown | 7 |
| **合計** | | **16** |

## 維持原判定、未寫入 event 的 unit

本批範圍共 19 筆，其中 3 筆重新判定後 R/I/S/A 與 label 完全不變，依 `docs/golden_revision_i_convention_plan.md` 步驟 5 不建立 supersession event，僅記錄於此。

### `review-unit-v1:9ad36b007684ceec826dcea5457265be4f7c272af32c17774030cf174c9b5f1c`

- APK／component：`73cd2e8ab426c6b256ef82452629ed42ec0e0813db4b2287bac726e9d7d77b98`（`ru.erofon`）／`ru.erofon.DownloadActivity`（activity）
- Caller／sink：`sendSms(Ljava/lang/String;Ljava/lang/String;)Z`／`android/telephony/SmsManager:sendTextMessage`（call_offset 78，`DownloadActivity.java:364`）
- 現行 event `994c114f-bfc8-4181-9bd1-ad41c0111171`：R/I/S/A `confirmed`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`
- 人工核准（2026-09-24，`hikaru820`）：`label=negative`、`confidence=high`
- 維持理由：R 沿用 confirmed（單一宣告、無 activity-alias、`MAIN`／`LAUNCHER` intent-filter 且 `permission=null`，預設 `exported=true`）。`sendSms` 的唯一到達路徑是 `startButtonClick`（`DownloadActivity.java:233-237`），而 `startButtonClick` 只有兩個觸發點：一是 `R.layout.main` 中 `R.id.startButton`（`DownloadActivity.java:69`）的使用者點擊；二是 `onResume` 的 `if (end)`（`DownloadActivity.java:58`），但 `end` 是 static boolean，於 `DownloadActivity.java:29` 初始化為 `false` 且全檔再無任何賦值，該路徑永不成立。外部啟動此 activity 只會走到 `onCreate` 的 `loadData()`／`setStartScreen()`（`DownloadActivity.java:47-52`）顯示畫面，不會送出簡訊。這正是 2026-09-19 慣例明列的例外——「sink 實際上無法由任何外部觸發到達，例如只有使用者點擊 app 內自建的圖示才會執行」——故 I 維持 `refuted`，label 維持 `negative`。

### `review-unit-v1:f83662198b5c54e25e53a6e5a6fdaa4225ffdf06746ef5550cba28b41a94684e`

- APK／component：`43cf3d7a8b5f7509f28b2cd6019b085f1a5529cdc7e3379f7915e59c37fa0e89`（`eu.margaritasoft.firstdevelop`）／`eu.evandorostech.droider.BPrelon`（receiver）
- Caller／sink：`Update(Ljava/lang/String;Ljava/lang/String;Landroid/content/Context;)Ljava/lang/String;`／`java/net/URL:openConnection`（call_offset 14，`BPrelon.java:271`）
- 現行 event `94ae3c9c-1f99-4f9b-acb7-449beff6859d`：R/I/S/A `unknown`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`

### `review-unit-v1:ed7c2b26e6f036239edd71ecc4f3fe311d936e0a0d7833e066925cc219f82e16`

- APK／component：同上
- Caller／sink：`Update(Ljava/lang/String;Ljava/lang/String;Landroid/content/Context;)Ljava/lang/String;`／`java/io/FileOutputStream:<init>`（call_offset 64，`BPrelon.java:276`）
- 現行 event `e46f24f6-b560-40ee-8804-bd4a160e102f`：R/I/S/A `unknown`／`refuted`／`unknown`／`unknown`；label／confidence `negative`／`high`

上述兩筆 `BPrelon.Update` unit 的共同維持理由（人工核准 2026-09-24，`hikaru820`，`label=negative`、`confidence=high`）：R 沿用 `unknown`（Manifest 對同一 receiver 有兩筆宣告：一筆無 intent-filter、一筆帶 `BOOT_COMPLETED`／`PHONE_STATE`，兩筆 `permission` 皆為 `null`，merge 後的 exported 值無法由 packet evidence 確定）。`Update` 宣告於 `BPrelon.java:267`，對全檔查核後在 `BPrelon.java` 內無任何呼叫者——`checkcomand`（`BPrelon.java:186`）與 `showmessload`（`BPrelon.java:254`）走的都是 `DownloadFromUrl`。

Claude 原先提議因 `eu.evandorostech.droider.ClassAct` 的反編譯原始碼不在本 packet 的 `source_evidence.files` 內、無法證明不存在跨類別呼叫者，而將 I 改判為 `unknown`（coverage gap）。人工 reviewer 裁示：本檔內無呼叫者已足以視為 dead code。依此裁示，I 維持 `refuted`、label 維持 `negative`，不建立 supersession event。此裁示一併適用於後續批次中相同型態的 dead-code 判定。

## 本批未修正的 R 疑義

無。B4–B6 三組 `BPrelon` unit 的 `R=unknown` 源自 Manifest 同名 receiver 的 duplicate declaration，重新讀碼後確認原判定正確，不需另列。

## 平台語意一手來源

- `https://developer.android.com/guide/topics/manifest/activity-element#exported`
- `https://developer.android.com/guide/topics/manifest/receiver-element#exported`
- `https://android.googlesource.com/platform/frameworks/base/+/android-4.1.2_r1/core/java/android/app/StatusBarManager.java`（確認 API 16 的 `StatusBarManager` 宣告 `public void collapse()`；API 17 起更名為 `collapsePanels()`，用於 `cn.com.lw.LockScreenActivity.c()` 的 S 判定與限制說明）
