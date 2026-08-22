# 技術筆記：真實世界資料人工抽查發現——`exported` 元件的語意落差與規則調整路線

這份筆記是 `STATUS_2026-07-16.md` 第 2–4 節的展開版，目的是把「這次抽查
到底發現了什麼、為什麼會這樣、路線 A/B 各自意味著什麼」完整寫清楚，之後
不管是自己回頭看、還是學姊/口試問起，都講得出完整的來龍去脈，不是只記得
一句「規則對真實世界 App 太寬鬆」。

---

## 零、地基概念——四種「`exported` 且無 permission 保護」的元件，性質完全不同

`NOTES_extractor_bugs_and_new_rule.md` 已經講過 `exported`/`permission`
這兩個屬性本身的意義。這份筆記要處理的問題更進一步：**就算 `exported`/
`permission` 兩個屬性都被正確解析出來了（不是解析錯誤），同樣是「exported
且無 permission」的元件，在安全意義上也完全不是同一回事**。真實世界資料
蒐集後，這種元件實際上可以分成四類：

| 類型 | 例子 | 攻擊者能塞什麼進去？ |
|---|---|---|
| ① 純 launcher 進入點 | 每個 App 的 `MainActivity`，intent-filter 只有 `MAIN`/`LAUNCHER` | 什麼都塞不了——這組 intent-filter 不帶任何資料欄位，系統只會用它來啟動 App 本身 |
| ② 第三方 SDK 官方要求的宣告 | Facebook SDK 的 `FBUnityDeepLinkingActivity`、Unity 的 `UnityPlayerActivity`、Firebase 的 `FirebaseInstanceIdService` | 開發者沒有選擇空間，是 SDK 官方整合文件要求的固定寫法 |
| ③ Android 平台機制強制要求 | App Widget 的 `APPWIDGET_CONFIGURE`/`_UPDATE`、`MediaRouteProviderService`、媒體按鍵 receiver | OS 層級要求 exported 才能正常運作（widget 設定、系統 MediaRouter 綁定），不是開發者的安全疏失 |
| ④ 真正自訂、可能有意義的進入點 | 接受自訂 URI scheme 的深連結 Activity（例如 `neuronation://`）、自訂 broadcast action 的 receiver | 攻擊者可以構造 Intent、傳入自訂資料，值得認真檢視 App 拿到這筆資料後怎麼處理 |

現行 `EXPORTED_UNPROTECTED_ACTIVITY`/`_RECEIVER` 與 `IPC_CONFUSED_DEPUTY`
規則，目前**完全不區分這四類**——只要「元件 exported 且無 permission」+
「App 持有任一危險權限」，不管是哪一類都會觸發。這份筆記要記錄的，就是
這件事被實際資料證實、以及接下來能怎麼處理。

---

## 一、問題是怎麼被發現的

### 1.1 觸發點：benign 類別的 `label=1` 比例高到不合理

38 筆真實世界資料裡，18 個 benign 樣本（MalDroid 2020 官方標記為良性的
App）在兩個 extractor bug 修復、資料清乾淨之後，**18 個裡有 18 個都被
標記 `label=1`（100%）**。這個數字本身就是一個訊號——如果良性 App 幾乎
全部被判定為高風險，代表判斷邏輯跟真實世界的落差可能比預期大。

### 1.2 第一步：系統性掃描，而非憑印象猜

在深入人工抽查之前，先寫了 `check_launcher_pattern.py` 系統性掃過全部
38 筆，檢驗「是不是規則系統性誤把純 launcher activity 當風險訊號」這個
初步假設。

**結果推翻了這個假設**：38 筆裡只有 9 筆（23.7%）唯一觸發原因是純
`MAIN`/`LAUNCHER` 進入點，其餘 29 筆（76.3%）含有非-launcher 的 exported
元件。如果只看這個數字就停下來，會誤以為「大部分是真的有風險的元件」，
但接下來的深度抽查證明事情比這複雜。

### 1.3 第二步：用 `audit_apk.py` 深度核對 7 筆

寫了 `audit_apk.py`，針對單一 APK 同時印出：完整權限清單、元件與
intent-filter 內容、規則引擎實際產生的 Finding（含 evidence）、原始
AndroidManifest.xml 可讀文字版。挑了三類樣本（第三方 SDK 主導、App 自身
非-launcher 進入點、banking 類別）各 2–3 筆，加一筆純 launcher 對照組，
共 7 筆，逐一核對 evidence 裡列出的元件到底是什麼性質。

---

## 二、逐案例深度解析

### 案例 1：`org.android.system`（banking）—— ✅ 規則判斷正確

唯一元件 `.SMSReceiver`，intent-filter 同時監聽 `SMS_RECEIVED` 與
`NEW_OUTGOING_CALL`，配合權限清單裡的 `READ_SMS`/`SEND_SMS`/`WRITE_SMS`/
`INTERNET`，package name 偽裝成系統名稱——這是第④類（真正自訂、有意義
的進入點），而且權限組合本身就是簡訊攔截/OTP 竊取的教科書手法。規則判斷
完全站得住腳。

### 案例 2：`net.marlove.mockgps`（benign，純 launcher 對照組）—— ❌ 誤判

`MainActivity` 只有純 `MAIN`/`LAUNCHER`，屬於第①類。但這是一款「模擬
GPS 定位」工具，`ACCESS_FINE_LOCATION` 是核心功能本身需要的權限。
`COMBO_LOCATION_EXFIL`（`ACCESS_FINE_LOCATION`+`INTERNET`）與
`IPC_CONFUSED_DEPUTY` 純粹因為「App 剛好持有定位權限」就觸發，跟這個
launcher activity 本身完全無關——攻擊者無法透過 `MAIN`/`LAUNCHER`
intent-filter 傳入任何可控資料。

### 案例 3：`com.hdgames.superbrosadventures`（benign，第三方 SDK）—— ❌ 誤判

被標記的 3 個 activity（`UnityPlayerActivity`、`FBUnityDeepLinkingActivity`、
`FBUnityAppLinkActivity`）與 1 個 provider（`FacebookContentProvider`，
`IPC_PROVIDER_REDELEGATION`，severity=critical）全部屬於第②類——Unity
引擎與 Facebook SDK 官方文件要求的標準宣告方式，開發者沒有自主決定的
空間。把 Facebook SDK 自己的設計決策算成這個 App 開發者的安全疏失，是
一種歸因層級的錯誤。

### 案例 4：`air.nn.mobile.app.main`（benign，第三方 SDK）—— ⚠️ 部分正確

這筆是最有意思的混合案例。`.AppEntry` 除了 `MAIN`/`LAUNCHER`，還額外
帶了 `ACTION_VIEW` + 自訂 scheme `neuronation://`——屬於第④類，是真正
有意義的訊號，值得標記。但同一個 `IPC_CONFUSED_DEPUTY` finding 的
evidence 裡，混入了 Amazon IAP、Adjust SDK、Firebase 的元件（第②類）
一起列為 `unprotected_activities`，稀釋了 `.AppEntry` 這個真正訊號的
辨識度——這也說明了「規則不分類直接打包計算」會讓真正該關注的案例被
淹沒在雜訊裡。

### 案例 5：`com.shoushou88.zhezhe99`（banking）—— ✅ 規則判斷正確

`SMSReceiver`+`PhoneListener`+`BootBroadcastReceiver`（含疑似 C2 回報
action `cn.gx3.notify`）+ 23 個危險權限（含 `MODIFY_PHONE_STATE`/
`RESTART_PACKAGES`/裝置管理員綁定）。多重訊號疊加，且都是第④類，銀行
木馬特徵完整，規則判斷正確。

### 案例 6：`com.sonos.acr`（benign，非-launcher）—— ❌ 誤判

被標記的元件：`APPWIDGET_CONFIGURE`/`_UPDATE`（widget 設定與更新）、
`MediaRouteProviderService`（Android MediaRouter API）、媒體按鍵
receiver——全部屬於第③類，是 Android 平台機制**強制要求** exported
才能運作的標準寫法。深連結 `sonos://` 另外還有 `autoVerify=true` 的
Android App Links 網域驗證，屬於實作得比較嚴謹的案例，規則反而沒有
把「有做網域驗證」這件事算進降低風險的考量。

### 案例 7：`com.reneph.passwordsafe`（benign，非-launcher）—— ❌ 誤判，全站最清楚的反例

只有 launcher（含 Samsung 多視窗支援分類，仍屬第①類）跟標準 widget
config（第③類）兩個元件被標記，權限清單裡完全沒有任何個資類危險權限。
`IPC_CONFUSED_DEPUTY` 純粹因為持有 `WRITE_EXTERNAL_STORAGE`（密碼管理
App 做備份匯出的合理用途）被列為「持有危險權限」而觸發。這是所有案例
裡，规则的語意落差表現得最極端的一個。

### 小結

7 筆中 2 筆（皆 banking）判斷正確，4 筆（皆 benign）誤判，1 筆部分正確。
兩個規則判斷正確的案例，共通點是**多重訊號疊加、且觸發元件全部屬於第④
類**；四個誤判案例，共通點是**觸發元件屬於第①②③類，且往往只靠單一
`IPC_CONFUSED_DEPUTY` finding 就把整個 App 判定為高風險**。

---

## 三、為什麼這不是一個「bug」，而是規則的語意落差

`NOTES_extractor_bugs_and_new_rule.md` 記錄的三個 bug，共通點是「manifest
裡明明有正確答案，程式碼卻沒讀到或讀錯了」——例如 `exported="false"` 被
覆寫成 `true`，這是可以用「對照 manifest 原始內容」直接證明對錯的事。

這次的狀況不一樣：**`audit_apk.py` 印出的 manifest 原始內容，跟解析出來
的 `exported`/`permission` 完全一致，沒有任何解析錯誤**。問題出在更上一層
——`IPC_CONFUSED_DEPUTY`/`EXPORTED_UNPROTECTED_*` 這幾條規則，判斷「這個
exported 元件有沒有意義」時，用的條件只有「exported + 無 permission +
App 持有任一危險權限」，沒有進一步問「這個元件的 intent-filter 到底能不
能接收攻擊者可控的資料」。manifest 事實的擷取是對的，**語意判斷的粒度
不夠細**，這是實作邏輯設計上的落差，不是解析錯誤。

這個差異很重要：如果是像 Bug 1–3 那種解析錯誤，答案是唯一的（修對就是
唯一正確答案）；但這次是規則設計的取捨問題，存在不只一種合理的處理方式
——這正是路線 A/B 需要討論、而不是直接判定「哪個對哪個錯」的原因。

---

## 四、兩條路線，以及各自預期會發生什麼事

### 路線 A：修規則，讓 `IPC_CONFUSED_DEPUTY` 區分四種元件性質

**具體做法**：在現有觸發條件之外，額外要求以下兩者至少符合一項：
1. exported 元件的 intent-filter 含有非 `MAIN`/`LAUNCHER` 的 action
   （排除第①類）
2. 元件不屬於已知的「平台機制強制 exported」清單（`android.appwidget.
   action.APPWIDGET_CONFIGURE`/`_UPDATE`、`android.media.
   MediaRouteProviderService` 等，排除第③類）
第②類（第三方 SDK）處理起來難度較高，因為沒有一份「所有第三方 SDK 元件
清單」可以直接查——可能需要用 package/class 名稱前綴（`com.google.
android.gms.*`/`com.facebook.*`/`com.unity3d.*` 等）做粗略比對，這部分
的完整度沒辦法做到 100%，只能處理常見的幾個大型 SDK。

**預期結果（推論，尚未實作驗證）**：套用這次抽查的 7 筆案例回推，案例
2、3、6、7（4 筆誤判）預期會不再觸發 `IPC_CONFUSED_DEPUTY`，`label`
從 1 變回 0；案例 1、5（banking，真正有風險）預期維持觸發不變，因為
它們的元件本來就屬於第④類。案例 4（部分正確）預期只留下 `.AppEntry`
這個真正有意義的訊號，Amazon/Adjust/Firebase 那幾個第②類元件會被排除。
如果這個推論成立，18 個 benign 樣本裡 `label=1` 的比例應該會從 100%
大幅下降，`filter_row` 訓練資料的 label 分布也會更接近原本規格文件
「正樣本比例低於 50%」的預期。

**代價**：需要修改 `privilege_rules.py` 的判斷邏輯、補充平台機制清單、
可能需要補幾個新的測試案例（例如一個「純 launcher + 持有危險權限」的
toy APK 案例，確保修改後這種組合不再誤觸發），工作量還沒有精確估計，
且屬於規則邏輯調整，不是威脅分類定義變動，理論上不需要學姊事先核准。

### 路線 B：維持現狀，把這次發現寫進誠實揭露

**具體做法**：不修改任何規則程式碼，把本篇筆記與 `STATUS_2026-07-16.md`
第 2 節的完整發現，寫進論文或報告的「已知限制」段落，說明現行規則對
真實世界 App（尤其含第三方 SDK 與平台標準機制）的元件複雜度過於敏感，
這是靜態分析工具處理真實世界資料時常見的限制，並非本專案獨有的缺陷。

**預期結果**：不改變任何現有的 `ground_truth.csv`/訓練結果，`filter_row`
模型會如實地在這種標籤雜訊下訓練（`exported`/`protected` 兩個特徵本來就
讓 label 100% 可預測，這批誤判不會影響 `filter_row` 訓練結果本身，只會
讓「label=1 對應真實風險」這個語意打折扣）。這條路線幾乎零成本，但論文
裡「真實世界資料驗證」這部分的說服力會比修過規則弱一些——需要花更多
篇幅解釋「為什麼 benign 樣本 label=1 比例這麼高，但這不代表規則失效」。

**代價**：如果之後有人（口試委員、學姊）質疑「你們的規則對真實世界 App
準確率是不是很差」，需要能清楚拿出這份筆記跟 7 筆案例逐一解釋清楚，
不能只回一句「這是已知限制」帶過。

### 目前的暫定考量

`STATUS_2026-07-16.md` 記錄的暫定想法是：時程壓力下，路線 B 成本趨近於
零，路線 A 有實質價值但可以延後到 `filter_row` 訓練完成、時程仍有餘裕時
再處理——**這只是暫定考量，不是最終決定**，最終選哪一條、或是否要先做
路線 A 的簡化版（例如只排除第①類純 launcher，不處理第②③類），留待
之後正式討論。

---

## 五、時間線總覽

```
07-15  真實世界資料蒐集，修復 cp950 編碼與元件名稱解析兩個 extractor bug
       （詳見 STATUS_2026-07-15.md，與本筆記主題不同，不重複展開）
       38 筆真實世界資料蒐集完成，發現 benign 類別 label=1 比例異常偏高

07-16  check_launcher_pattern.py 系統性掃描：純 launcher 假設只解釋 23.7%，
       推翻「規則只是誤判 launcher」這個過於簡化的假設
       audit_apk.py 深度核對 7 筆，拆解出四類 exported 元件性質
       確認這不是解析錯誤（manifest 事實擷取皆正確），是規則語意粒度問題
       記錄路線 A（修規則）/路線 B（誠實揭露）兩個選項，暫不拍板
       同日完成 APK 層級切分（含 stratified split 調整）與 filter_row
       Task 6 MVP 訓練管線（另詳 STATUS_2026-07-16.md 第 5 節）
```

這份筆記記錄的問題，跟 `NOTES_extractor_bugs_and_new_rule.md` 的三個
bug 性質不同——那三個是「答案唯一、修對就好」的解析錯誤，這次是「存在
不只一種合理處理方式」的規則設計取捨，這正是路線 A/B 需要留到之後正式
討論、而不是當下直接動手改的原因。
