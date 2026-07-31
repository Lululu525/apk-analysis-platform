# 資料集擴充計畫——流程清單與工作量估算

這份文件是 2026-07-31 週會（`APK 風險分析模型討論紀錄`）指派的「任務一：研究資料集整理方式」
與「任務二：評估工作量與分工」的產出，供 2026-08-04（週二 17:40）下次會議使用。

**範圍聲明**：本文件只處理這次會議指派的任務（資料集擴充可行性與工作量估算）。
`docs/PLAN_phase2.md` Task 9–13（標籤洩漏修正等）本週暫緩，不在本文件範圍內；本文件的
「建立 Label」步驟延用現有弱規則，不引入新的標籤設計。

---

## 一、資料來源與現況

- 來源：CIC MalDroid-2020，<https://cicresearch.ca/CICDataset/MalDroid-2020/>
- 已下載並解壓至本機 `C:\Users\s1002\Downloads\MalDroid-2020\APKs`：

  | 類別 | 檔案數 | 大小 | 平均大小 |
  |---|---:|---:|---:|
  | Benign | 4,039 | 53 GB | ~13 MB/apk |
  | Banking | 2,308 | 3.5 GB | ~1.5 MB/apk |
  | SMS | 1,019 | 650 MB | ~0.65 MB/apk |

- 目前 `dataset/real_world_apks/` 已使用其中 38 筆（banking 10、benign 18、sms 10），紀錄在
  `dataset/labels/ground_truth_with_split.csv` 的 `apk_sha256` 欄位。

## 二、抽樣目標與規則

- 目標：Benign ~1,795 筆、Malware（Banking + SMS 合計）~1,795 筆，共 ~3,590 筆
  （會議紀錄原文「各類別約 1,795 筆」已更正為「Benign vs Malware 兩大類各 ~1,795」，
  不是 SMS/Banking 各 1,795）。
- 抽樣方法：**隨機抽樣**，不做分層抽樣（不依官方 5 大類/家族比例）。
  - CIC 另提供 `CSVs/CSV.zip` 內 595MB 的 `feature_vectors_static.csv`（含官方分類/家族欄位），
    可用於之後做分層抽樣或核對，這次不展開使用。
- 去重：抽樣前**排除**已出現在 `ground_truth_with_split.csv` `apk_sha256` 欄位的 38 筆，
  避免新舊資料集重複。

## 三、完整流程清單

| # | 步驟 | 說明 |
|---|---|---|
| 1 | 下載與解壓縮 | 已完成（MalDroid-2020 全量已在本機） |
| 2 | 隨機抽樣 | Benign 池 4,039 → 抽 ~1,795；Banking+SMS 池 3,327 → 抽 ~1,795；排除既有 38 筆 sha256 |
| 3 | APK 完整性檢查 | 確認可被 androguard 正常開啟解析，剔除損壞檔案 |
| 4 | 去除重複 | 依 sha256 去重（含跨類別重複） |
| 5 | 執行靜態分析 | 呼叫現有 pipeline（`app/extractors/androguard_analyzer.py` 等）逐筆分析 |
| 6 | 特徵擷取 | Manifest／Component／Intent Filter／Permission／敏感 API |
| 7 | 建立 Label | 延用現有規則 `exported ∧ not protected`，與現有 68 筆一致；**額外**新增一欄
  MalDroid 官方類別（來源資料夾名稱：Benign/Banking/SMS），供之後 Task 9 MIL 相關工作使用，
  這次不作為 label 輸入 |
| 8 | 轉換成 CSV | 產出格式比照現有 `filter_row` / `ground_truth_with_split.csv` |
| 9 | 資料清理與格式統一 | 型態、缺值、命名一致性檢查 |

## 四、工作量粗估

**方法**：抽樣 (10-20 apk) 純執行成本低，本週不做批次實測；改為由助理實際跑 2 支具代表性
APK（1 支 SMS、1 支 Benign）量測核心分析步驟（`analyze_apk` + `findings_from_analysis` +
`check_combinations`）耗時，外推到目標量。此為粗估，未涵蓋 CSV 轉換/清理等末端步驟
（成本低，預期影響不大）。

| 樣本 | 檔案大小 | 核心分析耗時 |
|---|---:|---:|
| SMS (`00050ee1...`) | 0.71 MB | 0.21 s |
| Benign (`00070891...`) | 4.94 MB | 4.69 s |

外推（假設耗時與檔案大小大致線性關係，僅供排程參考，非精確值）：

| 類別 | 目標筆數 | 平均檔案大小 | 粗估總運算時間 |
|---|---:|---:|---:|
| Malware（Banking+SMS） | ~1,795 | ~1.2 MB | ~10–15 分鐘 |
| Benign | ~1,795 | ~13 MB | ~5–7 小時 |

**注意**：Benign 平均檔案遠大於 malware（真實上架 App vs 惡意樣本的複雜度差異），且大型 APK
變異度高，實際耗時可能高於此估計。抽樣、去重、CSV 轉換等步驟耗時遠低於靜態分析本身，
未單獨估算。

## 五、分工

維持「各自負責一批資料」：一人負責 Benign（~1,795 筆，運算時間較長）、
一人負責 Banking+SMS（~1,795 筆，運算時間較短）。雙方運算耗時不對等（Benign 側約
5–7 小時 vs Malware 側約 10–15 分鐘），但因分析可背景執行、不佔用人力時間，
判斷可接受，維持原分工方式。

## 六、需提供的資料（給学姊看的欄位/Label 說明）

對應會議紀錄第十一節。以下內容全部取自現有程式碼與 `dataset/training/filter_rows.jsonl` 的
真實資料，不是重新設計。

### 6.1 欄位名稱與資料型態

`filter_row`（一個元件一列，是目前唯一有實際訓練用途的 row type；`intent_row`/`resolution_row`
目前皆無獨立訓練價值，見 `app/ml/feature_schema.json`）：

| 欄位 | 型態 | 說明 |
|---|---|---|
| `sample_id` | string | APK 識別碼（僅識別用） |
| `package_name` | string | 套件名稱（僅識別用） |
| `component_name` | string | 元件類別名稱（僅識別用） |
| `component_type` | string（類別型） | `activity` / `service` / `receiver` / `provider` |
| `actions` | string list | Intent-Filter 的 action 原始清單（不直接進模型，見 6.4） |
| `categories` | string list | Intent-Filter 的 category 原始清單（不直接進模型） |
| `data_types` | string list | Intent-Filter 的 data type 原始清單（不直接進模型） |
| `data_schemes` | string list | Intent-Filter 的自訂 URI scheme 原始清單（不進模型，見 6.4 原因） |
| `permission` | string 或 null（類別型） | 元件要求的 permission（見 6.3） |
| `exported` | boolean | 元件是否可被外部存取（見 6.3） |
| `protected` | boolean | 元件是否有 permission 保護（見 6.3） |
| `has_action_*` / `has_category_*` / `has_data_type_*` | boolean（multi-hot） | 由 `actions`/`categories`/`data_types` 動態展開的 one-hot 欄位，欄位全集在 `encoder.joblib` 訓練時才固定 |
| `label` | int（0/1） | 訓練標籤，見 6.2 |
| `label_source` | string | 目前只有 `rule_weak_label`（toy APK 人工標記未真正接入，見 `docs/codex意見.md`） |
| `split` | string | `train` / `val` / `test`，以 APK 為單位切分 |

### 6.2 Label 定義

```python
label = 1 if (exported is True and protected is False) else 0
```

出處：`build_training_data.py:61`（`compute_label()`）。與現有 68 筆真實/toy 資料使用同一條公式，
這次擴充的新資料延續此定義，不改動（詳見本文件第三節第 7 步、`docs/adr/0002-*`）。

### 6.3 `exported` 與 `protected` 的計算方式

**`exported`**（`app/extractors/androguard_analyzer.py`）：
- Activity / Service / Receiver：Manifest 顯式宣告 `android:exported` 時直接採用該值；未顯式宣告時，
  依 Android 隱式規則推斷——**只要有任何 intent-filter 就視為 `exported=true`**。
- Provider：只採用顯式 `android:exported` 屬性，未宣告時預設 `false`（不套用 intent-filter 推斷規則）。

**`protected`**（`app/tools/parse_manifest.py:_component_permission`）：
- Provider：**必須同時有 `readPermission` 與 `writePermission`** 才算 `protected=true`；只設定其中一個
  視為未受保護（`protected=false`）。這是一個容易被忽略的細節，值得跟学姊特別說明。
- 其他元件：只要 `android:permission`（或對應的 required-permission 清單第一項）非空，即
  `protected=true`。

### 6.4 哪些欄位實際輸入模型

依 `app/ml/feature_schema.json`（`filter_row` encoder 規格）：

- **類別型輸入**：`component_type`、`permission`
- **布林輸入**：`exported`、`protected`
- **Multi-hot 輸入**：`has_action_*`、`has_category_*`、`has_data_type_*`（前綴動態展開）
- **明確排除、不進模型**：`data_schemes`（自訂 URI scheme 在小樣本上維度太高、缺乏鑑別力，決策記錄於
  2026-07-18，見 `feature_schema.json` notes）
- **僅作識別/輔助，不進模型**：`sample_id`、`package_name`、`component_name`、`row_type`、
  `label_source`、`split`
- **原始 `actions`/`categories`/`data_types` list 本身不直接進模型**，而是先展開成上面的 multi-hot
  欄位才進模型

### 6.5 實際資料範例（來自 `dataset/training/filter_rows.jsonl`）

```json
{"sample_id": "com.toyapk.scenario_a.case0__1.0__", "row_type": "filter",
 "features": {"component_type": "activity", "actions": ["android.intent.action.MAIN"],
 "categories": ["android.intent.category.LAUNCHER"], "data_types": [], "data_schemes": [],
 "permission": null, "exported": true, "protected": false,
 "has_action_android_intent_action_main": true,
 "has_category_android_intent_category_launcher": true},
 "label": 1, "label_source": "rule_weak_label", "split": "train"}

{"sample_id": "com.toyapk.scenario_a.case0__1.0__", "row_type": "filter",
 "features": {"component_type": "receiver",
 "actions": ["androidx.profileinstaller.action.INSTALL_PROFILE", "..."],
 "categories": [], "data_types": [], "data_schemes": [],
 "permission": "android.permission.DUMP", "exported": true, "protected": true,
 "has_action_androidx_profileinstaller_action_install_profile": true, "...": "..."},
 "label": 0, "label_source": "rule_weak_label", "split": "train"}
```

第一筆是純 launcher activity（無 permission 保護、`exported=true` → label 1）；第二筆是有
`DUMP` permission 保護的 receiver（`protected=true` → label 0），兩筆剛好對照出 label 公式怎麼運作。

## 七、下次會議前應完成事項對照

| 會議要求 | 本文件涵蓋 |
|---|---|
| 研究兩個新資料集的內容與檔案結構 | 第一節 |
| 確認資料是否能正常下載、解壓縮與分析 | 第一節（下載/解壓已完成）；分析可行性以 2 支樣本實測驗證 |
| 列出建立約 3,590 筆可用資料所需的完整流程 | 第三節 |
| 估算每個步驟所需時間 | 第四節 |
| 提出兩人分工方式 | 第五節 |
| 提供目前的 Feature CSV | 第六節（欄位/型態/範例），實際檔案沿用 `dataset/labels/ground_truth_with_split.csv` + `dataset/training/filter_rows.jsonl` |
| 說明現有 Label 的產生邏輯 | 第六節 6.2/6.3 |
| 暫時不必正式完成所有資料提取與模型訓練 | 本文件僅為計畫與估算，未執行批次抽樣/分析 |
