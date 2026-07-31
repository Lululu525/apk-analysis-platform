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

## 六、下次會議前應完成事項對照

| 會議要求 | 本文件涵蓋 |
|---|---|
| 研究兩個新資料集的內容與檔案結構 | 第一節 |
| 確認資料是否能正常下載、解壓縮與分析 | 第一節（下載/解壓已完成）；分析可行性以 2 支樣本實測驗證 |
| 列出建立約 3,590 筆可用資料所需的完整流程 | 第三節 |
| 估算每個步驟所需時間 | 第四節 |
| 提出兩人分工方式 | 第五節 |
| 提供目前的 Feature CSV | 沿用 `dataset/labels/ground_truth_with_split.csv`（另行傳送） |
| 說明現有 Label 的產生邏輯 | 第三節第 7 步（`exported ∧ not protected`，詳見 `build_training_data.py`） |
| 暫時不必正式完成所有資料提取與模型訓練 | 本文件僅為計畫與估算，未執行批次抽樣/分析 |
