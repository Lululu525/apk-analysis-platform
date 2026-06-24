# Dataset

本資料夾為 NSTC 大專生研究計畫（越權行為分析）的訓練資料集。

## 資料夾說明

| 資料夾 | 說明 |
|---|---|
| `toy_apks/` | 手工設計的 Toy APK，覆蓋 5 種漏洞場景（A–E） |
| `opensource_apks/` | 從 GitHub 開源 Android 專案 build 出的 APK |
| `public_apks/` | 從 F-Droid / AndroZoo 下載的公開 APK |
| `labels/ground_truth.csv` | 所有 APK 的 ground truth 標籤表 |

## 標籤說明

- `label = 1`：有越權風險（手動標記或 rule engine 確認）
- `label = 0`：正常（對照組）
- `label_source = manual`：手工標記的 ground truth
- `label_source = rule_weak_label`：由 `privilege_rules.py` 生成的弱標籤

## 場景對照

| 場景 | 偵測目標 |
|---|---|
| A | OVER_PRIVILEGE（過度宣告危險權限） |
| B | IPC_SERVICE_HIJACK（未保護的 exported Service） |
| C | IPC_CONFUSED_DEPUTY（Intent Spoofing） |
| D | IPC_BROADCAST_THEFT（未保護的敏感廣播接收器） |
| E | IPC_PROVIDER_REDELEGATION（未保護的 ContentProvider） |

## APK 總數上限

100–150 個 APK（4 個月內可完成標記的現實限制）。

## 注意事項

- `toy_apk_sources/` 資料夾存放 Android Studio 原始碼，不進 git
- 只有 build 出來的 `.apk` 檔案進 git（存放在本資料夾下）
