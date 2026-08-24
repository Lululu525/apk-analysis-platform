---
status: accepted
---

# 用 KAN-39 敏感 API 掃描取代曝露面公式，越權 label 改為逐元件計算

**Context**：`filter_row` 目前的訓練 label 只用 `exported`/`protected` 兩個 manifest 布林值算出（`label = exported and not protected`），而這兩個欄位同時是 encoder 的輸入特徵，造成結構性標籤洩漏（模型 F1 恆為 1.0）。企劃書對「越權」的定義是「權限是否超出實際功能需求」，光看 exported/protected 只能回答「元件是否可被外部觸發」，答不出「功能需求」這一半。

**Decision**：採用組員提供、目前尚未整合進 repo 的 KAN-39 `sensitive_api_detector.py`，取代 `androguard_analyzer.py` 現有的 `_find_sensitive_apis()`/`SENSITIVE_API_PATTERNS`（後者只回傳字串、沒有 caller 資訊，無法逐元件歸因）。`is_used` 與 `filter_row` 的新 label 改為**逐元件**計算：比對元件的 class 是否曾作為 caller，呼叫過該元件所持有權限對應的敏感 API 群組；另外新增 permission → group_id 對照表，把 manifest 權限字串接到 KAN-39 的 API 群組分類。

**Why**：KAN-39 模組雖然是外部依賴、沒有交付時間表，但程式碼已經拿到手上，而且已經對齊本專案 `app/schemas.py` 的 `Finding`/`Severity` 格式，比起等待組員整合或另建一套簡化版更省時間，也更完整（有 caller_class，能做到逐元件判定）。逐元件計算是因為 `filter_row` 本身的標籤粒度就是逐元件，只算整支 App 一個值無法回饋到個別元件的 label。

## Considered Options

- **等組員把 KAN-39 完整整合進 repo 才動工**——排程完全依賴外部進度，3 週的 Task 9 時程可能被卡死，否決。
- **只用 repo 內既有的 `_find_sensitive_apis()` 簡化版接上 `is_used`**——沒有 caller 資訊，無法做到逐元件判定，只能算整支 App 一個籠統值，否決。
- **不做敏感 API 偵測，`is_used` 恆為 True 的現況直接記錄為已知限制，不動程式碼**——會讓「越權」的定義停留在純曝露面分析（exported/unprotected），脫離企劃書「權限超出實際功能需求」的研究主張，否決。
