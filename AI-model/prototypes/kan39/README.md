# KAN-39 敏感 API 掃描原型

此目錄保留組員提供的 KAN-39 參考實作，避免未整合程式碼直接出現在
`app/extractors/`，使其被誤認為 production extractor。

## 目前狀態

- 原始檔名：`sensitive_api_detector.py`
- 原始位置：`app/extractors/sensitive_api_detector.py`（未追蹤檔案）
- 整理前 Git blob SHA：`c0eef45436af886e9001eaf02f63049d930e75c8`
- 已通過：Python 語法編譯檢查（`py_compile`）
- 尚未完成：pipeline import、Androguard 相容性驗證、Finding schema 驗證、單元測試與整合測試

## 使用限制

這份檔案僅供後續整合時參考。它仍保留原先位於 `app/extractors/` 時使用的
relative import，因此不應直接從 `prototypes/` 當成可執行模組匯入。

正式整合時，應依目前的 `androguard_analyzer.py`、`schemas.py` 與
authorization component-path evidence schema 重新檢查介面，並以測試證明結果
可重現；在此之前，不得將 KAN-39 標記為正式完成。
