# APK Analysis Platform

本專案為 APK 安全分析平台原型，包含：

- `apk-platform`：FastAPI backend，負責上傳 APK、建立 request.json、呼叫分析模組、回傳 report.json
- `AI-model`：AI / rule-based analysis engine，負責讀取 request.json 並輸出 report.json

---

## 專案結構

```text
apk-analysis-platform
│
├─ apk-platform
│   ├─ apps
│   │   └─ api
│   │       ├─ main.py
│   │       └─ db.py
│   ├─ metadata
│   │   ├─ requests
│   │   ├─ results
│   │   └─ artifacts
│   └─ storage
│       └─ objects
│           └─ apks
│
├─ AI-model
│   ├─ app
│   │   ├─ __init__.py
│   │   └─ main.py
│   └─ .venv
│
└─ README.md
