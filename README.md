# APK Analysis Platform

本專案為 APK 安全分析平台原型，包含：

- `apk-platform`：FastAPI backend，負責上傳 APK、建立 request.json、呼叫分析模組、回傳 report.json
- `AI-model`：AI / rule-based analysis engine，負責讀取 request.json 並輸出 report.json

---

# 專案結構

```
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
│   └─ app
│       ├─ __init__.py
│       └─ main.py
│
├─ setup.bat
├─ run.bat
└─ README.md
```

---

# 環境需求

需要安裝：

- Python 3.10+
- Git

確認版本：

```
python --version
git --version
```

---

# 安裝專案

## 1 Clone repository

```
git clone https://github.com/Lululu525/apk-analysis-platform.git
```

```
cd apk-analysis-platform
```

---

## 2 建立環境

執行：

```
setup.bat
```

這個腳本會自動：

- 建立 Python virtual environment
- 安裝 FastAPI
- 安裝 uvicorn
- 安裝必要套件

---

## 3 啟動系統

執行：

```
run.bat
```

成功後會看到：

```
Uvicorn running on http://127.0.0.1:8000
```

---

# API 測試

打開瀏覽器：

```
http://127.0.0.1:8000/docs
```

會看到 FastAPI Swagger UI。

---

# 測試流程

## 1 Upload APK

```
POST /v1/samples/upload
```

上傳 APK 檔案。

會回傳：

```
sample_id
```

---

## 2 執行分析

```
POST /v1/samples/{sample_id}/run-analysis
```

或先測試 mock：

```
POST /v1/samples/{sample_id}/run-mock
```

---

## 3 查看分析結果

```
GET /v1/samples/{sample_id}/result
```

會回傳：

- risk_score
- findings
- permissions
- suspicious API usage

---

# 分析流程

系統流程如下：

```
APK Upload
     │
     ▼
Create request.json
     │
     ▼
AI-model analysis
     │
     ▼
Generate report.json
     │
     ▼
Return results via API
```

---

# 目前功能

目前 prototype 支援：

- APK 上傳
- request.json 生成
- rule-based analysis
- suspicious API detection
- report.json 生成
- FastAPI API interface

---

# 未來擴充

未來可加入：

- 靜態分析 (jadx / androguard)
- ML risk scoring
- permission graph analysis
- dynamic sandbox analysis
- Web UI dashboard# APK Analysis Platform

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
