# APK Analysis Platform

APK Analysis Platform 是一個 **Android APK 安全分析平台原型
(Prototype)**。

系統分為兩個主要模組：

-   **apk-platform** FastAPI backend，負責：
    -   上傳 APK
    -   建立 request.json
    -   呼叫 AI 分析模組
    -   回傳 report.json
-   **AI-model** AI / rule-based analysis engine，負責：
    -   讀取 request.json
    -   分析 APK
    -   產生 report.json

------------------------------------------------------------------------

# Project Structure

```
apk-analysis-platform
│
├─ apk-platform
│   ├─ apps
│   │   └─ api
│   │       ├─ main.py
│   │       └─ db.py
│   │
│   ├─ metadata
│   │   ├─ requests
│   │   ├─ results
│   │   └─ artifacts
│   │
│   └─ storage
│       └─ objects
│           └─ apks
│
├─ AI-model
│   ├─ app
│   │   ├─ __init__.py
│   │   ├─ main.py
│   │   ├─ pipeline.py
│   │   ├─ schemas.py
│   │   ├─ schema_validation.py
│   │   │
│   │   ├─ detectors
│   │   │   ├─ __init__.py
│   │   │   └─ rules.py
│   │   │
│   │   └─ report
│   │       ├─ __init__.py
│   │       └─ builder.py
│   │
│   ├─ input
│   │   └─ request.json
│   ├─ output
│   │   └─ report.json
│   ├─ artifacts
│   ├─ models
│   ├─ tests
│   ├─ requirements.txt
│   └─ README.md
│
├─ .gitignore
├─ requirements.txt
├─ setup.bat
├─ run.bat
└─ README.md
```
------------------------------------------------------------------------

# Requirements

需要安裝：

-   Python 3.10+
-   Git

確認版本：

python --version git --version

------------------------------------------------------------------------

# Installation

## 1 Clone Repository

git clone https://github.com/Lululu525/apk-analysis-platform.git

cd apk-analysis-platform

------------------------------------------------------------------------

## 2 Setup Environment

執行：

setup.bat

此腳本會自動：

-   建立 Python virtual environment
-   安裝 FastAPI
-   安裝 uvicorn
-   安裝必要套件

------------------------------------------------------------------------

# Start Backend

run.bat

成功後會看到：

Uvicorn running on http://127.0.0.1:8000

------------------------------------------------------------------------

# API Testing

打開瀏覽器：

http://127.0.0.1:8000/docs

FastAPI 會自動生成 Swagger UI。

------------------------------------------------------------------------

# Testing Workflow

1 Upload APK

POST /v1/samples/upload

會回傳 sample_id

2 Run Analysis

POST /v1/samples/{sample_id}/run-analysis

或

POST /v1/samples/{sample_id}/run-mock

3 Get Result

GET /v1/samples/{sample_id}/result

回傳內容包含：

-   risk_score
-   findings
-   permissions
-   suspicious API usage

------------------------------------------------------------------------

# AI-model CLI Testing

cd AI-model

python -m app.main --in
../apk-platform/metadata/requests/`<job_id>`{=html}.request.json --out
output/report.json --artifacts artifacts

成功會顯示：

\[OK\] report written: output/report.json status=success risk_score=XX
findings=X

------------------------------------------------------------------------

# Analysis Pipeline

APK Upload │ Create request.json │ AI-model analysis │ Generate
report.json │ Return results via API

------------------------------------------------------------------------

# Current Features

-   APK upload
-   request.json generation
-   rule-based analysis
-   suspicious API detection
-   report.json generation
-   FastAPI API interface

------------------------------------------------------------------------

# Future Work

-   靜態分析 (jadx / androguard)
-   ML risk scoring
-   permission graph analysis
-   dynamic sandbox analysis
-   Web UI dashboard
