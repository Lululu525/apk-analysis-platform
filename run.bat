@echo off
echo ================================
echo Starting APK Analysis Platform
echo ================================

if not exist .venv (
    echo ERROR: Virtual environment not found.
    echo Please run setup.bat first.
    pause
    exit
)

call .venv\Scripts\activate

cd apk-platform

echo Starting FastAPI server...
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000

pause
