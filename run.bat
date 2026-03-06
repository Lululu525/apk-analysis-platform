@echo off
echo Starting APK Analysis Platform...

cd apk-platform

call .venv\Scripts\activate

python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000

pause