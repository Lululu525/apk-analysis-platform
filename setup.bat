@echo off
echo ================================
echo APK Analysis Platform Setup
echo ================================

cd apk-platform

echo Creating Python virtual environment...
python -m venv .venv

echo Activating virtual environment...
call .venv\Scripts\activate

echo Installing dependencies...
pip install fastapi uvicorn pydantic python-multipart

echo Setup complete!
pause