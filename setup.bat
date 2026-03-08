@echo off
echo ================================
echo APK Analysis Platform Setup
echo ================================

cd apk-platform

echo Creating Python virtual environment...
python -m venv .venv

echo Activating virtual environment...
call .venv\Scripts\activate

echo Installing backend dependencies...
pip install fastapi uvicorn pydantic python-multipart

cd ..

echo Installing AI-model dependencies...
pip install androguard

echo ================================
echo Setup complete!
echo ================================

pause
