@echo off
echo ================================
echo APK Analysis Platform Setup
echo ================================

echo Creating Python virtual environment...
python -m venv .venv

echo Activating virtual environment...
call .venv\Scripts\activate

echo Installing backend dependencies...
pip install fastapi uvicorn pydantic python-multipart

echo Installing AI-model dependencies...
pip install androguard networkx scikit-learn

echo Setup complete!
pause