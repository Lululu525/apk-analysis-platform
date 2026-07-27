@echo off
echo ================================
echo APK Analysis Platform Setup
echo ================================

echo Creating Python virtual environment...
python -m venv .venv

echo Activating virtual environment...
call .venv\Scripts\activate

echo Installing project dependencies from requirements.txt...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo Setup complete!
pause
