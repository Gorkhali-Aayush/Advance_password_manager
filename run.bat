@echo off
title Advanced Password Manager
cd /d "%~dp0"
echo Starting Advanced Password Manager...
echo.

:: Try to find Python in the virtual environment
if exist "..\..\.venv\Scripts\python.exe" (
    set PYTHON_PATH=..\..\.venv\Scripts\python.exe
) else if exist "..\.venv\Scripts\python.exe" (
    set PYTHON_PATH=..\.venv\Scripts\python.exe
) else if exist ".venv\Scripts\python.exe" (
    set PYTHON_PATH=.venv\Scripts\python.exe
) else (
    set PYTHON_PATH=python
)

:: Kill any existing Python processes that might be holding locks
taskkill /f /im python.exe >nul 2>&1
timeout /t 1 /nobreak >nul

:: Remove any leftover lock files
del /f /q "*.lock" >nul 2>&1

:: Run the application
"%PYTHON_PATH%" -c "import sys; sys.path.insert(0, 'src'); from main import main; main()"

:: If there was an error, pause to see it
if errorlevel 1 (
    echo.
    echo An error occurred. Press any key to exit...
    pause >nul
)
