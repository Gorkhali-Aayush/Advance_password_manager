@echo off
REM Advanced Password Manager - Windows Launcher
REM
REM This script launches the Advanced Password Manager application on Windows.
REM
REM Usage:
REM     run.bat              - Run application
REM     run.bat --debug      - Run in debug mode

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0

REM Check if virtual environment exists
if exist "!SCRIPT_DIR!.venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call "!SCRIPT_DIR!.venv\Scripts\activate.bat"
) else (
    echo Warning: Virtual environment not found
    echo Please create it with: python -m venv .venv
    echo Then install dependencies with: pip install -r requirements.txt
    echo.
)

REM Run the application
echo.
echo Starting Advanced Password Manager...
echo.

python "!SCRIPT_DIR!src\main.py" %*

REM Check if application exited with error
if %errorlevel% neq 0 (
    echo.
    echo Application exited with error code %errorlevel%
    pause
)

endlocal
