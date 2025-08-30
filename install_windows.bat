@echo off
REM GrepAPK Windows Installation Script
REM This script installs GrepAPK on Windows systems

echo.
echo ========================================
echo    GrepAPK Windows Installer
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python version: %PYTHON_VERSION%

REM Check if pip is available
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available
    echo Please reinstall Python with pip option checked
    pause
    exit /b 1
)

echo.
echo Installing GrepAPK...
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install build tools
echo Installing build tools...
python -m pip install --upgrade setuptools wheel

REM Install GrepAPK
echo Installing GrepAPK...
python -m pip install -e .

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Installation failed!
    echo Please check the error messages above
    echo.
    echo Common solutions:
    echo 1. Run this script as Administrator
    echo 2. Install Visual Studio Build Tools
    echo 3. Use: pip install --only-binary=all -e .
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Installation Complete!
echo ========================================
echo.
echo GrepAPK has been installed successfully!
echo.
echo You can now use GrepAPK with:
echo   python grepapk.py --help
echo.
echo Or run the test suite with:
echo   python test_installation.py
echo.
pause
