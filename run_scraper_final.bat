@echo off
setlocal ENABLEDELAYEDEXPANSION

echo 🚀 Ultimate Email Scraper - Final Version
echo ==========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Check if input file exists
if not exist "websites_test.csv" (
    echo ❌ Input file 'websites_test.csv' not found
    echo Please create a CSV file with URLs to scrape
    pause
    exit /b 1
)

REM Install requirements if needed
echo 📦 Checking requirements...
pip install --break-system-packages -r requirements_final.txt >nul 2>&1
pip install --break-system-packages brotli >nul 2>&1

REM Run the scraper
echo 🔍 Starting scraper...
echo.

python email_scraper_final.py --input websites_test.csv --output emails_found.csv --concurrent 8 --per-domain 3 --delay-min 1.5 --delay-max 3.0 --timeout 25 --retries 2

echo.
echo ✅ Scraping completed!
echo 📊 Check 'emails_found.csv' for results
echo.
pause