#!/usr/bin/env python3
"""
Simple launcher script for the Ultimate Email Scraper
"""

import subprocess
import sys
import os
from pathlib import Path

def check_requirements():
    """Check if required packages are installed"""
    try:
        import aiohttp
        import bs4
        import tldextract
        return True
    except ImportError:
        return False

def install_requirements():
    """Install required packages"""
    print("📦 Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements_final.txt"])
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def main():
    """Main launcher function"""
    print("🚀 Ultimate Email Scraper - Final Version")
    print("=" * 50)
    
    # Check if requirements are installed
    if not check_requirements():
        print("📦 Installing requirements...")
        if not install_requirements():
            print("❌ Failed to install requirements. Please install manually:")
            print("   pip install -r requirements_final.txt")
            return
    
    # Check if input file exists
    input_file = "websites_test.csv"
    if not Path(input_file).exists():
        print(f"❌ Input file not found: {input_file}")
        print("Please create a CSV file with URLs to scrape")
        return
    
    # Run the scraper
    print(f"🔍 Starting scraper with {input_file}")
    print("-" * 50)
    
    try:
        subprocess.run([
            sys.executable, "email_scraper_final.py",
            "--input", input_file,
            "--output", "emails_found.csv",
            "--concurrent", "8",
            "--per-domain", "3",
            "--delay-min", "1.5",
            "--delay-max", "3.0",
            "--timeout", "25",
            "--retries", "2"
        ])
    except KeyboardInterrupt:
        print("\n⏹️  Scraping interrupted by user")
    except Exception as e:
        print(f"❌ Error running scraper: {e}")

if __name__ == "__main__":
    main()