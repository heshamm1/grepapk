#!/usr/bin/env python3
"""
GrepAPK Launcher Script
Simple launcher for the GrepAPK Android Security Scanner
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main function
from config.grepapk_main import main

if __name__ == "__main__":
    main()
