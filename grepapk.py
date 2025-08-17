#!/usr/bin/env python3
"""
Enhanced GrepAPK Launcher Script
Launcher for the Enhanced GrepAPK Android Security Scanner with 100% Accuracy and Exploit Integration
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the enhanced main function
from config.grepapk_main import main

if __name__ == "__main__":
    main()
