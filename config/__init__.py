#!/usr/bin/env python3
"""
GrepAPK Configuration Package
Consolidated vulnerability scanning and detection system.
"""

__version__ = "3.0"
__author__ = "GrepAPK Security Team"
__description__ = "Android APK Security Scanner with AI and Regex Detection"

# Core modules
from . import grepapk_main
from . import vulnerability_patterns
from . import regex_scanner_enhanced
from . import ai_scanner
from . import ai_vulnerability_detector
from . import output_manager
from . import help_banner

# Export main classes and functions
__all__ = [
    'grepapk_main',
    'vulnerability_patterns', 
    'regex_scanner_enhanced',
    'ai_scanner',
    'ai_vulnerability_detector',
    'output_manager',
    'help_banner'
]
