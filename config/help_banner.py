#!/usr/bin/env python3
"""
Help & Banner Module for GrepAPK
Provides help text, banner display, and general tool information.
"""

import click
from pathlib import Path
from typing import Optional


class HelpBanner:
    """Handles help text, banner display, and tool information."""
    
    def __init__(self):
        self.version = "3.0"
    
    def _get_banner(self):
        """Get the banner text."""
        return f"""
                                   .-=****+-.                                   
                               :=+#%%%%%%%%%%#*=:.                              
                          .-+*#%%%%%%%%%%%%%%%%%%#*+-.                          
                      :-+#%%%%%%%%%%%%%%%%%%%%%%%%%%%%#+=:                      
                 .-=*#%%%%%%%%#+#%%%%%%%%%%%%%%#=#%%%%%%%%#*=-.                 
               =#%%%%%%%%%%%%%%-.#%%%##**##%%%#.-%%%%%%%%%%%%%%#=               
              -%%%%%%%%%%%%%%%%%-.=:.      .:=.-%%%%%%%%%%%%%%%%%-              
              =%%%%%%%%%%%%%%%#-.              .=#%%%%%%%%%%%%%%%=              
              -%%%%%%%%%%%%%%=   ..          ..   =%%%%%%%%%%%%%%:              
              -%%%%%%%%%%%%#:   -%%:        .%%-   :%%%%%%%%%%%%%:              
              :%%%%%%%%%%%%-     ::          ::     -%%%%%%%%%%%%-              
              :%%%%%%%%%%%*                          *%%%%%%%%%%%:              
              .%%%%%%%%%%%#--------------------------#%%%%%%%%%%#.               
               #%%%%#-..-%#-------------------------==+#%%%%%%%%#               
               *%%%%-    =*                 .-=+***+=-:.:+#%%%%%+               
               -%%%%:    =*              .=#%#*+===+*#%#=. =%%%%-               
               .%%%%:    =*             =%%+:         .=#%+ :#%%.               
                *%%%:    =*            *%*.  .=++.       =%#..#*                 
                :%%%:    =*           +%*    +%:*#   :-.  =%# -:                 
                 *%%:    =*          :%#.     +%*.  +*-#-  *%-                   
                 .%%=    +*          =%+   .  :@-   =*+*:  =%*                   
                  -%#=::=%*          -%* -**+  *#:   =@:   =%+                   
                   +%%%%%%*          .%%.-**%-  -#*  -%.   #%:                   
                    +%%%%%#:          =%*   :**. -%. :%=  *%+                     
                     =%%%%%%#*=     += =%#-  .%= -%   .*#*%+                     
                      -#%%%%%%*     #%+.:*%#-:%= :%. .-*%%%*:                     
                       .*%%%%%*     *%%#-.:+#%%#**%##%%+:=#%%#+.                 
                         -#%%%*     #%%%%#+-:::-=-=--:    -%%%%#=                
                          .+#%%+:.:*%%%%%%%%%#*+==++-      -#%%%%#-              
                            .=#%%%%%%%%%%%%%%%%%%%+.         =#%%%%*             
                              .=#%%%%%%%%%%%%%%#=.            .+%%%#.             
                                 -*%%%%%%%%%%*-                 :=-.              
                                   .-*#%%%*=.                                   
                                      .::.                                      

           🔒 GrepAPK - Advanced Android APK Security Scanner v{self.version}
         🤖 AI-Powered Vulnerability Detection with CodeBERT / CodeT5
                             Made with <3 by @etchoo
=================================================================="""
    
    def _get_logo_ascii(self):
        """Get the ASCII logo for GrepAPK."""
        return f"""
     ██████╗ ██████╗ ███████╗██████╗  █████╗ ██████╗ ██╗  ██╗
    ██╔════╝ ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝
    ██║  ███╗██████╔╝█████╗  ██████╔╝███████║██████╔╝█████╔╝
    ██║   ██║██╔══██╗██╔══╝  ██╔═══╝ ██╔══██║██╔═══╝ ██╔═██╗
    ╚██████╔╝██║  ██║███████╗██║     ██║  ██║██║     ██║  ██╗
     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝     ╚═╝  ╚═╝
        🔒 Advanced Android APK Security Scanner v{self.version}
  🤖 AI-Powered Vulnerability Detection with CodeBERT / CodeT5
                      Made with <3 by @etchoo
=================================================================="""
    
    def _get_logo_from_file(self):
        """Try to get logo from banner.txt file in the files folder."""
        try:
            banner_path = Path(__file__).parent.parent / "files" / "banner.txt"
            if banner_path.exists():
                with open(banner_path, 'r', encoding='utf-8') as f:
                    banner_content = f.read()
                return f"""{banner_content}
        🔒 GrepAPK - Advanced Android APK Security Scanner v{self.version}
      🤖 AI-Powered Vulnerability Detection with CodeBERT / CodeT5
                          Made with <3 by @etchoo
=================================================================="""
            else:
                return self._get_logo_ascii()
        except Exception:
            return self._get_logo_ascii()
    
    def display_banner(self):
        """Display the GrepAPK banner."""
        try:
            banner_path = Path(__file__).parent.parent / "files" / "banner.txt"
            if banner_path.exists():
                with open(banner_path, 'r', encoding='utf-8') as f:
                    banner_content = f.read()
                banner = f"""{banner_content}
        🔒 GrepAPK - Advanced Android APK Security Scanner v{self.version}
      🤖 AI-Powered Vulnerability Detection with CodeBERT / CodeT5
                          Made with <3 by @etchoo
=================================================================="""
                print(banner)
            else:
                banner = self._get_banner()
                print(banner)
        except Exception:
            banner = self._get_banner()
            print(banner)
    
    @staticmethod
    def _display_fallback_banner() -> None:
        """Display fallback banner if banner.txt is not available."""
        fallback_banner = """GrepAPK - Android APK Security Scanner v2.0
================================================================================
Advanced Android APK Security Scanner with AI-Powered Vulnerability Detection
Hybrid Detection: Regex + AI Integration
Professional Security Analysis & Exploitation Methods
================================================================================
Version: 1.0
Author: @etchoo
AI Model: Microsoft CodeBERT / CodeT5
================================================================================
"""
        click.echo(fallback_banner)
    
    @staticmethod
    def display_usage() -> None:
        """Display usage information."""
        usage_text = """
USAGE EXAMPLES:

1. Full Security Scan:
   python3 grepapk.py -d <APK_CODEBASE> -S

2. Tiny Scan (Framework Detection Only):
   python3 grepapk.py -d <APK_CODEBASE> -T

3. Verbose Output:
   python3 grepapk.py -d <APK_CODEBASE> -S -v

4. Generate HTML Report:
   python3 grepapk.py -d <APK_CODEBASE> -S -f html -o report.html

5. Custom Output File:
   python3 grepapk.py -d <APK_CODEBASE> -S -o custom_report.txt

SCAN TYPES:
  -S, --full-scan      Perform comprehensive security vulnerability scan
  -T, --tiny-scan      Perform tiny scan (framework detection only)

OPTIONS:
  -d, --directory      Directory containing APK codebase (required)
  -f, --output-format  Output format: txt or html (default: txt)
  -o, --output-file    Output file path for the report
  -v, --verbose        Enable verbose logging and detailed output

EXAMPLES:
  python3 grepapk.py -d /path/to/android/app -S
  python3 grepapk.py -d /path/to/android/app -T -v
  python3 grepapk.py -d /path/to/android/app -S -f html -o security_report.html
"""
        click.echo(usage_text)
    
    @staticmethod
    def display_features() -> None:
        """Display detailed feature information."""
        features_text = """
DETAILED FEATURES:

🔍 VULNERABILITY DETECTION:
  • Hardcoded Secrets (API keys, passwords, tokens)
  • Information Disclosure (logging, debug info, error messages)
  • Insecure Components (exported components, WebView issues)
  • Intent Vulnerabilities (intent spoofing, filter bypass)
  • Input Validation (SQL injection, command injection, XSS)
  • Security Bypass (root detection, SSL pinning bypass)
  • Network Security (cleartext traffic, weak SSL)

🤖 AI-POWERED ANALYSIS:
  • Microsoft CodeBERT / CodeT5 Integration
  • Context-Aware Code Analysis
  • Confidence Scoring (0.0 – 1.0)
  • False Positive Reduction
  • Intelligent Remediation Suggestions
  • Parallel AI Processing
  • Batch Processing for Large Codebases

🛡️  SEMGREP INTEGRATION:
  • Custom Security Rules
  • Multiple Rule Sets
  • JSON Output Processing
  • Rule-Specific Vulnerability Mapping
  • Severity Level Mapping
  • Exploitation Method Assignment

📱 ANDROID-SPECIFIC:
  • Java/Kotlin Source Code Analysis
  • XML Manifest and Layout Analysis
  • Smali Bytecode Analysis (Decompiled APKs)
  • Gradle Build Configuration Analysis
  • Framework Detection (Ionic, React Native, Flutter)
  • Component Security Analysis

🚀 PERFORMANCE & OPTIMIZATION:
  • Parallel File Processing
  • Configurable Worker Threads
  • File Size Filtering
  • Duplicate Detection
  • Memory Management
  • Timeout Handling

📊 REPORTING & OUTPUT:
  • Text Format Reports
  • HTML Format Reports
  • Vulnerability Categorization
  • Severity Classification
  • Exploitation Methods
  • Remediation Recommendations
  • ADB Payload Generation
  • Cross-Validation Results
"""
        click.echo(features_text)
    
    @staticmethod
    def display_scan_types() -> None:
        """Display information about different scan types."""
        scan_types_text = """
SCAN TYPE DETAILS:

🔍 FULL SECURITY SCAN (-S):
  • Comprehensive vulnerability detection using ALL methods
  • Regex pattern matching across all source files
  • AI-powered code analysis (when available)
  • Semgrep static analysis with custom rules
  • Hybrid detection and cross-validation
  • Framework detection and analysis
  • Detailed vulnerability reporting
  • Exploitation method identification
  • Remediation recommendations

📋 TINY SCAN (-T):
  • Framework detection only
  • Quick analysis of manifest and build files
  • No vulnerability scanning
  • Fast execution for initial assessment
  • Useful for understanding project structure
  • Framework identification and confidence scoring

SCAN FLOW:
  1. Framework Detection
  2. File Discovery and Filtering
  3. Regex Pattern Scanning
  4. AI-Powered Analysis (if available)
  5. Semgrep Static Analysis
  6. Hybrid Cross-Validation
  7. Result Deduplication
  8. Report Generation
"""
        click.echo(scan_types_text)
    
    @staticmethod
    def display_vulnerability_categories() -> None:
        """Display information about vulnerability categories."""
        categories_text = """
VULNERABILITY CATEGORIES:

🔐 HARDCODED SECRETS:
  • API Keys and Tokens
  • Database Credentials
  • Passwords and PINs
  • Encryption Keys
  • Authentication Tokens
  • OAuth Secrets

📢 INFORMATION DISCLOSURE:
  • Sensitive Data Logging
  • Debug Information Exposure
  • Error Message Details
  • Internal Path Exposure
  • Stack Trace Disclosure
  • Configuration Exposure

🔓 INSECURE COMPONENTS:
  • Exported Components
  • WebView Security Issues
  • Content Provider Vulnerabilities
  • Service Exports
  • Receiver Exports
  • Activity Exports

🎯 INTENT VULNERABILITIES:
  • Intent Spoofing
  • Intent Filter Bypass
  • Deep Link Vulnerabilities
  • Component Hijacking
  • Intent Redirection
  • Filter Manipulation

⚡ INPUT VALIDATION:
  • SQL Injection
  • Command Injection
  • Path Traversal
  • Cross-Site Scripting (XSS)
  • Unsafe Deserialization
  • Buffer Overflow

🚪 SECURITY BYPASS:
  • Root Detection Bypass
  • SSL Pinning Bypass
  • Authentication Bypass
  • Permission Bypass
  • Code Signing Bypass
  • Anti-Tamper Bypass

🌐 NETWORK SECURITY:
  • Cleartext Traffic
  • Weak SSL/TLS
  • Certificate Validation Bypass
  • Hostname Verification Bypass
  • Insecure Network Calls
  • Man-in-the-Middle Vulnerabilities
"""
        click.echo(categories_text)
    
    def show_help(self):
        """Display just the banner logo."""
        help_text = f"""{self._get_logo_from_file()}"""
        try:
            print(help_text)
        except UnicodeEncodeError:
            # Fallback for systems with limited Unicode support
            import sys
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
                print(help_text)
            else:
                # For older Python versions, encode manually
                print(help_text.encode('utf-8', errors='replace').decode('utf-8'))
    
    @staticmethod
    def get_version() -> str:
        """Get the current version of GrepAPK."""
        return "3.0.0"
    
    @staticmethod
    def get_author() -> str:
        """Get the author information."""
        return "@etchoo"
    
    @staticmethod
    def get_ai_model() -> str:
        """Get the AI model information."""
        return "Microsoft CodeBERT / CodeT5"
    
    @staticmethod
    def validate_scan_type(full_scan: bool, tiny_scan: bool) -> tuple[bool, str]:
        """Validate scan type parameters."""
        if not full_scan and not tiny_scan:
            return False, "❌ Error: Must specify either -S (full scan) or -T (tiny scan)"
        
        if full_scan and tiny_scan:
            return False, "❌ Error: Cannot specify both -S and -T"
        
        return True, ""
    
    @staticmethod
    def get_scan_type_string(full_scan: bool, tiny_scan: bool) -> str:
        """Get the scan type as a string."""
        if full_scan:
            return 'FULL'
        elif tiny_scan:
            return 'TINY'
        else:
            return 'UNKNOWN'
