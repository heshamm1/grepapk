# GrepAPK 🔍

<div align="center">
  <img src="files/logo.png" alt="GrepAPK Logo" width=""/>
  <br/>
  <em>Advanced Android APK Security Scanner/Static Analysis Tool</em>
</div>

<div align="center">
  
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/) [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) [![Version](https://img.shields.io/badge/Version-1.0-orange.svg)](https://github.com/heshamm1/grepapk)

</div>

> **Comprehensive vulnerability detection using AI and regex patterns**

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Vulnerability Categories](#vulnerability-categories)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Examples](#examples)
- [License](#license)

## 🎯 Overview

GrepAPK is a powerful Android APK security scanning tool that combines intelligent regex pattern matching with AI-powered vulnerability detection. It provides comprehensive analysis of Android applications to identify security vulnerabilities across multiple programming languages and frameworks.

### ✨ Key Capabilities

- **Multi-Language Support**: Java, Kotlin, Dart, and Smali
- **AI-Powered Detection**: Advanced vulnerability analysis using CodeBERT/CodeT5 models
- **Comprehensive Coverage**: 12 major vulnerability categories
- **Flexible Scanning**: Tiny scan (framework analysis), full vulnerability scan, and RASP analysis
- **Multiple Output Formats**: JSON and TXT reports
- **False Positive Reduction**: Smart filtering for accurate results
- **ADB Payload Generation**: Ready-to-use exploitation commands
- **RASP Detection**: Runtime Application Self-Protection mechanism analysis

## 🚀 Features

### 🔍 Vulnerability Detection
- **Insecure Data Storage**: SharedPreferences, SQLite, file storage vulnerabilities
- **Insecure ICC**: Exported components, intent hijacking, task hijacking
- **WebView Vulnerabilities**: JavaScript injection, insecure content loading
- **Hardcoded Secrets**: API keys, passwords, certificates in source code
- **Network Security**: HTTP traffic, SSL bypass, certificate pinning
- **Input Validation**: SQL injection, path traversal, command injection
- **Configuration Issues**: Debug flags, backup settings, obfuscation
- **Side-Channel Attacks**: Timing leaks, clipboard data, intent sniffing
- **Third-Party SDK**: Outdated libraries, PII leakage
- **Authentication**: Weak session handling, biometric bypass
- **Root Detection**: Bypass techniques, detection logic
- **SSL Pinning**: Implementation flaws, bypass methods

### 🛠️ Technical Features
- **Regex Pattern Matching**: 1000+ vulnerability patterns
- **AI Model Integration**: Microsoft CodeBERT/CodeT5 for intelligent analysis
- **Parallel Processing**: Multi-threaded scanning for performance
- **Context-Aware Analysis**: Reduced false positives through smart filtering
- **RASP Detection**: Runtime protection mechanism analysis and assessment
- **Exportable Results**: JSON and TXT formats with detailed vulnerability information

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Android SDK (for ADB payloads)

### Method 1: Direct Installation

```bash
# Clone the repository
git clone https://github.com/heshamm1/grepapk.git
cd grepapk

# Install dependencies
pip install -r requirements.txt

# Run the tool
python grepapk.py --help
```

### Method 2: Using setup.py

```bash
# Clone and install
git clone https://github.com/heshamm1/grepapk.git
cd grepapk
python setup.py install

# Run from anywhere
grepapk --help
```

### Method 3: Using install.py

```bash
# Run the interactive installer
python install.py
```

## 🚀 Quick Start

### Basic Usage

```bash
# Scan an APK codebase directory
python grepapk.py -d /path/to/apk/source -F -f json -o scan_results

# Perform a tiny scan (framework analysis only)
python grepapk.py -d /path/to/apk/source -T -v

# Use AI-only detection
python grepapk.py -d /path/to/apk/source -F --ai-only -f json -o ai_scan
```

### Command Line Options

```bash
python .\grepapk.py -h

                             @@@@@@@@
                        @@@@@@@@@@@@@@@@@@
                    @@@@@@@@@@@@@@@@@@@@@@@@@@
               @@@@@@@@@@ @@@@@@@@@@@@@ @@@@@@@@@@@
            @@@@@@@@@@@@@@ @@@@@@@@@@@@ @@@@@@@@@@@@@@
            @@@@@@@@@@@@@@@            @@@@@@@@@@@@@@
            @@@@@@@@@@@@@                @@@@@@@@@@@@@
            @@@@@@@@@@@    @@       @@@   @@@@@@@@@@@@
            @@@@@@@@@@                     @@@@@@@@@@
            @@@@@@@@@@                      @@@@@@@@@@
            @@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            @@@@                      @@@@@@   @@@@@@
            @@@@@    @             @@@@    @@@@ @@@@@
             @@@@    @           @@@          @@@ @@@
             @@@@    @          @@   @@@@       @@ @
              @@@    @         @@    @@@@  @@@@ @@@
              @@@    @         @@     @@   @@@   @@
               @@@@@@@         @@ @@@ @@@   @    @@
                @@@@@@         @@@ @@@  @@@ @   @@
                 @@@@@@@        @@@  @@  @@ @@@@@
                  @@@@@@@@   @@@ @@@  @  @@  @@@@
                   @@@@@@@   @@@@@  @@@@@@@@@@@@@@@@
                     @@@@    @@@@@@@@  @@@      @@@@@@
                      @@@@@@@@@@@@@@@@@@@@@       @@@@@@
                         @@@@@@@@@@@@@@@@          @@@@@@
                           @@@@@@@@@@@@
                              @@@@@@
        🔒 GrepAPK - Advanced Android APK Security Scanner v3.0
      🤖 AI-Powered Vulnerability Detection with CodeBERT / CodeT5
                          Made with <3 by @etchoo
==================================================================
Usage: grepapk.py [OPTIONS]

  GrepAPK - Android APK Security Scanner

Options:
  -h, --help               Show this help message and exit
  -d, --directory TEXT     Directory of the APK codebase to scan  [required]
  -T, --tiny-scan          Perform tiny scan (framework analysis only)
  -F, --full-scan          Perform enhanced full vulnerability scan
  --ai-only                Use AI model only for scanning
  --regex-only             Use regex patterns only for scanning
  --all-methods            Use all detection methods (AI + regex) with
                           enhanced accuracy
  --rasp-only              Perform RASP mechanism analysis only
  -f, --format [txt|json]  Output format (txt or json)
  -o, --output TEXT        Output filename (without extension)
  -v, --verbose            Enable verbose output
```

## 📖 Usage

### Scan Types

#### 1. Tiny Scan (-T)
Analyzes framework, programming language, and RASP controls using AI models.

```bash
python grepapk.py -d /path/to/apk -T -v
```

**Output**: Framework analysis, language detection, security controls assessment

#### 2. Full Scan (-F)
Performs comprehensive vulnerability scanning across all categories.

```bash
python grepapk.py -d /path/to/apk -F --all-methods -f json -o full_scan
```

**Output**: Complete vulnerability report with severity levels and exploitation details

#### 3. RASP Analysis (--rasp-only)
Analyzes Runtime Application Self-Protection mechanisms and security controls.

```bash
python grepapk.py -d /path/to/apk --rasp-only -f json -o rasp_analysis
```

**Output**: RASP mechanism assessment, protection effectiveness, and security control analysis

### Detection Methods

#### Regex-Only Scanning
Fast pattern-based detection using predefined vulnerability patterns.

```bash
python grepapk.py -d /path/to/apk -F --regex-only -f json -o regex_scan
```

#### AI-Only Scanning
Intelligent analysis using machine learning models (requires AI dependencies).

```bash
python grepapk.py -d /path/to/apk -F --ai-only -f json -o ai_scan
```

#### Combined Detection
Uses both regex and AI for maximum coverage and accuracy.

```bash
python grepapk.py -d /path/to/apk -F --all-methods -f json -o combined_scan
```

## 🎯 Vulnerability Categories

### 1. Insecure Data Storage
- **SharedPreferences**: Plaintext storage of sensitive data
- **SQLite**: Unencrypted database content
- **File Storage**: Insecure internal/external storage usage
- **WebView Cache**: Sensitive page caching
- **Logcat Leaks**: Credentials in application logs
- **Backup Data**: Sensitive information in Android backups

### 2. Insecure Inter-Component Communication (ICC)
- **Exported Components**: Activities, services, receivers, providers
- **Intent Hijacking**: Implicit intent vulnerabilities
- **Intent Spoofing**: Forged intent attacks
- **Sensitive Data**: Tokens/passwords in intent extras
- **Sticky Broadcasts**: Persistent broadcast vulnerabilities
- **PendingIntent Misuse**: Mutable intent hijacking
- **Task Hijacking**: UI overlay attacks

### 3. WebView Vulnerabilities
- **JavaScript Interface**: RCE through @JavascriptInterface
- **Untrusted Content**: XSS-like mobile attacks
- **Local File Loading**: File:// and content:// attacks
- **SSL Bypass**: MITM vulnerability through ignored errors

### 4. Hardcoded Secrets
- **API Keys**: Backend credentials in source code
- **Passwords**: Authentication credentials
- **Certificates**: Embedded SSL/TLS certificates
- **URLs**: Hardcoded backend endpoints

### 5. Network Security
- **HTTP Traffic**: Cleartext communication
- **SSL Bypass**: Insecure certificate validation
- **Certificate Pinning**: Missing or weak pinning implementation

### 6. Input Validation
- **SQL Injection**: Raw query vulnerabilities
- **Path Traversal**: File operation bypasses
- **Command Injection**: Native/JNI call vulnerabilities

### 7. Configuration Issues
- **Debug Flags**: Production debugging enabled
- **Backup Settings**: Unrestricted data extraction
- **Obfuscation**: Disabled ProGuard/R8 protection
- **Native Libraries**: Vulnerable native code

### 8. Side-Channel Attacks
- **Clipboard Data**: Sensitive information exposure
- **Timing Attacks**: Authentication logic differences
- **Intent Sniffing**: Data leakage through logging

### 9. Third-Party SDK
- **Outdated Libraries**: Known vulnerability exposure
- **PII Leakage**: Analytics and advertising data exposure

### 10. Authentication
- **Session Management**: Weak token handling
- **Biometric Bypass**: Client-side authentication flaws

### 11. Root Detection
- **Detection Logic**: Weak bypass protection
- **Client-Only**: Patchable security measures

### 12. SSL Pinning
- **Implementation**: Hardcoded certificate flaws
- **Bypass Methods**: Dynamic hooking and patching

## 📊 Output Formats

### JSON Output
Structured vulnerability data with detailed information:

```json
{
  "scan_info": {
    "directory": "/path/to/apk",
    "scan_type": "FULL",
    "timestamp": "2024-01-01T12:00:00Z",
    "total_vulnerabilities": 150
  },
  "vulnerabilities": [
    {
      "title": "Insecure Data Storage - SharedPreferences",
      "category": "insecure_data_storage",
      "subcategory": "shared_preferences",
      "severity": "HIGH",
      "confidence": 95,
      "file": "MainActivity.java",
      "line": 42,
      "line_content": "SharedPreferences.Editor editor = prefs.edit();",
      "description": "Sensitive data stored in plaintext SharedPreferences",
      "exploitation_method": "External APK",
      "adb_payload": "adb shell am start -n com.example.app/.MainActivity",
      "recommendation": "Use EncryptedSharedPreferences for sensitive data"
    }
  ]
}
```

### TXT Output
Human-readable vulnerability report:

```
GrepAPK Security Scan Report
============================

Scan Information:
- Directory: /path/to/apk
- Scan Type: FULL
- Timestamp: 2024-01-01 12:00:00
- Total Vulnerabilities: 150

Vulnerabilities Found:
=====================

1. Insecure Data Storage - SharedPreferences
   File: MainActivity.java:42
   Severity: HIGH
   Description: Sensitive data stored in plaintext SharedPreferences
   Exploitation: External APK
   Recommendation: Use EncryptedSharedPreferences for sensitive data
```

## ⚙️ Configuration

### Environment Variables

```bash
# AI Model Configuration
export GREPAPK_AI_MODEL_PATH="/path/to/models"
export GREPAPK_AI_CONFIDENCE_THRESHOLD=0.8

# Performance Settings
export GREPAPK_MAX_THREADS=8
export GREPAPK_SCAN_TIMEOUT=3600
```

### Configuration Files

The tool automatically detects and uses configuration from the `config/` directory:

- `vulnerability_patterns.py`: Vulnerability detection patterns
- `regex_scanner_enhanced.py`: Enhanced scanning logic
- `ai_scanner.py`: AI model integration
- `output_manager.py`: Output formatting and management
- `rasp_detector.py`: RASP mechanism detection and analysis

## 📝 Examples

### Example 1: Quick Security Assessment

```bash
# Perform a quick framework analysis
python grepapk.py -d /path/to/android/app -T -v

# Output: Framework detection, language identification, security controls
```

### Example 2: Comprehensive Security Audit

```bash
# Full vulnerability scan with all detection methods
python grepapk.py -d /path/to/android/app -F --all-methods -f json -o security_audit -v

# Output: Complete vulnerability report in JSON format
```

### Example 3: Regex-Only Fast Scan

```bash
# Fast pattern-based scanning
python grepapk.py -d /path/to/android/app -F --regex-only -f txt -o quick_scan

# Output: Fast vulnerability detection using regex patterns
```

### Example 4: AI-Enhanced Analysis

```bash
# AI-powered vulnerability detection
python grepapk.py -d /path/to/android/app -F --ai-only -f json -o ai_analysis -v

# Output: Intelligent vulnerability analysis with confidence scores
```

### Example 5: RASP Mechanism Analysis

```bash
# Analyze runtime protection mechanisms
python grepapk.py -d /path/to/android/app --rasp-only -f json -o rasp_analysis -v

# Output: RASP mechanism assessment, protection effectiveness, and security controls
```

## 🤝 Contributing

We welcome contributions to improve GrepAPK! Here's how you can help:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/heshamm1/grepapk.git
cd grepapk

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Contribution Areas

1. **Vulnerability Patterns**: Add new detection patterns
2. **AI Models**: Improve machine learning detection
3. **Performance**: Optimize scanning algorithms
4. **Documentation**: Enhance guides and examples
5. **Testing**: Add test cases and validation

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- **Microsoft Research**: CodeBERT and CodeT5 models
- **Android Security Community**: Vulnerability research and patterns
- **Open Source Contributors**: Pattern libraries and security tools

## Support

- **Issues**: [GitHub Issues](https://github.com/heshamm1/grepapk/issues)
- **Discussions**: [GitHub Discussions](https://github.com/heshamm1/grepapk/discussions)
- **Documentation**: [Wiki](https://github.com/heshamm1/grepapk/wiki)

---

**⚠️ Disclaimer**: This tool is for educational and security research purposes only. Always ensure you have proper authorization before scanning any applications.

**Made with ❤️ by the @etchoo**
