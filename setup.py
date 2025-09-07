#!/usr/bin/env python3
"""
Setup script for GrepAPK - Android APK Security Scanner
A comprehensive tool for detecting vulnerabilities in Android applications using regex patterns and AI analysis.
"""

from setuptools import setup, find_packages
import os
import re

def read_readme():
    """Read README.md file for long description."""
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "Android APK Security Scanner with AI-powered vulnerability detection"

def get_version():
    """Extract version from banner.txt file."""
    try:
        with open("files/banner.txt", "r", encoding="utf-8") as fh:
            content = fh.read()
            version_match = re.search(r'[Vv]ersion[:\s]*([0-9]+\.[0-9]+)', content)
            if version_match:
                return version_match.group(1)
    except FileNotFoundError:
        pass

    return "3.0.0"

def read_requirements():
    """Read requirements from requirements.txt file."""
    try:
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            requirements = []
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    requirements.append(line)
            return requirements
    except FileNotFoundError:
        # Fallback requirements if file not found
        return [
            "click>=8.0.0",
            "pathlib2>=2.3.0",
            "colorama>=0.4.4",
            "rich>=12.0.0",
            "tqdm>=4.64.0"
        ]

# Package configuration
setup(
    name="grepapk",
    version=get_version(),
    author="GrepAPK Security Team",
    author_email="security@grepapk.com",
    description="Android APK Security Scanner with AI-powered vulnerability detection",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    keywords=[
        "android", "apk", "security", "vulnerability", "scanner", 
        "static-analysis", "penetration-testing", "mobile-security",
        "regex", "ai", "machine-learning", "code-analysis"
    ],
    url="https://github.com/grepapk/grepapk",
    project_urls={
        "Bug Reports": "https://github.com/grepapk/grepapk/issues",
        "Source": "https://github.com/grepapk/grepapk",
        "Documentation": "https://github.com/grepapk/grepapk/blob/main/README.md",
        "Security": "https://github.com/grepapk/grepapk/security/policy",
    },
    packages=find_packages(),
    py_modules=[
        "config.grepapk_main",
        "config.vulnerability_patterns",
        "config.regex_scanner_enhanced",
        "config.ai_scanner",
        "config.output_manager",
        "config.help_banner",
        "config.rasp_detector"
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Security Analysts",
        "Intended Audience :: Penetration Testers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Environment :: Console",
        "Framework :: Click",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "pre-commit>=2.20.0",
        ],
        "ai": [
            "torch>=1.12.0",
            "transformers>=4.20.0",
            "tokenizers>=0.13.0",
            "numpy>=1.21.0",
            "scikit-learn>=1.1.0",
        ],
        "full": [
            "torch>=1.12.0",
            "transformers>=4.20.0",
            "tokenizers>=0.13.0",
            "numpy>=1.21.0",
            "scikit-learn>=1.1.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "pre-commit>=2.20.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "grepapk=config.grepapk_main:main",
            "grepapk-scan=config.grepapk_main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": [
            "*.txt",
            "*.md",
            "*.yaml",
            "*.yml",
            "*.json",
            "*.xml",
            "*.cfg",
            "*.ini",
        ],
    },
    data_files=[
        ("share/grepapk", [
            "files/banner.txt",
            "README.md",
            "requirements.txt"
        ]),
        ("share/grepapk/config", [
            "config/__init__.py",
            "config/grepapk_main.py",
            "config/ai_vulnerability_detector.py",
            "config/rasp_detector.py"
        ]),
        ("share/grepapk/config/patterns", [
            "config/vulnerability_patterns.py"
        ]),
        ("share/grepapk/config/scanners", [
            "config/regex_scanner_enhanced.py",
            "config/ai_scanner.py"
        ]),
        ("share/grepapk/config/utils", [
            "config/output_manager.py",
            "config/help_banner.py"
        ]),
    ],
    zip_safe=False,
    platforms=["any"],
    license="MIT",
    license_files=["LICENSE"],
    maintainer="GrepAPK Security Team",
    maintainer_email="maintainers@grepapk.com",
    download_url="https://github.com/grepapk/grepapk/releases",
    provides=["grepapk"],
    requires_python=">=3.8",
    setup_requires=[
        "setuptools>=45.0.0",
        "wheel>=0.37.0",
    ],
    test_suite="tests",
    tests_require=[
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
    ],
    options={
        "bdist_wheel": {
            "universal": True,
        },
    },
    # Additional metadata
    keywords_text="android apk security vulnerability scanner static analysis",
    description_file="README.md",
    long_description_file="README.md",
    # Custom commands
    cmdclass={},
    # Scripts
    scripts=[
        "grepapk.py",
    ],
    # Package discovery
    package_dir={"": "."},
    # Exclude patterns
    exclude_package_data={
        "": [
            "*.pyc",
            "*.pyo",
            "*.pyd",
            "__pycache__",
            "*.so",
            "*.dll",
            "*.dylib",
            ".git*",
            ".svn*",
            ".DS_Store",
            "*.log",
            "*.tmp",
            "*.bak",
        ]
    },
    # Dependencies for specific platforms
    dependency_links=[],
    # Additional classifiers for security tools
    keywords_security=[
        "vulnerability-assessment",
        "penetration-testing",
        "security-audit",
        "code-review",
        "static-analysis",
        "mobile-security",
        "android-security",
    ],
    # Project URLs for security community
    project_urls_security={
        "Security Policy": "https://github.com/grepapk/grepapk/security/policy",
        "Security Advisories": "https://github.com/grepapk/grepapk/security/advisories",
        "Bug Bounty": "https://github.com/grepapk/grepapk/security/advisories",
        "Responsible Disclosure": "https://github.com/grepapk/grepapk/security/policy",
    },
)

# Print installation information
if __name__ == "__main__":
    print(f"🔍 GrepAPK v{get_version()} Setup")
    print("📦 Installing Android APK Security Scanner...")
    print("🚀 Features:")
    print("   • Regex-based vulnerability detection")
    print("   • AI-powered analysis (optional)")
    print("   • 12 vulnerability categories")
    print("   • False positive reduction")
    print("   • Multiple output formats (TXT/JSON)")
    print("   • ADB payload generation")
    print("   • Cross-platform support")
    print()
    print("💡 For AI features, install with: pip install -e .[ai]")
    print("💡 For development, install with: pip install -e .[dev]")
    print("💡 For everything, install with: pip install -e .[full]")
    print()
