#!/usr/bin/env python3
"""
Cross-Platform GrepAPK Installation Script
Handles installation on Windows, macOS, and Linux with proper dependency management.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def print_banner():
    """Print GrepAPK installation banner."""
    print("🔍" + "="*60 + "🔍")
    print("🚀        GrepAPK v3.0 Cross-Platform Installer        🚀")
    print("🔍" + "="*60 + "🔍")
    print()
    print("📱 Android APK Security Scanner with AI-powered Analysis")
    print("🛡️  Comprehensive vulnerability detection and false positive reduction")
    print(f"🖥️  Detected OS: {platform.system()} {platform.release()}")
    print()

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required!")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected")
    return True

def check_pip():
    """Check if pip is available and working."""
    try:
        import pip
        print("✅ pip is available")
        
        # Check pip version
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                                  capture_output=True, text=True, check=True)
            print(f"   {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            print("⚠️  pip version check failed")
            
        return True
    except ImportError:
        print("❌ Error: pip is not available!")
        print("   Please install pip first: https://pip.pypa.io/en/stable/installation/")
        sys.exit(1)

def check_system_dependencies():
    """Check for system-specific dependencies."""
    system = platform.system()
    
    if system == "Darwin":  # macOS
        print("🍎 macOS detected - checking dependencies...")
        # Check if Homebrew is available
        if shutil.which("brew"):
            print("✅ Homebrew is available")
        else:
            print("⚠️  Homebrew not found - consider installing for better dependency management")
            print("   Install with: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
    
    elif system == "Linux":
        print("🐧 Linux detected - checking dependencies...")
        # Check for common package managers
        package_managers = ["apt", "yum", "dnf", "pacman", "zypper"]
        found_manager = None
        for manager in package_managers:
            if shutil.which(manager):
                found_manager = manager
                break
        
        if found_manager:
            print(f"✅ Package manager found: {found_manager}")
        else:
            print("⚠️  No common package manager detected")
    
    elif system == "Windows":
        print("🪟 Windows detected - checking dependencies...")
        # Check if Visual C++ redistributable might be needed
        print("ℹ️  Windows installation - no additional system dependencies required")
    
    return True

def upgrade_pip():
    """Upgrade pip to latest version."""
    print("\n🔄 Upgrading pip to latest version...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        print("✅ pip upgraded successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️  pip upgrade failed: {e}")
        print("   Continuing with current pip version...")
        return False

def install_build_tools():
    """Install build tools if needed."""
    print("\n🔧 Installing build tools...")
    
    build_tools = [
        "setuptools>=45.0.0",
        "wheel>=0.37.0",
        "setuptools_scm[toml]>=6.2"
    ]
    
    try:
        for tool in build_tools:
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", tool], 
                          check=True, capture_output=True)
        print("✅ Build tools installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build tools installation failed: {e}")
        return False

def install_dependencies(option):
    """Install dependencies based on user choice."""
    print(f"\n📦 Installing GrepAPK with {option} dependencies...")
    
    if option == "basic":
        cmd = [sys.executable, "-m", "pip", "install", "-e", "."]
    elif option == "ai":
        cmd = [sys.executable, "-m", "pip", "install", "-e", ".[ai]"]
    elif option == "dev":
        cmd = [sys.executable, "-m", "pip", "install", "-e", ".[dev]"]
    elif option == "full":
        cmd = [sys.executable, "-m", "pip", "install", "-e", ".[full]"]
    else:
        print("❌ Invalid option!")
        return False
    
    try:
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✅ Installation completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        if e.stderr:
            print(f"   Error output: {e.stderr}")
        if e.stdout:
            print(f"   Output: {e.stdout}")
        return False

def create_launcher_scripts():
    """Create launcher scripts for easy access."""
    print("\n🔧 Creating launcher scripts...")
    
    system = platform.system()
    
    # Create Python launcher script
    launcher_content = '''#!/usr/bin/env python3
"""
GrepAPK Launcher Script
Quick launcher for GrepAPK security scanner.
"""

import sys
from config.grepapk_main import main

if __name__ == "__main__":
    main()
'''
    
    try:
        with open("grepapk.py", "w", encoding="utf-8") as f:
            f.write(launcher_content)
        print("✅ Python launcher script 'grepapk.py' created")
    except Exception as e:
        print(f"⚠️  Could not create Python launcher script: {e}")
    
    # Create shell script for Unix-like systems
    if system != "Windows":
        shell_launcher = '''#!/bin/bash
# GrepAPK Shell Launcher
python3 "$(dirname "$0")/grepapk.py" "$@"
'''
        try:
            with open("grepapk", "w", encoding="utf-8") as f:
                f.write(shell_launcher)
            os.chmod("grepapk", 0o755)
            print("✅ Shell launcher script 'grepapk' created")
        except Exception as e:
            print(f"⚠️  Could not create shell launcher script: {e}")
    
    # Create batch file for Windows
    else:
        batch_launcher = '''@echo off
REM GrepAPK Batch Launcher
python "%~dp0grepapk.py" %*
'''
        try:
            with open("grepapk.bat", "w", encoding="utf-8") as f:
                f.write(batch_launcher)
            print("✅ Batch launcher script 'grepapk.bat' created")
        except Exception as e:
            print(f"⚠️  Could not create batch launcher script: {e}")

def verify_installation():
    """Verify that GrepAPK was installed correctly."""
    print("\n🔍 Verifying installation...")
    
    try:
        # Try to import main modules
        import config.grepapk_main
        import config.vulnerability_patterns
        import config.regex_scanner_enhanced
        import config.output_manager
        
        print("✅ Core modules imported successfully")
        
        # Try to run help
        try:
            result = subprocess.run([sys.executable, "-m", "config.grepapk_main", "--help"], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                print("✅ Command-line interface working")
                return True
            else:
                print("⚠️  Command-line interface may have issues")
                print(f"   Return code: {result.returncode}")
                if result.stderr:
                    print(f"   Error: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("⚠️  Command-line interface timed out")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"⚠️  Verification issue: {e}")
        return False

def show_usage_examples():
    """Show usage examples after installation."""
    system = platform.system()
    
    print("\n📚 Usage Examples:")
    print("="*50)
    
    if system == "Windows":
        print("🔍 Basic scan:")
        print("   grepapk.bat -d C:\\path\\to\\apk\\codebase -F")
        print("   python grepapk.py -d C:\\path\\to\\apk\\codebase -F")
    else:
        print("🔍 Basic scan:")
        print("   ./grepapk -d /path/to/apk/codebase -F")
        print("   python3 grepapk.py -d /path/to/apk/codebase -F")
    
    print()
    print("🔍 Regex-only scan:")
    print("   grepapk -d /path/to/apk/codebase --regex-only -v")
    print()
    print("🔍 AI-only scan:")
    print("   grepapk -d /path/to/apk/codebase --ai-only -v")
    print()
    print("🔍 Framework detection:")
    print("   grepapk -d /path/to/apk/codebase -T")
    print()
    print("🔍 JSON output:")
    print("   grepapk -d /path/to/apk/codebase -F -f json -o report.json")
    print()

def show_troubleshooting():
    """Show troubleshooting information."""
    system = platform.system()
    
    print("\n🔧 Troubleshooting:")
    print("="*50)
    
    if system == "Darwin":  # macOS
        print("🍎 macOS specific:")
        print("   • If you get permission errors, try: sudo python3 install_cross_platform.py")
        print("   • For M1/M2 Macs, ensure you're using the correct Python version")
        print("   • Consider using Homebrew: brew install python@3.9")
    
    elif system == "Linux":
        print("🐧 Linux specific:")
        print("   • If you get permission errors, try: sudo python3 install_cross_platform.py")
        print("   • For Ubuntu/Debian: sudo apt install python3-pip python3-venv")
        print("   • For CentOS/RHEL: sudo yum install python3-pip")
    
    elif system == "Windows":
        print("🪟 Windows specific:")
        print("   • Run PowerShell as Administrator if you get permission errors")
        print("   • Ensure Python is added to PATH during installation")
        print("   • Consider using Windows Subsystem for Linux (WSL) for better compatibility")
    
    print("\n🔧 General troubleshooting:")
    print("   • Try creating a virtual environment: python3 -m venv venv")
    print("   • Activate it: source venv/bin/activate (Linux/macOS) or venv\\Scripts\\activate (Windows)")
    print("   • Then run: pip install -e .")
    print("   • Check logs for specific error messages")

def main():
    """Main installation function."""
    print_banner()
    
    # Check prerequisites
    check_python_version()
    check_pip()
    check_system_dependencies()
    
    # Upgrade tools
    upgrade_pip()
    install_build_tools()
    
    # Show installation options
    print("\n📋 Installation Options:")
    print("1. Basic - Core functionality only (recommended for most users)")
    print("2. AI - Core + AI-powered analysis (requires more disk space)")
    print("3. Dev - Core + Development tools (for contributors)")
    print("4. Full - Everything (Core + AI + Dev tools)")
    print()
    
    while True:
        choice = input("Select installation type (1-4): ").strip()
        
        if choice == "1":
            option = "basic"
            break
        elif choice == "2":
            option = "ai"
            break
        elif choice == "3":
            option = "dev"
            break
        elif choice == "4":
            option = "full"
            break
        else:
            print("❌ Invalid choice! Please enter 1, 2, 3, or 4.")
    
    # Install dependencies
    if not install_dependencies(option):
        print("\n❌ Installation failed! Please check the error messages above.")
        show_troubleshooting()
        sys.exit(1)
    
    # Create launcher scripts
    create_launcher_scripts()
    
    # Verify installation
    if verify_installation():
        print("\n🎉 GrepAPK installation completed successfully!")
        show_usage_examples()
        
        print("\n🚀 You can now use GrepAPK to scan Android APKs for vulnerabilities!")
        print("   For more information, run: grepapk --help")
        print("   Or visit: https://github.com/grepapk/grepapk")
    else:
        print("\n⚠️  Installation completed but verification failed.")
        print("   Please check the installation and try running: grepapk --help")
        show_troubleshooting()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Installation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
