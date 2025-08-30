#!/usr/bin/env python3
"""
GrepAPK Installation Script
Easy installation script for GrepAPK with different dependency options.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Print GrepAPK installation banner."""
    print("🔍" + "="*60 + "🔍")
    print("🚀           GrepAPK v3.0 Installation Script           🚀")
    print("🔍" + "="*60 + "🔍")
    print()
    print("📱 Android APK Security Scanner with AI-powered Analysis")
    print("🛡️  Comprehensive vulnerability detection and false positive reduction")
    print()

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required!")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def check_pip():
    """Check if pip is available."""
    try:
        import pip
        print("✅ pip is available")
        return True
    except ImportError:
        print("❌ Error: pip is not available!")
        print("   Please install pip first: https://pip.pypa.io/en/stable/installation/")
        sys.exit(1)

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
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✅ Installation completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        print(f"   Error output: {e.stderr}")
        return False

def create_launcher_scripts():
    """Create launcher scripts for easy access."""
    print("\n🔧 Creating launcher scripts...")
    
    # Create grepapk launcher script
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
        with open("grepapk", "w") as f:
            f.write(launcher_content)
        
        # Make executable on Unix-like systems
        if platform.system() != "Windows":
            os.chmod("grepapk", 0o755)
        
        print("✅ Launcher script 'grepapk' created")
    except Exception as e:
        print(f"⚠️  Could not create launcher script: {e}")

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
        result = subprocess.run([sys.executable, "-m", "config.grepapk_main", "--help"], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ Command-line interface working")
            return True
        else:
            print("⚠️  Command-line interface may have issues")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"⚠️  Verification issue: {e}")
        return False

def show_usage_examples():
    """Show usage examples after installation."""
    print("\n📚 Usage Examples:")
    print("="*50)
    print("🔍 Basic scan:")
    print("   grepapk -d /path/to/apk/codebase -F")
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

def main():
    """Main installation function."""
    print_banner()
    
    # Check prerequisites
    check_python_version()
    check_pip()
    
    # Show installation options
    print("\n📋 Installation Options:")
    print("1. Basic - Core functionality only")
    print("2. AI - Core + AI-powered analysis")
    print("3. Dev - Core + Development tools")
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
        sys.exit(1)
    
    # Create launcher scripts
    create_launcher_scripts()
    
    # Verify installation
    if verify_installation():
        print("\n🎉 GrepAPK installation completed successfully!")
        show_usage_examples()
        
        print("🚀 You can now use GrepAPK to scan Android APKs for vulnerabilities!")
        print("   For more information, run: grepapk --help")
        print("   Or visit: https://github.com/grepapk/grepapk")
    else:
        print("\n⚠️  Installation completed but verification failed.")
        print("   Please check the installation and try running: grepapk --help")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Installation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
