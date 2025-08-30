#!/usr/bin/env python3
"""
GrepAPK Installation Test Script
Tests if the installation is working correctly across different platforms.
"""

import sys
import os
import platform
import subprocess
from pathlib import Path

def print_header():
    """Print test header."""
    print("🔍" + "="*60 + "🔍")
    print("🧪           GrepAPK Installation Test Suite           🧪")
    print("🔍" + "="*60 + "🔍")
    print()
    print(f"🖥️  Operating System: {platform.system()} {platform.release()}")
    print(f"🐍 Python Version: {sys.version}")
    print(f"📁 Working Directory: {os.getcwd()}")
    print()

def test_python_imports():
    """Test if core Python modules can be imported."""
    print("🔍 Testing Python imports...")
    
    test_modules = [
        "click",
        "pathlib",
        "colorama",
        "rich",
        "tqdm"
    ]
    
    failed_imports = []
    
    for module in test_modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n⚠️  Failed imports: {', '.join(failed_imports)}")
        return False
    
    print("✅ All core Python modules imported successfully")
    return True

def test_grepapk_imports():
    """Test if GrepAPK modules can be imported."""
    print("\n🔍 Testing GrepAPK imports...")
    
    test_modules = [
        "config.grepapk_main",
        "config.vulnerability_patterns",
        "config.regex_scanner_enhanced",
        "config.output_manager",
        "config.help_banner"
    ]
    
    failed_imports = []
    
    for module in test_modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n⚠️  Failed imports: {', '.join(failed_imports)}")
        return False
    
    print("✅ All GrepAPK modules imported successfully")
    return True

def test_command_line_interface():
    """Test if the command-line interface works."""
    print("\n🔍 Testing command-line interface...")
    
    try:
        # Test help command
        result = subprocess.run([
            sys.executable, "-m", "config.grepapk_main", "--help"
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("✅ Command-line interface working")
            print(f"   Output length: {len(result.stdout)} characters")
            return True
        else:
            print(f"❌ Command-line interface failed with return code: {result.returncode}")
            if result.stderr:
                print(f"   Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Command-line interface timed out")
        return False
    except Exception as e:
        print(f"❌ Command-line interface error: {e}")
        return False

def test_file_structure():
    """Test if the file structure is correct."""
    print("\n🔍 Testing file structure...")
    
    required_files = [
        "config/__init__.py",
        "config/grepapk_main.py",
        "config/vulnerability_patterns.py",
        "config/regex_scanner_enhanced.py",
        "config/output_manager.py",
        "config/help_banner.py",
        "setup.py",
        "pyproject.toml",
        "requirements.txt"
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  Missing files: {', '.join(missing_files)}")
        return False
    
    print("✅ All required files present")
    return True

def test_package_installation():
    """Test if the package is properly installed."""
    print("\n🔍 Testing package installation...")
    
    try:
        import config
        print(f"✅ Package imported: {config.__name__}")
        print(f"   Version: {getattr(config, '__version__', 'Unknown')}")
        print(f"   Author: {getattr(config, '__author__', 'Unknown')}")
        
        # Check if it's in the right location
        config_path = os.path.dirname(config.__file__)
        print(f"   Location: {config_path}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Package import failed: {e}")
        return False

def test_ai_dependencies():
    """Test if AI dependencies are available (optional)."""
    print("\n🔍 Testing AI dependencies...")
    
    ai_modules = [
        "torch",
        "transformers",
        "numpy",
        "scikit-learn"
    ]
    
    available_modules = []
    missing_modules = []
    
    for module in ai_modules:
        try:
            __import__(module)
            available_modules.append(module)
            print(f"✅ {module}")
        except ImportError:
            missing_modules.append(module)
            print(f"❌ {module}")
    
    if available_modules:
        print(f"\n✅ AI modules available: {', '.join(available_modules)}")
        print("   AI-powered scanning will be available")
    else:
        print(f"\n⚠️  No AI modules available: {', '.join(missing_modules)}")
        print("   AI-powered scanning will not be available")
        print("   Install with: pip install -e .[ai]")
    
    return True  # This test doesn't fail the overall test

def run_all_tests():
    """Run all tests and provide summary."""
    print_header()
    
    tests = [
        ("Python Imports", test_python_imports),
        ("GrepAPK Imports", test_grepapk_imports),
        ("File Structure", test_file_structure),
        ("Package Installation", test_package_installation),
        ("Command Line Interface", test_command_line_interface),
        ("AI Dependencies", test_ai_dependencies)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\n📈 Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n🎉 All tests passed! GrepAPK is ready to use.")
        print("   Try running: grepapk --help")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please check the installation.")
        print("   Refer to INSTALLATION.md for troubleshooting.")
    
    return failed == 0

if __name__ == "__main__":
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Testing cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
