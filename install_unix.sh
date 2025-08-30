#!/bin/bash
# GrepAPK Unix Installation Script
# This script installs GrepAPK on Linux and macOS systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists dnf; then
            echo "fedora"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install system dependencies
install_system_deps() {
    local os=$(detect_os)
    
    case $os in
        "ubuntu"|"debian")
            print_status "Installing system dependencies for Ubuntu/Debian..."
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv python3-dev build-essential
            ;;
        "centos"|"rhel")
            print_status "Installing system dependencies for CentOS/RHEL..."
            sudo yum install -y python3 python3-pip python3-devel gcc
            ;;
        "fedora")
            print_status "Installing system dependencies for Fedora..."
            sudo dnf install -y python3 python3-pip python3-devel gcc
            ;;
        "arch")
            print_status "Installing system dependencies for Arch Linux..."
            sudo pacman -S --noconfirm python python-pip base-devel
            ;;
        "macos")
            print_status "macOS detected - checking Homebrew..."
            if ! command_exists brew; then
                print_warning "Homebrew not found. Consider installing it for better dependency management:"
                echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            else
                print_success "Homebrew is available"
            fi
            ;;
        *)
            print_warning "Unknown OS type: $os"
            print_warning "Please ensure Python 3.8+ and pip are installed manually"
            ;;
    esac
}

# Function to check Python version
check_python_version() {
    if ! command_exists python3; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    local python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major=$(echo $python_version | cut -d. -f1)
    local minor=$(echo $python_version | cut -d. -f2)
    
    if [[ $major -lt 3 ]] || [[ $major -eq 3 && $minor -lt 8 ]]; then
        print_error "Python 3.8 or higher is required. Current version: $python_version"
        exit 1
    fi
    
    print_success "Python version: $python_version"
}

# Function to check pip
check_pip() {
    if ! python3 -m pip --version >/dev/null 2>&1; then
        print_error "pip is not available"
        exit 1
    fi
    
    print_success "pip is available"
}

# Function to upgrade pip and build tools
upgrade_tools() {
    print_status "Upgrading pip..."
    python3 -m pip install --upgrade pip
    
    print_status "Installing/upgrading build tools..."
    python3 -m pip install --upgrade setuptools wheel setuptools_scm[toml]
}

# Function to install GrepAPK
install_grepapk() {
    print_status "Installing GrepAPK..."
    
    # Check if we're in the right directory
    if [[ ! -f "setup.py" ]] || [[ ! -f "pyproject.toml" ]]; then
        print_error "setup.py or pyproject.toml not found. Please run this script from the GrepAPK directory."
        exit 1
    fi
    
    # Install in development mode
    python3 -m pip install -e .
    
    if [[ $? -eq 0 ]]; then
        print_success "GrepAPK installed successfully!"
    else
        print_error "Installation failed!"
        exit 1
    fi
}

# Function to create launcher scripts
create_launchers() {
    print_status "Creating launcher scripts..."
    
    # Python launcher
    cat > grepapk.py << 'EOF'
#!/usr/bin/env python3
"""
GrepAPK Launcher Script
Quick launcher for GrepAPK security scanner.
"""

import sys
from config.grepapk_main import main

if __name__ == "__main__":
    main()
EOF
    
    # Shell launcher
    cat > grepapk << 'EOF'
#!/bin/bash
# GrepAPK Shell Launcher
python3 "$(dirname "$0")/grepapk.py" "$@"
EOF
    
    chmod +x grepapk
    
    print_success "Launcher scripts created"
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Test imports
    if python3 -c "import config.grepapk_main; print('Import test passed')" 2>/dev/null; then
        print_success "Core modules imported successfully"
    else
        print_error "Failed to import core modules"
        return 1
    fi
    
    # Test command line interface
    if python3 -m config.grepapk_main --help >/dev/null 2>&1; then
        print_success "Command-line interface working"
    else
        print_warning "Command-line interface may have issues"
        return 1
    fi
    
    return 0
}

# Function to show usage examples
show_usage() {
    echo
    echo "========================================"
    echo "           Usage Examples"
    echo "========================================"
    echo
    echo "Basic scan:"
    echo "  ./grepapk -d /path/to/apk/codebase -F"
    echo "  python3 grepapk.py -d /path/to/apk/codebase -F"
    echo
    echo "Get help:"
    echo "  ./grepapk --help"
    echo "  python3 grepapk.py --help"
    echo
    echo "Test installation:"
    echo "  python3 test_installation.py"
    echo
}

# Main installation function
main() {
    echo "========================================"
    echo "      GrepAPK Unix Installer"
    echo "========================================"
    echo
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Install system dependencies
    install_system_deps
    
    # Check Python and pip
    check_python_version
    check_pip
    
    # Upgrade tools
    upgrade_tools
    
    # Install GrepAPK
    install_grepapk
    
    # Create launchers
    create_launchers
    
    # Verify installation
    if verify_installation; then
        print_success "Installation completed successfully!"
        show_usage
    else
        print_warning "Installation completed but verification failed."
        print_warning "Please check the installation and try running: ./grepapk --help"
    fi
}

# Run main function
main "$@"
