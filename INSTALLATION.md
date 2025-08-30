# GrepAPK Installation Guide

This guide provides comprehensive installation instructions for GrepAPK across different operating systems.

## 🚀 Quick Installation

### Option 1: Cross-Platform Installer (Recommended)
```bash
# Download and run the cross-platform installer
python3 install_cross_platform.py
```

### Option 2: Manual Installation
```bash
# Clone the repository
git clone https://github.com/grepapk/grepapk.git
cd grepapk

# Install with pip
pip install -e .
```

## 🖥️ Operating System Specific Instructions

### 🪟 Windows

#### Prerequisites
- Python 3.8 or higher
- pip (usually comes with Python)
- Git (optional, for cloning)

#### Installation Steps
1. **Download Python**
   - Visit [python.org](https://www.python.org/downloads/)
   - Download Python 3.8+ for Windows
   - **Important**: Check "Add Python to PATH" during installation

2. **Verify Installation**
   ```cmd
   python --version
   pip --version
   ```

3. **Install GrepAPK**
   ```cmd
   # Option A: Using the cross-platform installer
   python install_cross_platform.py
   
   # Option B: Manual installation
   pip install -e .
   ```

4. **Run GrepAPK**
   ```cmd
   # Using the batch file
   grepapk.bat --help
   
   # Using Python directly
   python grepapk.py --help
   ```

#### Troubleshooting Windows
- **Permission Denied**: Run PowerShell as Administrator
- **Python not found**: Ensure Python is added to PATH
- **pip not found**: Reinstall Python with pip option checked
- **Build tools error**: Install Visual Studio Build Tools

### 🍎 macOS

#### Prerequisites
- Python 3.8 or higher
- pip
- Git (optional)

#### Installation Steps
1. **Install Python**
   ```bash
   # Using Homebrew (recommended)
   brew install python@3.9
   
   # Or download from python.org
   # Visit: https://www.python.org/downloads/macos/
   ```

2. **Verify Installation**
   ```bash
   python3 --version
   pip3 --version
   ```

3. **Install GrepAPK**
   ```bash
   # Option A: Using the cross-platform installer
   python3 install_cross_platform.py
   
   # Option B: Manual installation
   pip3 install -e .
   ```

4. **Run GrepAPK**
   ```bash
   # Using the shell script
   ./grepapk --help
   
   # Using Python directly
   python3 grepapk.py --help
   ```

#### Troubleshooting macOS
- **Permission Denied**: Use `sudo python3 install_cross_platform.py`
- **M1/M2 Mac Issues**: Ensure you're using the correct Python version
- **Homebrew Issues**: Update Homebrew with `brew update`
- **Python Path Issues**: Check with `which python3`

### 🐧 Linux

#### Prerequisites
- Python 3.8 or higher
- pip
- Git (optional)

#### Installation Steps

##### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install GrepAPK
python3 install_cross_platform.py
```

##### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install python3 python3-pip

# Fedora
sudo dnf install python3 python3-pip

# Install GrepAPK
python3 install_cross_platform.py
```

##### Arch Linux
```bash
# Install Python and pip
sudo pacman -S python python-pip

# Install GrepAPK
python install_cross_platform.py
```

##### Generic Linux
```bash
# Verify Python installation
python3 --version
pip3 --version

# Install GrepAPK
python3 install_cross_platform.py
```

4. **Run GrepAPK**
   ```bash
   # Using the shell script
   ./grepapk --help
   
   # Using Python directly
   python3 grepapk.py --help
   ```

#### Troubleshooting Linux
- **Permission Denied**: Use `sudo python3 install_cross_platform.py`
- **Package Manager Issues**: Update your package manager first
- **Python Version**: Ensure you have Python 3.8+
- **pip Issues**: Install pip separately if needed

## 🔧 Installation Options

### Basic Installation (Recommended)
```bash
pip install -e .
```
- Core functionality only
- Regex-based vulnerability detection
- Lightweight and fast

### AI-Powered Installation
```bash
pip install -e .[ai]
```
- Core functionality
- AI-powered vulnerability detection
- Requires more disk space (~2-4GB)

### Development Installation
```bash
pip install -e .[dev]
```
- Core functionality
- Development tools (pytest, black, flake8, mypy)
- For contributors and developers

### Full Installation
```bash
pip install -e .[full]
```
- Everything included
- Core + AI + Development tools
- Maximum functionality

## 🐍 Virtual Environment (Recommended)

### Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv grepapk_env

# Activate virtual environment
# On Windows:
grepapk_env\Scripts\activate

# On macOS/Linux:
source grepapk_env/bin/activate
```

### Install in Virtual Environment
```bash
# Activate virtual environment first
pip install -e .

# Or with specific options
pip install -e .[ai]
```

## 🔍 Verification

After installation, verify that GrepAPK is working:

```bash
# Check if GrepAPK is installed
grepapk --help

# Or run directly
python3 grepapk.py --help

# Test basic functionality
grepapk --version
```

## 🚨 Common Issues and Solutions

### Import Errors
```bash
# Error: No module named 'config'
# Solution: Ensure you're in the correct directory
cd /path/to/grepapk
pip install -e .
```

### Permission Errors
```bash
# Error: Permission denied
# Solution: Use sudo (Linux/macOS) or run as Administrator (Windows)
sudo python3 install_cross_platform.py
```

### Python Version Issues
```bash
# Error: Python version too old
# Solution: Install Python 3.8 or higher
# Check current version:
python3 --version
```

### Build Tools Issues
```bash
# Error: Microsoft Visual C++ 14.0 is required (Windows)
# Solution: Install Visual Studio Build Tools
# Or use pre-compiled wheels:
pip install --only-binary=all -e .
```

### Network Issues
```bash
# Error: Connection timeout
# Solution: Use a different pip index or mirror
pip install -i https://pypi.org/simple/ -e .
```

## 📦 Alternative Installation Methods

### Using Conda
```bash
# Create conda environment
conda create -n grepapk python=3.9
conda activate grepapk

# Install GrepAPK
pip install -e .
```

### Using Docker
```bash
# Build Docker image
docker build -t grepapk .

# Run GrepAPK in container
docker run -it grepapk --help
```

## 🔄 Updating GrepAPK

```bash
# Update to latest version
git pull origin main
pip install -e . --upgrade

# Or reinstall completely
pip uninstall grepapk
pip install -e .
```

## 📞 Getting Help

If you encounter issues during installation:

1. **Check the troubleshooting section above**
2. **Review error messages carefully**
3. **Ensure you meet all prerequisites**
4. **Try the cross-platform installer**
5. **Create an issue on GitHub with:**
   - Operating system and version
   - Python version
   - Full error message
   - Steps to reproduce

## 🎯 Next Steps

After successful installation:

1. **Read the main README.md** for usage instructions
2. **Try a basic scan** with `grepapk --help`
3. **Explore features** with different command options
4. **Join the community** for support and updates

---

**Happy Scanning! 🔍🛡️**
