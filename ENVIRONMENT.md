# Environment Setup for nvme-cli

This guide covers how to set up your development environment for building nvme-cli and libnvme on Linux and Windows platforms.

## Dependencies Overview

### Core Build Tools

**Both Platforms:**
- Meson >= 0.62.0 (build system)
- Ninja (build backend) or Samurai (minimal alternative)
- C compiler (GCC or Clang on Linux, MSVC or MinGW on Windows)

### Platform-Specific Dependencies

#### Linux Dependencies

**Required:**
- gcc or clang
- meson
- ninja-build or samurai

**Optional (recommended):**
- json-c >= 0.13 (for JSON output and plugins)
- OpenSSL >= 3.0.0 (for security features)
- libkeyutils (for key management)
- liburing >= 2.2 (for io_uring support)
- dbus-1 (for MCTP dbus scan support)

**Documentation (optional):**
- asciidoc or asciidoctor
- xmlto

**Testing (optional):**
- Python 3 with pytest (for tests)
- SWIG (for Python bindings)

#### Windows Dependencies

**Required:**
- MSVC (Visual Studio 2019 or later) OR MinGW-w64 (installed via WinGet)
- Meson
- Ninja
- Python 3.8+
- Windows SDK (for Visual Studio builds)

**System Libraries (automatically linked):**
- ws2_32.lib (Windows Sockets 2)
- wsock32.lib (Windows Sockets)
- kernel32.lib (Windows Kernel)
- iphlpapi.lib (IP Helper API)

**Optional:**
- OpenSSL >= 3.0.0 (for security features)
- Perl (for documentation generation scripts)

**Note:** On Windows, Linux-specific dependencies (json-c, liburing, keyutils, libdbus) are automatically disabled.

## Linux Environment Setup

### Ubuntu/Debian

```bash
# Install core build tools
sudo apt update
sudo apt install -y build-essential meson ninja-build pkg-config

# Install optional dependencies
sudo apt install -y \
    libjson-c-dev \
    libssl-dev \
    libkeyutils-dev \
    libdbus-1-dev

# For io_uring support (optional)
sudo apt install -y liburing-dev

# For documentation generation (optional)
sudo apt install -y asciidoc xmlto

# For Python bindings (optional)
sudo apt install -y python3-dev swig
```

### Fedora/RHEL/CentOS

```bash
# Install core build tools
sudo dnf install -y gcc meson ninja-build pkgconfig

# Install optional dependencies
sudo dnf install -y \
    json-c-devel \
    openssl-devel \
    keyutils-libs-devel \
    dbus-devel

# For io_uring support (optional)
sudo dnf install -y liburing-devel

# For documentation generation (optional)
sudo dnf install -y asciidoc xmlto

# For Python bindings (optional)
sudo dnf install -y python3-devel swig
```

### Arch Linux

```bash
# Install core build tools
sudo pacman -S base-devel meson ninja pkg-config

# Install optional dependencies
sudo pacman -S json-c openssl keyutils dbus

# For io_uring support (optional)
sudo pacman -S liburing

# For documentation generation (optional)
sudo pacman -S asciidoc xmlto

# For Python bindings (optional)
sudo pacman -S python swig
```

## Windows Environment Setup

### Using WinGet (Windows 10/11)

WinGet provides the easiest way to set up the build environment on Windows:

#### Installation

```powershell
# Install MinGW-w64 (GCC compiler toolchain)
winget install BrechtSanders.WinLibs.POSIX.UCRT

# Install Python (required for meson)
winget install Python.Python.3.12

# Install Perl (required for documentation generation scripts)
winget install StrawberryPerl.StrawberryPerl

# Install Meson build system (after Python is installed)
pip install meson

# Install OpenSSL (optional, for security features)
winget install ShiningLight.OpenSSL
```

#### Setting Up PATH

After installation, you need to add the tools to your PATH:

**Temporary PATH setup (for current PowerShell session):**

```powershell
# Set PATH to include MinGW, Python, and Meson
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312\Scripts;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312;$env:PATH"
```

**Note:** The exact path for MinGW may vary depending on your WinGet installation. Use this command to locate it:
```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter "BrechtSanders.WinLibs*" -Directory
```

**Permanent PATH setup:**

To avoid setting PATH every time:

1. Open System Properties:
   - Press `Win + X` → System → Advanced system settings
   - Or search for "Environment Variables" in Start Menu

2. Click "Environment Variables"

3. Under "User variables", select "Path" and click "Edit"

4. Click "New" and add these paths (adjust the username and exact paths as needed):
   - `C:\Users\YourUsername\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin`
   - `C:\Users\YourUsername\AppData\Local\Programs\Python\Python312`
   - `C:\Users\YourUsername\AppData\Local\Programs\Python\Python312\Scripts`

5. Click OK on all dialogs

6. Restart PowerShell or any open terminals

#### Verification

Verify the installation by checking versions:

```powershell
gcc --version
python --version
meson --version
ninja --version
```

Expected output should show:
- GCC 15.x or later
- Python 3.12.x or later
- Meson 1.x or later
- Ninja 1.x or later

## Troubleshooting Environment Setup

### Windows: Finding Installation Paths

If you need to locate where WinGet installed tools:

**Find Python:**
```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python" -Recurse -Filter "python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
```

**Find Meson:**
```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA" -Recurse -Filter "meson.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
```

**Find GCC (MinGW):**
```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA" -Recurse -Filter "gcc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
```

### Windows: Command Not Found Errors

**"meson: command not found"**

Solution: Add Python Scripts directory to PATH:
```powershell
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312\Scripts;$env:PATH"
```

**"gcc: command not found"**

Solution: Add MinGW bin directory to PATH:
```powershell
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin;$env:PATH"
```

**"python: command not found"**

Solution: Add Python to PATH:
```powershell
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312;$env:PATH"
```

### Linux: Missing Dependencies

**json-c not found:**
```bash
# Ubuntu/Debian
sudo apt install libjson-c-dev

# Fedora/RHEL
sudo dnf install json-c-devel

# Arch
sudo pacman -S json-c
```

**OpenSSL not found:**
```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Arch
sudo pacman -S openssl
```

**Meson too old:**
```bash
# Install newer version via pip
pip3 install --user meson

# Add to PATH if needed
export PATH="$HOME/.local/bin:$PATH"
```

### Verifying Your Environment

After setup, verify all required tools are available:

**Linux:**
```bash
gcc --version
meson --version
ninja --version
pkg-config --version
```

**Windows:**
```powershell
gcc --version
python --version
meson --version
ninja --version
```

If any command fails, review the PATH setup instructions above.

## Next Steps

Once your environment is set up, proceed to [BUILD.md](BUILD.md) for instructions on configuring and building nvme-cli and libnvme.
