# Build Guide for nvme-cli

This document provides instructions for building nvme-cli and libnvme on both Linux and Windows platforms.

> **Prerequisites:** Before building, ensure your environment is properly set up by following the instructions in [ENVIRONMENT.md](ENVIRONMENT.md).

## Table of Contents

- [Build Configuration Options](#build-configuration-options)
- [Building libnvme](#building-libnvme)
- [Building nvme-cli](#building-nvme-cli)
- [Common Build Scenarios](#common-build-scenarios)
- [Reconfiguring](#reconfiguring-an-existing-build)
- [Troubleshooting](#troubleshooting)

## Meson Options

Key options available via `-D<option>=<value>`:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `nvme` | enabled/disabled/auto | enabled | Build nvme executable |
| `libnvme` | enabled/disabled/auto | enabled | Build libnvme library |
| `default_library` | static/shared/both | shared | Library build type |
| `tests` | true/false | true | Build tests |
| `nvme-tests` | true/false | false | Run tests against real hardware |
| `docs` | false/html/man/rst/all | false | Install documentation |
| `docs-build` | true/false | false | Build documentation |
| `examples` | true/false | true | Build examples |
| `python` | enabled/disabled/auto | auto | Build Python bindings |
| `json-c` | enabled/disabled/auto | auto | JSON support (Linux only) |
| `openssl` | enabled/disabled/auto | auto | OpenSSL support |
| `keyutils` | enabled/disabled/auto | auto | Keyutils support (Linux only) |
| `libdbus` | enabled/disabled/auto | disabled | DBus support (Linux only) |
| `liburing` | enabled/disabled/auto | disabled | io_uring support (Linux only) |
| `version-tag` | string | (auto-detected) | Override version (required on Windows with MinGW to avoid bash dependency) |

**Important for Windows:** When using MinGW on Windows, always specify `-Dversion-tag=<version>` (e.g., `-Dversion-tag=3.0-a.1`) to bypass a bash script that detects the git version. Without this option, the build will fail in PowerShell environments.

### Common Configuration Patterns

#### Minimal Build (libnvme only, no tests, no docs)

**Linux:**
```bash
meson setup .build \
    -Dnvme=disabled \
    -Dlibnvme=enabled \
    -Dtests=false \
    -Ddocs=false \
    -Ddocs-build=false \
    -Dexamples=false
```

**Windows (PowerShell):**
```powershell
meson setup .build `
    -Dnvme=disabled `
    -Dlibnvme=enabled `
    -Dtests=false `
    -Ddocs=false `
    -Ddocs-build=false `
    -Dexamples=false `
    -Dversion-tag=3.0-a.1
```

#### Full Featured Build
```bash
meson setup .build \
    -Djson-c=enabled \
    -Dopenssl=enabled \
    -Dkeyutils=enabled \
    -Dtests=true \
    -Ddocs-build=true
```

#### Static Library Build
```bash
meson setup .build -Ddefault_library=static
```

#### Dynamic Library Build
```bash
meson setup .build -Ddefault_library=shared
```

## Building libnvme

Starting with nvme-cli 3.x, libnvme is fully integrated into the nvme-cli source tree. There is no separate repository or external dependency.

### Basic libnvme Build

Build libnvme only (without nvme-cli, tests, or documentation):

**Linux:**
```bash
# Configure
meson setup .build \
    -Dnvme=disabled \
    -Dlibnvme=enabled \
    -Dtests=false \
    -Ddocs=false \
    -Ddocs-build=false \
    -Dexamples=false

# Build
meson compile -C .build

# Install (optional)
sudo meson install -C .build
```

**Windows (PowerShell with MinGW):**
```powershell
# Set PATH (adjust paths if needed)
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312\Scripts;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312;$env:PATH"

# Configure
meson setup .build `
    -Dnvme=disabled `
    -Dlibnvme=enabled `
    -Dtests=false `
    -Ddocs=false `
    -Ddocs-build=false `
    -Dexamples=false `
    -Dversion-tag=3.0-a.1

# Build
meson compile -C .build

# Install (optional, requires admin privileges)
meson install -C .build
```

### Static Build

To build libnvme as a static library:

```bash
meson setup .build \
    -Ddefault_library=static \
    -Dnvme=disabled \
    -Dlibnvme=enabled \
    -Dtests=false \
    -Ddocs=false \
    -Ddocs-build=false
    
meson compile -C .build
```

The static library will be located at: `.build/libnvme/src/libnvme.a` (Linux) or `.build/libnvme/src/libnvme.lib` (Windows)

### Dynamic Build

To build libnvme as a shared library:

```bash
meson setup .build \
    -Ddefault_library=shared \
    -Dnvme=disabled \
    -Dlibnvme=enabled \
    -Dtests=false \
    -Ddocs=false \
    -Ddocs-build=false
    
meson compile -C .build
```

The shared library will be located at: 
- Linux: `.build/libnvme/src/libnvme.so.<version>`
- Windows: `.build/libnvme/src/libnvme.dll`

### Without Tests

To skip building tests (recommended for production builds):

```bash
meson setup .build \
    -Dtests=false \
    -Dnvme-tests=false
    
meson compile -C .build
```

### Without Documentation

To skip building documentation:

```bash
meson setup .build \
    -Ddocs=false \
    -Ddocs-build=false
    
meson compile -C .build
```

### With Specific Dependencies

#### Linux with JSON and OpenSSL
```bash
meson setup .build \
    -Djson-c=enabled \
    -Dopenssl=enabled \
    -Dkeyutils=enabled
    
meson compile -C .build
```

#### Windows with OpenSSL
```bash
meson setup .build -Dopenssl=enabled
meson compile -C .build
```

## Building nvme-cli

To build the complete nvme-cli tool (includes libnvme):

### Linux

```bash
# Configure with all features
meson setup .build

# Or minimal configuration
meson setup .build \
    -Djson-c=disabled \
    -Dopenssl=disabled \
    -Dtests=false \
    -Ddocs=false

# Build
meson compile -C .build

# Install
sudo meson install -C .build
```

### Windows

```bash
# Configure (in Visual Studio Developer Command Prompt)
meson setup .build

# Build
meson compile -C .build

# Install (requires admin privileges)
meson install -C .build
```

## Common Build Scenarios

### Scenario 1: Development Build (Linux)

Quick build for development with all features:

```bash
meson setup .build -Dbuildtype=debug
meson compile -C .build
```

### Scenario 2: Release Build (Linux)

Optimized build for production:

```bash
meson setup .build \
    -Dbuildtype=release \
    -Ddefault_library=shared \
    -Djson-c=enabled \
    -Dopenssl=enabled
    
meson compile -C .build
sudo meson install -C .build
```

### Scenario 3: Static Binary (Linux)

Single static binary with no dependencies:

```bash
meson setup .build \
    -Ddefault_library=static \
    -Dbuildtype=release \
    -Djson-c=disabled \
    -Dopenssl=disabled
    
meson compile -C .build
```

Or use the Makefile wrapper:
```bash
make static
```

### Scenario 4: Cross-Compilation (Linux)

For embedded systems or different architectures:

```bash
# Create a cross-file (e.g., arm64-cross.txt)
# Then configure with cross-file
meson setup .build --cross-file arm64-cross.txt

meson compile -C .build
```

Example using the build script:
```bash
./scripts/build.sh -b release -c gcc -t aarch64 cross
```

### Scenario 5: Windows DLL Build

Build shared library on Windows:

```bash
meson setup .build -Ddefault_library=shared
meson compile -C .build
```

### Scenario 6: CI/Testing Build

For continuous integration or testing:

```bash
meson setup .build \
    -Dtests=true \
    -Dexamples=true \
    -Dwarn_level=3
    
meson compile -C .build
meson test -C .build
```

## Reconfiguring an Existing Build

To change configuration options without starting over:

```bash
# View current configuration
meson configure .build

# Change specific options
meson configure .build -Dtests=false -Ddocs=false

# Rebuild with new configuration
meson compile -C .build
```

## Cleaning Build Directory

```bash
# Clean build artifacts (keeps configuration)
ninja -C .build clean

# Or completely remove build directory
rm -rf .build
```

## Troubleshooting

### Dependency Not Found

If meson reports a missing dependency:

1. Check if it's optional and can be disabled:
   ```bash
   meson setup .build -D<dependency>=disabled
   ```

2. Install the dependency using your package manager

3. Set `PKG_CONFIG_PATH` if installed in non-standard location:
   ```bash
   export PKG_CONFIG_PATH=/path/to/pkgconfig:$PKG_CONFIG_PATH
   ```

### Windows-Specific Issues

#### "bash command not found" or Script Execution Errors

**Problem:** Meson tries to execute a bash script to detect the git version, failing with:
```
ERROR: Command `bash C:\Users\...\scripts/meson-vcs-tag.sh ...` failed
```

**Solution:** Always specify the `-Dversion-tag` option when configuring:
```powershell
meson setup .build -Dversion-tag=3.0-a.1 [other options...]
```

#### "meson: command not found"

**Problem:** Meson is not in the PATH.

**Solution:** Set the PATH to include Python and Scripts directories:
```powershell
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312\Scripts;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312;$env:PATH"
```

Or locate meson using:
```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python" -Recurse -Filter "meson.exe" | Select-Object -First 1 -ExpandProperty FullName
```

#### "gcc: command not found"

**Problem:** MinGW GCC is not in the PATH.

**Solution:** Add MinGW to PATH. First, locate the installation:
```powershell
Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter "*WinLibs*" -Directory
```

Then add to PATH:
```powershell
$env:PATH = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin;$env:PATH"
```

#### Setting PATH Permanently on Windows

To avoid setting PATH every time:

1. Open System Properties:
   - Press `Win + X` → System → Advanced system settings
   - Or search for "Environment Variables" in Start Menu

2. Click "Environment Variables"

3. Under "User variables", select "Path" and click "Edit"

4. Click "New" and add these paths (adjust as needed):
   - `C:\Users\YourUsername\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin`
   - `C:\Users\YourUsername\AppData\Local\Programs\Python\Python312`
   - `C:\Users\YourUsername\AppData\Local\Programs\Python\Python312\Scripts`

5. Click OK on all dialogs and restart PowerShell

### General Build Issues

### Minimal Build Requirements

If you have limited dependencies, use this minimal configuration:

```bash
meson setup .build \
    -Dnvme=disabled \
    -Dlibnvme=enabled \
    -Dtests=false \
    -Ddocs=false \
    -Ddocs-build=false \
    -Dexamples=false \
    -Djson-c=disabled \
    -Dopenssl=disabled \
    -Dkeyutils=disabled \
    -Dlibdbus=disabled \
    -Dliburing=disabled
```

## Additional Resources

- Main README: [README.md](README.md)
- Meson documentation: https://mesonbuild.com/
- libnvme documentation: `libnvme/doc/`
- GitHub Actions CI examples: `.github/workflows/`
