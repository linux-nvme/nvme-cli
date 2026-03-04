# Windows Port README

This document outlines some of the design choices and strategies used during the development of Windows support.

## Windows support strategy using MinGW

The mingw-w64 libraries and tools were chosen for the design to provide a more straightforward port to Windows, taking advantage of its headers and libraries and the GNU toolchain, including the gcc compiler. Benefits from this approach include faster turnaround, toolchain compatibility, and fewer code changes, which will help the code be more maintainable.

Installation and configuration of mingw and other tools such as meson, python, perl, and OpenSSL is described in [ENVIRONMENT.md](ENVIRONMENT.md). Meson build configuration is the same on Windows as on Linux.

## Windows build configuration support

The Meson build configuration files have been updated to detect the platform, and configure the build accordingly. Configuration options remain unchanged. On Windows builds, some features are flagged as not supported, and some files are not yet included in the build.

## Platform-specific includes

To reduce preprocessor checks for `_WIN32` throughout the codebase, common platform-specific includes, type definitions, and utility functions are centralized in `platform/linux.h` and `platform/windows.h` under libnvme. Code can include `platform/include.h`, which includes the appropriate platform header based on the target platform.

Some methods, macros, and types used throughout the code lack direct Windows equivalents. Windows-specific implementations and definitions have been added to `platform/windows.h` and `platform/windows.c`.

For types defined by `linux/types.h` on Linux, a new `platform/types.h` was created to define equivalent types for Windows. On Linux, `platform/types.h` simply includes `linux/types.h`. All project includes of `linux/types.h` have been replaced with `platform/types.h`.

## Stubs for currently unsupported methods

To allow compilation while some features remain unsupported on Windows, `windows-stubs.c` files contain stubbed implementations of unsupported methods. As support is added, these stubs are removed. These stub files are temporary and will be phased out as development progresses.

The Meson build configurations determine whether to build using the windows-stub.c files or the standard implementation files based on the target platform.

## Platform-specific method implementation

Many existing implementations work for both Linux and Windows. When platform-specific implementations are needed, we follow this pattern:

- **Header files (.h)**: Method declarations remain unchanged and platform-agnostic.
- **Windows implementations (filename-windows.c)**: Platform-specific implementations for Windows are placed in files following the naming convention `filename-windows.c` (for example, `ioctl-windows.c`).
- **Platform-agnostic implementations**: Code that works on both Linux and Windows remains in the existing `.c` file.
- **Linux-specific implementations**: Linux-only code remains in the existing `.c` file within `#ifndef _WIN32` guards. Eventually, we plan to extract these into separate `filename-linux.c` files. For now, keeping them inline simplifies upstream merging and ensures we don't miss method updates from the main project.
- **Build configuration**: The Meson build configuration determines which implementation files to include in the build based on the target platform.

Some Windows methods behave differently than their Linux counterparts and require project-specific implementations. Examples include `fstat` and `free`. We created wrapper methods such as `nvme_fstat` and `nvme_free` with platform-specific implementations to provide platform-agnostic interfaces throughout the codebase.

### The linux.h / linux.c exception

The files `nvme/linux.h` and `nvme/linux.c` present a problem for the pattern described above. Although the file names suggests that the methods they implement are Linux-specific, they are actually utility methods that are needed for both Linux and Windows implementations, and many of the existing implementations are compitible with Windows using MinGW. For now, a new file named `nvme/windows.c` contains the Windows-specific implementations of methods declared in `nvme/linux.h`, breaking with the pattern. Re-evaluation of the linux.h / linux.c names is needed.