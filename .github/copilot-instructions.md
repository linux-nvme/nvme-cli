# nvme-cli Codebase Guide for AI Agents

## Project Overview

nvme-cli is a cross-platform NVMe management utility (Linux/Windows) with an integrated libnvme library (v3.x+). The project uses Meson build system and supports an extensible plugin architecture for vendor-specific commands.

**Critical:** Starting with nvme-cli 3.x, libnvme is fully integrated into the source tree at `libnvme/` - there's no external dependency.

## Architecture

### Component Structure

- **nvme-cli** (`nvme.c`, `nvme-builtin.h`): Main CLI tool with built-in NVMe commands
- **libnvme** (`libnvme/src/nvme/`): Cross-platform NVMe library with OS-specific ioctl implementations
  - `ioctl.c` (Linux), `ioctl-windows.c` (Windows)
- **Plugins** (`plugins/*/`): Vendor-specific extensions (OCP, WDC, Intel, Solidigm, etc.)
- **Utilities** (`util/`): Shared helpers (argument parsing, formatting, cleanup)

### Command Registration Pattern

Commands use a macro-based registration system via `define_cmd.h`:

1. **Built-in commands** (`nvme-builtin.h`):
   ```c
   COMMAND_LIST(
       ENTRY("list", "List all NVMe devices", list)
       ENTRY("id-ctrl", "Send Identify Controller", id_ctrl)
   )
   ```

2. **Plugin commands** (e.g., `plugins/ocp/ocp-nvme.h`):
   ```c
   PLUGIN(NAME("ocp", "OCP cloud SSD extensions", OCP_PLUGIN_VERSION),
       COMMAND_LIST(
           ENTRY("smart-add-log", "Retrieve extended SMART", smart_add_log)
       )
   )
   ```

Commands are invoked as: `nvme <command>` (built-in) or `nvme <plugin> <command>` (plugin).

### Cross-Platform Abstraction

- **Platform detection**: Use Meson's `build_machine.system()` checks
- **OS-specific code**: Separate implementations in `libnvme/src/nvme/ioctl-*.c`
- **Windows quirks**: 
  - Network libraries (ws2_32, wsock32, iphlpapi) auto-linked on Windows
  - Linux-only features (json-c, liburing, keyutils) auto-disabled on Windows

## Build System (Meson)

### Standard Build Commands

**Linux:**
```bash
meson setup .build
meson compile -C .build
meson install -C .build
```

**Windows (MSYS2):**
```bash
meson setup .build
meson compile -C .build
meson install -C .build
```

**Windows (PowerShell):**
```powershell
meson setup .build
meson compile -C .build
```

### Key Build Options

- `-Dnvme=enabled|disabled` - Build nvme CLI (default: enabled)
- `-Dlibnvme=enabled|disabled` - Build libnvme library (default: enabled)
- `-Dtests=true|false` - Build tests (default: true)
- `-Ddefault_library=static|shared` - Library type
- `-Djson-c=enabled|auto|disabled` - JSON support (required for plugins on Linux)

**Important:** Disabling json-c on Linux disables all plugins.

### Build Configurations

See `scripts/build.sh` for CI configurations:
- `scripts/build.sh` - Default build
- `scripts/build.sh fallback` - Download all dependencies
- `scripts/build.sh static` - Static binary
- `scripts/build.sh libnvme` - libnvme only

## Development Workflows

### Adding a New Built-in Command

1. Add `ENTRY()` to `nvme-builtin.h`
2. Implement callback in `nvme.c`:
   ```c
   static int my_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
   ```
3. Use `argconfig` for option parsing (see existing commands)
4. Return 0 on success, errno on failure

### Adding a Plugin Command

1. Create plugin header in `plugins/<vendor>/<vendor>-nvme.h`:
   ```c
   #undef CMD_INC_FILE
   #define CMD_INC_FILE plugins/<vendor>/<vendor>-nvme
   
   PLUGIN(NAME("<vendor>", "Description", VERSION),
       COMMAND_LIST(
           ENTRY("cmd-name", "Description", callback_fn)
       )
   )
   #include "define_cmd.h"
   ```
2. Implement commands in `plugins/<vendor>/<vendor>-nvme.c`
3. Update `plugins/meson.build` to include new plugin

### Testing

Python-based tests in `tests/`:
- Test framework: `nvme_test.py`, `nvme_test_logger.py`
- Run with: `meson test -C .build` or `pytest tests/`
- Tests require real NVMe hardware (controlled by `-Dnvme-tests=true`)

### Windows Development

You're currently working on Windows implementation (`libnvme/src/nvme/ioctl-windows.c`). Key points:

- Use Windows API: `DeviceIoControl()`, `CreateFile()`, etc.
- Convert Windows errors to errno with helper functions
- Many Linux features unsupported: reset, rescan, io_uring
- Test using MinGW builds

## Code Conventions

### Coding Style

**Follow Linux kernel coding style** for all code contributions:

- **Indentation**: Use tabs (not spaces) for indentation, with 8-character tab stops
- **Line length**: Should not exceed 80 characters with 8-space tabs if possible. This is a soft guideline - readability takes priority, with a hard limit of 100 columns for code.
- **Bracing**: K&R style - opening brace on same line, closing brace on new line. For conditional statements with single instructions in all branches, do not use braces.
  ```c
  // Multiple statements - use braces
  if (condition) {
      do_something();
      do_another_thing();
  } else {
      do_something_else();
  }
  
  // Single statement in all branches - no braces
  if (condition)
      do_something();
  else
      do_something_else();
  ```
- **Naming**: 
  - Functions/variables: lowercase with underscores (`get_smart_log`, `namespace_id`)
  - Macros/constants: uppercase with underscores (`NVME_LOG_PAGE_SIZE`)
  - Struct members: lowercase with underscores
- **Spacing**: Space after keywords (`if (`, `while (`), no space for function calls (`func(`)
- **Pointer declarations**: Attach asterisk to type name, not variable name: `type *name` not `type* name`
  ```c
  int *ptr;           // Correct
  char *str;          // Correct
  void *user_data;    // Correct
  int* ptr;           // Wrong
  ```
- **Comments**: Follow these conventions:
  - **Multi-line block comments**: Use Linux kernel style with `/* */` wrapper and ` * ` prefix:
    ```c
    /*
     * This is a multi-line comment explaining something
     * with important details across multiple lines.
     */
    ```
  - **Single-line standalone comments**: Use `/* */` format: `/* Single line comment */`
  - **Inline comments** (end-of-line): Use `/* */` format: `/* Inline comment */`
  - **TODO comments**: Use C++ style: `// TODO: description`
  - **SPDX license headers**: Use C++ style: `// SPDX-License-Identifier: ...`
- **Type declarations**: Prefer kernel types (`__u32`, `__le16`) for hardware structures

See the Linux kernel [coding style documentation](https://www.kernel.org/doc/html/latest/process/coding-style.html) for complete details.

### Commit Messages

Follow Linux kernel style:
```
<area>: <short description>

<detailed description>

Signed-off-by: Name <email>
```

Examples: `nvme: fix buffer overflow`, `ocp: add latency monitor log`

### Error Handling

- Return 0 on success, negative errno on failure
- Use `nvme_status_to_errno()` for NVMe status codes
- Log errors with `nvme_show_error()` or `perror()`

### Memory Management

- Use cleanup attributes for auto-cleanup: `_cleanup_(nvme_free_tree)`, `_cleanup_free_`
- Defined in `util/cleanup.h`
- Example: `_cleanup_free_ char *buf = malloc(size);`

### Licensing

- nvme-cli: GPL-2.0-or-later (some files GPL-2.0-only)
- libnvme: LGPL-2.1-or-later
- Always include SPDX header: `// SPDX-License-Identifier: GPL-2.0-or-later`

## Key Files Reference

- `nvme.c` (11k lines) - Main CLI implementation
- `nvme-builtin.h` - Built-in command registry
- `define_cmd.h` - Command macro magic
- `plugin.c`, `plugin.h` - Plugin infrastructure
- `ENVIRONMENT.md` - Dependency setup guide
- `meson.build` - Root build configuration

## Common Pitfalls

1. **Plugins disabled**: Check if json-c is enabled on Linux builds
2. **Test failures**: Tests require real NVMe hardware and `-Dnvme-tests=true`
3. **libnvme not found**: In 3.x+, libnvme is integrated - don't install separately
4. **Wrong command invocation**: Plugins use `nvme <plugin> <cmd>`, not `nvme <cmd>`