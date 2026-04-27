# nvme-cli — Project Guide for Claude

## Project overview

nvme-cli is the Linux command-line utility for NVM-Express (NVMe) SSDs. As of version 3.x, the libnvme library is fully integrated into this repository (not an external dependency, not a git submodule — the complete source lives in `libnvme/`). The project is dual-licensed: GPL-2.0-only for the CLI and plugins, LGPL-2.1-or-later for libnvme.

Current version: **3.0-a.3** (alpha). Installed to `/usr/local/sbin/nvme` by default.

---

## Repository layout

```
nvme.c                  Main CLI entry point + built-in command implementations (~11K lines)
nvme.h                  Top-level public header: nvme_args struct, print flags, NVME_ARGS macro
nvme-builtin.h          Registry of 118 built-in commands via ENTRY() macros
nvme-cmds.c/.h          NVMe command/response structs mirroring the spec
nvme-print-stdout.c     Human-readable output (~7K lines)
nvme-print-json.c       JSON output (~5.8K lines)
nvme-print-binary.c     Raw binary output
nvme-print.h            Print function declarations
nvme-models.c           Device model database
fabrics.c/h             NVMe-oF (Fabrics) implementation
plugin.c/h              Plugin loading, command dispatch, help system
logging.c/h             Logging infrastructure
util/                   argconfig, json wrapper, base64, crc32, suffix, table, cleanup, mem
plugins/                32 vendor plugins (see below)
libnvme/                Integrated libnvme library (NOT a submodule)
unit/                   C unit tests (argconfig, suffix, uint128)
tests/                  Python functional tests (real hardware)
Documentation/          Man pages in AsciiDoc format
scripts/                build.sh, release.sh, gen-hostnqn.sh
ccan/                   Embedded utility library
nvmf-autoconnect/       Systemd integration for NVMe-oF auto-connect
completions/            Shell completion files
.github/workflows/      12 CI workflows
```

---

## Build system (Meson)

```bash
meson setup .build              # Configure (default: debugoptimized)
meson compile -C .build         # Build
meson test -C .build            # Run unit tests
meson install -C .build         # Install

# Common option overrides
meson setup .build -Dplugins=intel,wdc,ocp   # Subset of plugins
meson setup .build -Ddocs=man                # Build man pages
meson setup .build -Db_sanitize=address      # AddressSanitizer
meson setup .build --default-library=static  # Static libnvme

# CI-style build (used by GitHub Actions)
./scripts/build.sh               # meson + ninja, default settings
./scripts/build.sh -c clang      # Use clang
./scripts/build.sh -b release    # Release build type

# Legacy Make wrapper (still supported)
make && make install
```

**Key meson_options.txt options:**

| Option | Default | Notes |
|--------|---------|-------|
| `nvme` | enabled | Build the nvme CLI binary |
| `libnvme` | enabled | Build libnvme |
| `fabrics` | enabled | NVMe-oF support; can disable for embedded/PCIe-only builds |
| `json-c` | auto | Required in practice for all plugins |
| `openssl` | auto | TLS/auth for NVMe-TCP (requires ≥3.0) |
| `keyutils` | auto | Key management for NVMe-oF auth |
| `plugins` | all | Comma-separated list or "all" |
| `docs` | false | man / html / rst / all |
| `tests` | true | Build unit tests |

Generated header `nvme-config.h` carries git version string, feature flags (`CONFIG_JSONC`, `CONFIG_OPENSSL`, etc.), and directory paths.

---

## Command and plugin architecture

### Built-in commands

`nvme-builtin.h` lists 118 built-in commands via the X-macro pattern:

```c
ENTRY("id-ctrl",    "Send NVMe Identify Controller",   id_ctrl)
ENTRY("smart-log",  "Retrieve SMART / Health Info log", smart_log)
// ...
```

The macro expands (in `cmd_handler.h`) through 4 passes to generate:
1. Function prototypes
2. `struct command` instances
3. `commands[]` array
4. Plugin `struct` + `__attribute__((constructor))` registration

Implementations live in `nvme.c` (most built-ins) and `nvme-cmds.c`.

### Vendor plugins

32 plugins under `plugins/<name>/`:

```
amzn  dapustor  dell  dera  fdp  feat  huawei  ibm  innogrit  inspur  intel
lm  mangoboost  memblaze  micron  nbft  netapp  nvidia  ocp  sandisk
scaleflux  seagate  sed  shannon  solidigm  ssstc  toshiba  transcend
virtium  wdc  ymtc  zns
```

Each plugin is two files:
- `{name}-nvme.h` — PLUGIN / COMMAND_LIST / ENTRY macro declarations
- `{name}-nvme.c` — `#define CREATE_CMD` then `#include "{name}-nvme.h"` + implementations

Plugins are linked statically (not dlopen). Each plugin's constructor calls `register_extension(&plugin)`.

Command callback signature:
```c
int cmd_func(int argc, char **argv, struct command *acmd, struct plugin *plugin);
```

### Adding a new built-in command

1. Add `ENTRY("name", "help text", function_name)` to `nvme-builtin.h`
2. Implement `static int function_name(int argc, char **argv, struct command *cmd, struct plugin *plugin)` in `nvme.c`
3. Declare local option struct, use `NVME_ARGS(opts, ...)` for standard args + extras
4. Call `argconfig_parse(argc, argv, desc, opts)` to parse
5. Use libnvme functions for device interaction
6. Use `nvme_print_*` / `json_*` for output

### Adding a vendor plugin

1. Create `plugins/{vendor}/{vendor}-nvme.h` — PLUGIN/COMMAND_LIST/ENTRY
2. Create `plugins/{vendor}/{vendor}-nvme.c` — `#define CREATE_CMD`, `#include "{vendor}-nvme.h"`, implementations
3. Add plugin name to `meson_options.txt` choices list
4. Add to `plugins/meson.build`

---

## Argument parsing (util/argconfig.h)

Options are declared as arrays of `struct argconfig_commandline_options` using macros:

```c
OPT_FLAG("verbose",      'v', &cfg.verbose,      "increase verbosity")
OPT_UINT("namespace-id", 'n', &cfg.namespace_id, "namespace identifier")
OPT_STRING("input-file", 'i', "FILE", &cfg.input_file, "input file path")
OPT_SUFFIX("data-len",   'z', &cfg.data_len,     "data length (supports suffixes)")
OPT_FMT("output-format", 'o', &cfg.output_format,"output format: normal|json|binary")
OPT_END()
```

The `NVME_ARGS(opts, ...)` macro auto-injects standard global options:
- **Before**: `--verbose`/`-v`, `--output-format`/`-o`
- **After**: `--timeout`, `--dry-run`, `--no-retries`, `--no-ioctl-probing`, `--output-format-version`

---

## Output / print flags

```c
enum nvme_print_flags {
    NORMAL  = 0,
    VERBOSE = 1 << 0,   // detailed field decoding
    JSON    = 1 << 1,   // JSON output
    VS      = 1 << 2,   // vendor-specific hex dump
    BINARY  = 1 << 3,   // raw binary
    TABULAR = 1 << 4,   // aligned table columns
};
```

Select output mode with `validate_output_format(cfg.output_format, &flags)`.

---

## Code style

- **Indentation**: tabs (kernel style, 8-space display)
- **Line length**: 80 characters max (enforced by `.checkpatch.conf`)
- **Brace style**: Linux kernel — same line for `if`/`for`/`while`, next line for functions
- **Naming**:
  - NVMe spec data layout types: `nvme_*`, `nvmf_*`
  - libnvme public API: `nvme_*` (lib functions), `nvmf_*` (fabrics)
  - CLI command functions: lowercase snake_case (`id_ctrl`, `smart_log`)
  - Macros: `UPPER_CASE`
- **Error handling**: return negative `errno` on error; use `nvme_strerror()` / `perror()`
- **No `.clang-format`** — kernel style by convention + checkpatch CI enforcement
- **Cleanup macros**: RAII-like cleanup via `__cleanup_*` macros in `util/cleanup.h`

---

## libnvme (integrated library)

`libnvme/` is **not** a git submodule — it is the full source, maintained in sync with nvme-cli. Key structure:

```
libnvme/src/nvme/
  types.h       NVMe spec-mirrored C types
  cmds.h        Command definitions + send functions
  lib.h         Public API (device tree, namespaces, paths)
  accessors.h   Auto-generated getters/setters (do not edit by hand)
  private.h     Internal structs (used by accessor generator)
  fabrics.h     NVMe-oF specific API
  ioctl.h       Raw IOCTL wrappers
libnvme/src/
  lib.c         Core implementation
  ioctl.c       IOCTL implementation
  fabrics.c     Fabrics/discovery implementation
  accessors.c   Auto-generated accessor implementations
libnvme/src/libnvme.ld      Hand-maintained ABI version script
libnvme/src/nvme/accessors.ld  Auto-generated accessor ABI version script
```

**Important**: `accessors.h` and `accessors.c` are generated — do not edit by hand. The generator lives in `libnvme/` tree (Python scripts). The CI workflow `check-accessors.yml` validates they are up to date.

**NVMe-oF footprint constraint**: The `fabrics` build option can be disabled for embedded/PCIe-only targets. Anything fabrics-specific must remain in `fabrics.c` / `nvmf-*` files, not bleed into core nvme.c.

---

## Testing

```bash
# Unit tests (fast, no hardware needed)
meson test -C .build
meson test -C .build --verbose

# Functional tests (real hardware, configured in tests/config.json)
cd tests && pytest

# CI containers (for reproducible builds)
# Images: ghcr.io/linux-nvme/{debian,fedora,tumbleweed}:latest
# Cross-build: ghcr.io/linux-nvme/ubuntu-cross-{target}:latest
```

Unit tests live in `unit/` (C). Functional tests live in `tests/` (Python/pytest).

---

## Documentation

Man pages are in `Documentation/` as AsciiDoc (`.txt`) files. Build with:

```bash
meson setup .build -Ddocs=man
meson compile -C .build
```

Each subcommand should have a corresponding `Documentation/nvme-{cmd}.txt`.
Plugin commands: `Documentation/nvme-{vendor}-{cmd}.txt`.

---

## CI

12 GitHub Actions workflows. Key ones:
- **build.yml** — matrix: Debian/Fedora/Tumbleweed × gcc/clang × debug/release
- **checkpatch.yml** — Linux kernel style (runs on every PR)
- **coverage.yml** — codecov integration
- **codeql.yml** — security scanning
- **check-accessors.yml** — validates accessor generation is current

Pre-built static binary: `https://monom.org/linux-nvme/upload/nvme-cli-latest-x86_64`

---

## Key files quick-reference

| File | Why it matters |
|------|---------------|
| `nvme.c` | Main implementation; start here for any built-in command |
| `nvme-builtin.h` | Command registry; ENTRY() macros → function names |
| `plugin.c` | Dispatch logic; how argv[1] resolves to a handler |
| `util/argconfig.h` | All OPT_* macros; how options are declared |
| `nvme.h` | nvme_args struct, NVME_ARGS macro, print flags |
| `nvme-print-stdout.c` | Human output; add new print functions here |
| `nvme-print-json.c` | JSON output counterpart |
| `libnvme/src/nvme/lib.h` | libnvme public API declarations |
| `libnvme/src/nvme/types.h` | Spec-mirrored NVMe data types |
| `meson.build` | Build targets, dependencies, version |
| `meson_options.txt` | All configurable build knobs |
| `CONTRIBUTING.md` | Conventions for new commands and plugins |
