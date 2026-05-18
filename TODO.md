# Windows Build TODO - Excluded Features and Plugins

This document tracks features and plugins that are currently excluded from the Windows build of nvme-cli, and remaining work items.

## Status Legend
- ❌ **Will likely never need Windows support** - Requires Linux-specific kernel/networking features
- ⚠️ **Low priority** - Limited use case on Windows
- ✅ **Implemented / Supported** - Working on Windows
- 🔧 **Should eventually be supported** - Would be useful on Windows with porting effort

---

## Windows Port Status

The Windows port is **substantially functional** as of May 2026. Core device I/O, device enumeration, device path translation, and the topology tree are all implemented. Most NVMe admin and I/O commands work via Windows StorNVMe IOCTLs.

### ✅ Implemented Core Functionality

| Component | Implementation | File(s) |
|-----------|---------------|---------|
| Device I/O (Admin + IO commands) | `IOCTL_STORAGE_QUERY/SET_PROPERTY`, `IOCTL_STORAGE_PROTOCOL_COMMAND`, `IOCTL_SCSI_PASS_THROUGH` | `libnvme/src/nvme/ioctl-win.c` |
| Device enumeration (`nvme list`) | SetupDI + CFGMGR32 APIs, StoragePort map | `libnvme/src/nvme/filters-win.c` |
| Device path translation | `nvmeX`, `nvmeXnY`, `\\.\PhysicalDriveN`, `\\?\...` paths | `libnvme/src/nvme/lib-win.c` |
| Topology tree scanning | Controller/subsystem/namespace discovery | `libnvme/src/nvme/tree-win.c` |
| Global context | `libnvme_create_global_ctx()` | `libnvme/src/nvme/lib.c` (cross-platform) |
| Dry run mode | `libnvme_set_dry_run()` | `libnvme/src/nvme/lib.c` (cross-platform) |
| ETDAS telemetry control | `libnvme_set_etdas()` / `libnvme_clear_etdas()` | `libnvme/src/nvme/nvme-cmds.c` (cross-platform) |
| Large page memory allocation | `VirtualAlloc` + large pages with fallback | `util/mem-windows.c` |
| Windows error → errno translation | `GetLastError()` mapping | `libnvme/src/nvme/ioctl-win.c` |

### ✅ Working Admin Commands

| Command | IOCTL Method |
|---------|--------------|
| Identify (Controller/NS) | `IOCTL_STORAGE_QUERY_PROPERTY` + `StorageAdapterProtocolSpecificProperty` |
| Get Log Page | `IOCTL_STORAGE_QUERY_PROPERTY` + `StorageDeviceProtocolSpecificProperty` |
| Get Features | `IOCTL_STORAGE_QUERY_PROPERTY` |
| Set Features | `IOCTL_STORAGE_SET_PROPERTY` (StorNVMe limits to FID 0x10) |
| FW Download | `IOCTL_STORAGE_FIRMWARE_DOWNLOAD` |
| FW Commit | `IOCTL_STORAGE_FIRMWARE_ACTIVATE` (all 4 commit actions) |
| Format NVM | `IOCTL_SCSI_PASS_THROUGH` (SES=1) / `IOCTL_STORAGE_REINITIALIZE_MEDIA` (SES=2) |
| Security Send/Receive | `IOCTL_SCSI_PASS_THROUGH` with SCSI Security Protocol CDB |
| Device Self-Test | `IOCTL_STORAGE_PROTOCOL_COMMAND` (passthru) |
| Sanitize | `IOCTL_STORAGE_PROTOCOL_COMMAND` (passthru) |
| NS Management/Attach | `IOCTL_STORAGE_PROTOCOL_COMMAND` (WinPE only) |
| Vendor-Specific (0xC0-0xFF) | `IOCTL_STORAGE_PROTOCOL_COMMAND` (passthru) |

### ✅ Working I/O Commands

| Command | Method |
|---------|--------|
| Read | `IOCTL_SCSI_PASS_THROUGH` + SCSI READ(16) CDB |
| Write | `IOCTL_SCSI_PASS_THROUGH` + SCSI WRITE(16) CDB |
| Flush | `IOCTL_SCSI_PASS_THROUGH` + SCSI SYNCHRONIZE CACHE |
| Compare | `IOCTL_STORAGE_PROTOCOL_COMMAND` (WinPE only) |
| Vendor-Specific IO (0x80-0xFF) | `IOCTL_STORAGE_PROTOCOL_COMMAND` (passthru) |

---

## Core Features Excluded

### ❌ NVMe over Fabrics (fabrics.c)
**Status:** Will likely never need Windows support  
**Reason:** Requires Linux kernel NVMe-oF implementation, networking stack, and sysfs

**Commands affected:**
- `nvme discover` - Discover NVMeoF subsystems
- `nvme connect` - Connect to NVMeoF subsystem
- `nvme connect-all` - Connect to all discovered subsystems
- `nvme disconnect` - Disconnect from NVMeoF subsystem
- `nvme disconnect-all` - Disconnect from all subsystems
- `nvme config` - Configuration of NVMeoF subsystems
- `nvme dim` - Discovery Information Management

**Current implementation:** Stub functions that print "not supported on Windows"

---

### ⚠️ RPMB (nvme-rpmb.c)
**Status:** Low priority  
**Reason:** Replay Protection Memory Block uses Linux kernel crypto API

**Commands affected:**
- `nvme rpmb` - RPMB operations

**Porting effort:** Would require Windows crypto API port  
**Current implementation:** Stub function in `windows-stubs.c` (`rpmb_cmd_option`)

---

### ❌ Controller/Subsystem Reset
**Status:** Will likely never need Windows support  
**Reason:** Windows does not expose NVMe reset through standard storage IOCTLs

**Functions affected:**
- `libnvme_reset_ctrl()` - returns `ENOTSUP`
- `libnvme_reset_subsystem()` - returns `ENOTSUP`

---

## Vendor Plugins Excluded from Windows

### 🔧 Huawei (plugins/huawei/huawei-nvme.c)
**Status:** Should eventually be supported  
**Reason:** Uses `scandir()`, `mkdir()` with mode parameter

**Porting requirements:**
- Replace `scandir()` with Windows directory enumeration
- `mkdir()` wrapper already available in `mkdir.h`

**Use case:** Useful for Huawei NVMe device users on Windows

---

### 🔧 NetApp (plugins/netapp/netapp-nvme.c)
**Status:** Should eventually be supported  
**Reason:** Uses `mkdir()` with mode parameter

**Porting requirements:**
- `mkdir()` wrapper already available in `mkdir.h`
- Verify no other Linux dependencies

**Use case:** Useful for NetApp NVMe device users on Windows

---

### 🔧 SanDisk (plugins/sandisk/)
**Status:** Should eventually be supported  
**Reason:** Uses `scandir()`, `mkdir()` with mode parameter

**Files:**
- `sandisk-nvme.c`
- `sandisk-utils.c`

**Porting requirements:**
- Replace `scandir()` with Windows directory enumeration
- `mkdir()` wrapper already available

**Use case:** Popular consumer NVMe devices, high value for Windows users

---

### ⚠️ ScaleFlux (plugins/scaleflux/sfx-nvme.c)
**Status:** Low priority  
**Reason:** Uses `linux/fs.h` for filesystem ioctls

**Porting requirements:**
- Replace Linux filesystem ioctls with Windows equivalents
- May require significant rework

**Use case:** Enterprise storage, less common on Windows workstations

---

### 🔧 WDC/Western Digital (plugins/wdc/)
**Status:** Should eventually be supported  
**Reason:** Uses `scandir()`, `mkdir()` with mode parameter, `linux/fs.h`

**Files:**
- `wdc-nvme.c`
- `wdc-utils.c`

**Porting requirements:**
- Replace `scandir()` with Windows directory enumeration
- Handle Linux filesystem ioctls (BLKGETSIZE, etc.)
- `mkdir()` wrapper already available

**Use case:** Popular consumer and enterprise NVMe devices, **high priority** for Windows

---

### 🔧 ZNS - Zoned Namespaces (plugins/zns/zns.c)
**Status:** Should eventually be supported  
**Reason:** Uses `linux/fs.h` for block device operations

**Porting requirements:**
- Replace Linux block device ioctls with Windows equivalents
- May require Windows NVMe driver support for ZNS

**Use case:** Zoned storage is emerging technology, useful for development/testing on Windows

---

### ❌ LM - Lossless Logger (plugins/lm/)
**Status:** Will likely never need Windows support  
**Reason:** Subdirectory plugin with heavy Linux dependencies

**Use case:** Appears to be Linux kernel/driver development focused

---

## Currently Enabled Plugins on Windows

### Always-built cross-platform plugins (20 total):
- ✅ amzn - Amazon vendor specific
- ✅ dapustor - DapuStor vendor specific
- ✅ dell - Dell vendor specific
- ✅ dera - Dera vendor specific
- ✅ fdp - Flexible Data Placement
- ✅ ibm - IBM vendor specific
- ✅ innogrit - Innogrit vendor specific
- ✅ inspur - Inspur vendor specific
- ✅ intel - Intel vendor specific
- ✅ mangoboost - MangoBoost vendor specific
- ✅ memblaze - Memblaze vendor specific
- ✅ micron - Micron vendor specific
- ✅ nvidia - NVIDIA vendor specific
- ✅ seagate - Seagate vendor specific
- ✅ shannon - Shannon vendor specific
- ✅ ssstc - SSSTC vendor specific
- ✅ toshiba - Toshiba vendor specific
- ✅ transcend - Transcend vendor specific
- ✅ virtium - Virtium vendor specific
- ✅ ymtc - YMTC vendor specific
- ✅ feat - NVMe feature extensions

### Conditionally-built plugins (require dependencies):
- ✅ ocp - OCP cloud SSD extensions (requires json-c)
- ✅ solidigm - Solidigm vendor specific (requires json-c)
- ⚠️ sed - SED Opal (requires `HAVE_SED_OPAL`)
- ❌ nbft - ACPI NBFT table extensions (requires fabrics, disabled on Windows)

---

## Porting Priority Recommendations

### High Priority (Popular consumer devices)
1. **WDC/Western Digital** - Very common consumer NVMe SSDs
2. **SanDisk** - Popular consumer NVMe SSDs (owned by WD)
3. **ZNS** - Emerging standard, useful for development

### Medium Priority
4. **Huawei** - Large vendor
5. **NetApp** - Enterprise storage

### Low Priority
6. **ScaleFlux** - Niche enterprise
7. **LM** - Development/debug tool

### Not Recommended
- **NVMe-oF (fabrics)** - Requires Linux kernel support
- **RPMB** - Requires crypto API port, limited use case

---

## Implementation Notes

### Completed Windows Compatibility Layer

The project uses per-header compatibility wrappers in `libnvme/src/nvme/`:

| Header | Functions Provided |
|--------|--------------------|
| `stdlib.h` | `posix_memalign()`, `reallocarray()`, `aligned_free` macro |
| `stdio.h` | `dprintf()`, `getline()`, `open_memstream()`, `close_memstream()` |
| `unistd.h` | `getpagesize()`, `fsync` → `_commit` |
| `signal.h` | `sigaction()` (simplified), `sigemptyset()` |
| `fcntl.h` | `O_BINARY` portability |
| `malloc.h` | `malloc_usable_size` → `_msize` |
| `endian.h` | `htobe16/32/64`, `htole16/32/64`, `le16/32/64toh` |
| `mkdir.h` | `mkdir(path, mode)` → `_mkdir(path)` |

**`localtime_r()`** is provided by MinGW via `-D_POSIX_THREAD_SAFE_FUNCTIONS` (set in meson.build).

**`scandir()`** is not needed for core functionality — `filters-win.c` reimplements device scanning using native Windows APIs (SetupDI/CFGMGR32). Some excluded plugins still depend on `scandir()`.

### Windows-Specific Source Files

| File | Description |
|------|-------------|
| `libnvme/src/nvme/ioctl-win.c` | NVMe IOCTL implementation (~1670 lines) |
| `libnvme/src/nvme/filters-win.c` | Device enumeration via SetupDI/CFGMGR32 (~870 lines) |
| `libnvme/src/nvme/filters-win.h` | StoragePort map API declarations |
| `libnvme/src/nvme/lib-win.c` | Device open/close, path translation (~250 lines) |
| `libnvme/src/nvme/tree-win.c` | Topology tree scanning (~330 lines) |
| `libnvme/src/nvme/windows-stubs.c` | Stubs for Linux-only functions (~290 lines) |
| `windows-stubs.c` | nvme-cli level stubs (RPMB) |
| `util/mem-windows.c` | `VirtualAlloc` large page memory allocation |

### Windows Build Dependencies

Libraries linked on Windows: `ws2_32`, `kernel32`, `bcrypt`, `setupapi`, `cfgmgr32`

### Still Needed for Full Plugin Support
- ⚠️ `scandir()` implementation for Windows (needed by huawei, sandisk, wdc plugins)
- ⚠️ Linux filesystem ioctl replacements - `BLKGETSIZE`, etc. (needed by wdc, scaleflux, zns plugins)
- ⚠️ Block device size detection on Windows

---

## How to Enable a Plugin

1. Check the plugin source for Linux-specific dependencies:
   ```bash
   grep -E "scandir|linux/fs.h|sys/sysinfo.h" plugins/<vendor>/*.c
   ```

2. Add necessary compatibility wrappers to the appropriate header in `libnvme/src/nvme/`

3. Move plugin from Linux-only section to cross-platform section in `plugins/meson.build`

4. Build and test:
   ```bash
   meson compile -C .build
   ```

---

## Testing on Windows

The Windows build:
- ✅ Compiles successfully (MSYS2 MinGW)
- ✅ Shows help and lists commands
- ✅ Device enumeration works (`nvme list`)
- ✅ Supported admin commands work (identify, get-feature, get-log, smart-log, etc.)
- ✅ I/O commands work (read, write, flush via SCSI translation)
- ⚠️ Firmware operations are implemented (download, commit). Testing needed.
- ⚠️ Vendor-specific passthrough commands are implemented. Testing needed.
- ⚠️ Device access requires administrator privileges
- ⚠️ Some commands are WinPE-only (NS management, compare)
- ⚠️ Unit tests excluded on Windows build

---

## Remaining Windows Stubs

### libnvme stubs (`libnvme/src/nvme/windows-stubs.c`)

All remaining stubs are for Linux-specific functionality with no Windows equivalent:

| Category | Stubbed Functions | Reason |
|----------|------------------|--------|
| TLS/PSK Key Management | `libnvme_export_tls_key*`, `libnvme_import_tls_key*`, `libnvme_insert_tls_key*`, `libnvme_generate_tls_key_identity*` | Linux keyring API |
| Keyring Operations | `libnvme_read_key`, `libnvme_lookup_keyring`, `libnvme_update_key`, `libnvme_revoke_tls_key`, `libnvme_scan_tls_keys`, `libnvme_describe_key_serial` | Linux keyctl |
| Crypto | `libnvme_gen_dhchap_key`, `libnvme_create_raw_secret` | Linux crypto API |
| Host Config | `libnvme_read_hostnqn`, `libnvme_generate_hostnqn` | No `/etc/nvme/hostnqn` on Windows |

### nvme-cli stubs (`windows-stubs.c`)

| Function | Reason |
|----------|--------|
| `rpmb_cmd_option` | RPMB not supported on Windows |

### tree-win.c stubs (return NULL/0)

| Function | Reason |
|----------|--------|
| `libnvme_get_subsys_attr` | No sysfs on Windows |
| `libnvme_get_path_attr` | No sysfs on Windows |
| `libnvme_get_attr` | No sysfs on Windows |
| `libnvme_ctrl_get_command_error_count` | No sysfs on Windows |
| `libnvme_ctrl_get_reset_count` | No sysfs on Windows |
| `libnvme_ctrl_get_reconnect_count` | No sysfs on Windows |
| `libnvme_init_ctrl` | Not needed (scan path handles init) |

---

## Remaining Work Items

### 🟡 IMPORTANT: Permissions and Security

**Status:** Not implemented  
**Priority:** HIGH

**Requirements:**
1. **Administrator/Elevated Privileges**
   - Direct device access requires admin rights on Windows
   - Should detect and warn if not elevated
   - Consider adding manifest for UAC elevation

2. **Error Handling**
   - Basic Windows error → errno translation is implemented
   - Could improve error messages for common permission-denied scenarios

---

### 🟢 NICE TO HAVE: Additional Improvements

**Priority:** LOW

1. **Windows-Specific Documentation**
   - Update man pages for Windows
   - Document device path format (`nvmeX`, `\\.\PhysicalDriveN`)
   - Document privilege requirements
   - Installation instructions for Windows

2. **Windows Installer**
   - MSI or MSIX package
   - Include libnvme DLL
   - Add to PATH automatically

3. **Unit Tests on Windows**
   - Currently excluded from Windows build
   - Would improve confidence in cross-platform correctness

---

## Summary of Remaining Work

| Component | Priority | Status |
|-----------|----------|--------|
| Plugin porting (WDC, SanDisk, ZNS) | 🟡 Medium | Blocked on `scandir()` / Linux ioctl replacements |
| Plugin porting (Huawei, NetApp) | 🟡 Medium | Blocked on `scandir()` |
| Admin privilege detection | 🟡 Medium | Not started |
| Windows documentation | 🟢 Low | Not started |
| Windows installer | 🟢 Low | Not started |
| Unit test support | 🟢 Low | Not started |

**Bottom Line:** The Windows port is **functional** for core NVMe operations. The major I/O layer, device enumeration, and path translation are all implemented. Remaining work is incremental: enabling more vendor plugins, improving user experience (privilege detection, documentation), and testing infrastructure.

---

Last updated: May 4, 2026
