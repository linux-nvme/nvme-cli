# Windows Build TODO - Excluded Features and Plugins

This document tracks features and plugins that are currently excluded from the Windows build of nvme-cli.

## Status Legend
- ❌ **Will likely never need Windows support** - Requires Linux-specific kernel/networking features
- ⚠️ **Low priority** - Limited use case on Windows
- ✅ **Should eventually be supported** - Would be useful on Windows with porting effort

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
**Current implementation:** Stub function that prints "not supported on Windows"

---

## Vendor Plugins Excluded

### ✅ Huawei (plugins/huawei/huawei-nvme.c)
**Status:** Should eventually be supported  
**Reason:** Uses `scandir()`, `mkdir()` with mode parameter

**Porting requirements:**
- Replace `scandir()` with Windows equivalent (FindFirstFile/FindNextFile)
- Handle `mkdir()` mode parameter (already have wrapper in win-compat.h)

**Use case:** Useful for Huawei NVMe device users on Windows

---

### ✅ IBM (plugins/ibm/ibm-nvme.c)
**Status:** Should eventually be supported  
**Reason:** Uses `localtime_r()`, `mkdir()` with mode parameter

**Porting requirements:**
- Replace `localtime_r()` with `localtime_s()` (Windows equivalent)
- Handle `mkdir()` mode parameter

**Use case:** Useful for IBM NVMe device users on Windows

---

### ✅ NetApp (plugins/netapp/netapp-nvme.c)
**Status:** Should eventually be supported  
**Reason:** Uses `mkdir()` with mode parameter

**Porting requirements:**
- Handle `mkdir()` mode parameter (already have wrapper)
- Verify no other Linux dependencies

**Use case:** Useful for NetApp NVMe device users on Windows

---

### ✅ SanDisk (plugins/sandisk/)
**Status:** Should eventually be supported  
**Reason:** Uses `scandir()`, `mkdir()` with mode parameter

**Files:**
- `sandisk-nvme.c`
- `sandisk-utils.c`

**Porting requirements:**
- Replace `scandir()` with Windows directory enumeration
- Handle `mkdir()` mode parameter

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

### ✅ WDC/Western Digital (plugins/wdc/)
**Status:** Should eventually be supported  
**Reason:** Uses `scandir()`, `mkdir()` with mode parameter, `linux/fs.h`

**Files:**
- `wdc-nvme.c`
- `wdc-utils.c`

**Porting requirements:**
- Replace `scandir()` with Windows directory enumeration
- Handle Linux filesystem ioctls (BLKGETSIZE, etc.)
- Replace `mkdir()` mode handling

**Use case:** Popular consumer and enterprise NVMe devices, **high priority** for Windows

---

### ⚠️ YMTC (plugins/ymtc/ymtc-nvme.c)
**Status:** Low priority  
**Reason:** Uses `mkdir()` with mode parameter

**Porting requirements:**
- Handle `mkdir()` mode parameter (already have wrapper)

**Use case:** Chinese market primarily, lower Windows user base

---

### ✅ ZNS - Zoned Namespaces (plugins/zns/zns.c)
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

**Porting requirements:**
- Unknown - would need investigation
- Likely uses sysfs, Linux-specific logging

**Use case:** Appears to be Linux kernel/driver development focused

---

## Currently Enabled Plugins (19 total)

These plugins work on Windows:
- ✅ amzn - Amazon vendor specific
- ✅ dapustor - DapuStor vendor specific
- ✅ dell - Dell vendor specific
- ✅ dera - Dera vendor specific
- ✅ fdp - Flexible Data Placement
- ✅ innogrit - Innogrit vendor specific
- ✅ inspur - Inspur vendor specific
- ✅ intel - Intel vendor specific
- ✅ mangoboost - MangoBoost vendor specific
- ✅ memblaze - Memblaze vendor specific
- ✅ **micron - Micron vendor specific** (enabled with mkdir wrapper)
- ✅ nbft - ACPI NBFT table extensions
- ✅ nvidia - NVIDIA vendor specific
- ✅ ocp - OCP cloud SSD extensions
- ✅ feat - NVMe feature extensions  
- ✅ seagate - Seagate vendor specific
- ✅ shannon - Shannon vendor specific
- ✅ ssstc - SSSTC vendor specific
- ✅ toshiba - Toshiba vendor specific
- ✅ transcend - Transcend vendor specific
- ✅ virtium - Virtium vendor specific

---

## Porting Priority Recommendations

### High Priority (Popular consumer devices)
1. **WDC/Western Digital** - Very common consumer NVMe SSDs
2. **SanDisk** - Popular consumer NVMe SSDs (owned by WD)
3. **ZNS** - Emerging standard, useful for development

### Medium Priority
4. **IBM** - Enterprise users
5. **Huawei** - Large vendor
6. **NetApp** - Enterprise storage

### Low Priority
7. **YMTC** - Regional market focus
8. **ScaleFlux** - Niche enterprise
9. **LM** - Development/debug tool

### Not Recommended
- **NVMe-oF (fabrics)** - Requires Linux kernel support
- **RPMB** - Requires crypto API port, limited use case

---

## Implementation Notes

### Completed Compatibility Additions
- ✅ `win-compat.h/c` - Windows compatibility layer
- ✅ `mkdir(path, mode)` macro - Redirects to `_mkdir(path)`
- ✅ `getline()`, `strsep()`, `reallocarray()` implementations
- ✅ `gmtime_r()` wrapper using `gmtime_s()`
- ✅ `dirent.h` emulation (opendir, readdir, closedir)
- ✅ mmap/munmap stubs
- ✅ Signal handling compatibility (sigaction, sigemptyset)

### Still Needed for Full Plugin Support
- ⚠️ `scandir()` implementation for Windows
- ⚠️ `localtime_r()` wrapper using `localtime_s()`
- ⚠️ Linux filesystem ioctl replacements (BLKGETSIZE, etc.)
- ⚠️ Block device size detection on Windows

---

## How to Enable a Plugin

1. Check the plugin source for Linux-specific dependencies:
   ```bash
   grep -E "scandir|localtime_r|linux/fs.h|sys/sysinfo.h" plugins/<vendor>/*.c
   ```

2. Add necessary compatibility wrappers to `win-compat.h`

3. Move plugin from Linux-only section to cross-platform section in `plugins/meson.build`

4. Build and test:
   ```bash
   meson compile -C .build
   ```

---

## Testing on Windows

Currently, testing is limited without physical NVMe devices. The Windows build:
- ✅ Compiles successfully
- ✅ Shows help and lists commands
- ⚠️ Cannot test actual device operations without Windows NVMe devices
- ⚠️ Device access requires Windows NVMe driver and proper permissions

---

Last updated: January 23, 2026

---

## Potentially Implementable Stub Functions

This section lists stub functions in `libnvme/src/nvme/windows-stubs.c` that could be implemented with reasonable effort **if device I/O is implemented**. These are separate from the Critical Missing Functionality below, which blocks all device operations.

### ✅ Easy - Simple Data Structures (30 minutes effort)

**`nvme_create_global_ctx()`** - Global context allocation
- Current: Returns NULL
- Needed: Allocate `nvme_global_ctx` structure, initialize log level, return pointer
- Use case: Required by many commands for configuration/logging
- Implementation: ~50 lines, mostly struct initialization
- Dependencies: None

**`nvme_set_dry_run()`** - Dry run mode flag
- Current: No-op stub
- Needed: Set flag in global context: `ctx->dry_run = enable;`
- Use case: Testing commands without actual hardware changes
- Implementation: 1 line
- Dependencies: Requires `nvme_create_global_ctx()` first

**`nvme_set_etdas()` / `nvme_clear_etdas()`** - Telemetry flags
- Current: Return -ENOTSUP
- Needed: Set/clear flags in global context
- Use case: Telemetry data collection control
- Implementation: 2-3 lines each
- Dependencies: Requires `nvme_create_global_ctx()` first

### ⚠️ Medium - Requires Windows APIs (4-8 hours effort)

**`nvmf_hostnqn_generate()`** - Host NQN generation
- Current: Returns NULL
- Needed: Generate UUID-based host NQN using Windows `UuidCreate()` API
- Use case: Host identification for some NVMe commands (may be needed even without fabrics)
- Implementation: ~30 lines
  ```c
  // Use Windows RPC API
  UUID uuid;
  UuidCreate(&uuid);
  UuidToStringA(&uuid, &uuid_str);
  asprintf(&hostnqn, "nqn.2014-08.org.nvmexpress:uuid:%s", uuid_str);
  RpcStringFreeA(&uuid_str);
  return hostnqn;
  ```
- Dependencies: Link against `rpcrt4.lib`
- Note: Linux version tries DMI/device-tree first, Windows can just use random UUID

**`nvmf_hostnqn_generate_from_hostid()`** - Format host NQN from UUID
- Current: Returns NULL
- Needed: Format provided UUID into NQN string
- Use case: Creates standardized host identifier
- Implementation: ~10 lines (just string formatting)
- Dependencies: None (pure string manipulation)

### ❌ NOT Implementable - Require Linux Kernel Features

**Fabrics Operations** - All require Linux NVMe-oF kernel driver:
- `nvmf_add_ctrl()`, `nvmf_get_discovery_log()`, `nvmf_connect_*()`, etc.
- These will NEVER work on Windows without kernel NVMe-oF support

**Fabrics String Converters** - Pointless without fabrics:
- `nvmf_trtype_str()`, `nvmf_adrfam_str()`, `nvmf_sectype_str()`, etc.
- These only format fabrics discovery/connection information
- No fabrics = no use for these functions

**Tree/Topology Functions** - Require Linux sysfs:
- `nvme_scan_topology()`, `nvme_create_root()`, `nvme_free_tree()`
- Windows has no sysfs equivalent
- Path properties (NUMA, queue depth) also depend on sysfs

**Keyring/TLS Functions** - Require Linux keyctl:
- `nvme_read_key()`, `nvme_lookup_keyring()`, `nvme_insert_tls_key_*()`, etc.
- Windows Credential Manager is completely different architecture

**NBFT Functions** - Fabrics boot table (fabrics-specific):
- `nvmf_nbft_read_files()`, `nvmf_nbft_free()`
- Only used for NVMe-oF boot, not applicable to Windows

### Summary

**Worth implementing (if device I/O works):**
- ✅ `nvme_create_global_ctx()` - Essential for most commands
- ✅ `nvme_set_dry_run()` - Testing support
- ✅ `nvme_set_etdas()` / `nvme_clear_etdas()` - Telemetry control
- ⚠️ `nvmf_hostnqn_generate*()` - May be needed for host identification (2 functions)

**Total effort:** ~8-10 hours for all of the above

**Not worth implementing:**
- ❌ 9 fabrics string converters - Useless without fabrics support
- ❌ 40+ fabrics operations - Require Linux kernel
- ❌ 30+ tree/topology functions - Require sysfs
- ❌ 20+ keyring/TLS functions - Require Linux keyctl
- ❌ NBFT functions - Fabrics boot only

**Critical Note:** These stubs are low priority. The entire list above is meaningless until the Critical Missing Functionality (device I/O layer) is implemented. Focus should be on Windows IOCTL implementation first.

---

## Critical Missing Functionality for Windows

The current Windows build successfully compiles and shows help output, but **cannot actually communicate with NVMe devices**. All device I/O operations are stubbed. The following core functionality must be implemented for a minimally functional tool:

### 🔴 CRITICAL: Device I/O Layer (libnvme)

**Status:** Currently all stubbed - zero device functionality  
**Location:** `libnvme/src/nvme/ioctl.c` and Windows platform layer  
**Priority:** **HIGHEST - MUST IMPLEMENT**

#### What's Missing:

1. **Windows NVMe IOCTL Implementation**
   - Current: `ioctl()` function in `platform/windows.h` returns `ENOSYS`
   - Needed: Implement Windows storage device IOCTLs using:
     - `IOCTL_STORAGE_QUERY_PROPERTY`
     - `IOCTL_STORAGE_PROTOCOL_COMMAND` (Windows 10+)
     - `DeviceIoControl()` Win32 API
   - Reference: Windows NVMe driver documentation
   - Impact: **ALL nvme commands fail without this**

2. **Device Path Translation**
   - Current: Code expects Linux paths like `/dev/nvme0`, `/dev/nvme0n1`
   - Needed: Windows device paths:
     - Physical drives: `\\.\PhysicalDrive0`, `\\.\PhysicalDrive1`
     - SCSI devices: `\\.\SCSI#Disk&Ven_...`
     - NVMe devices: May need Windows NVMe miniport interfaces
   - Must implement path translation in device open routines
   - Impact: **Cannot open any devices**

3. **Device Enumeration (`nvme list`)**
   - Current: `nvme_scan_topology()` stubbed to return error
   - Needed: Windows device enumeration using:
     - `SetupAPI` (`SetupDiGetClassDevs`, `SetupDiEnumDeviceInterfaces`)
     - `CFGMGR32` (Configuration Manager API)
     - Query for NVMe device class GUID
     - Enumerate physical drives and identify NVMe devices
   - Location: `libnvme/src/nvme/tree.c` (excluded from Windows build)
   - Impact: **`nvme list` command completely non-functional**

4. **Global Context (`nvme_create_global_ctx()`)**
   - Current: Stubbed to return NULL in `windows-stubs.c`
   - Needed: Minimal implementation for Windows
     - Log level management
     - Device handle tracking
     - Configuration state
   - Impact: **Most commands fail to initialize**

5. **Device Handle Management**
   - Current: `nvme_open()`, `nvme_close()` stubbed
   - Needed: 
     - Use `CreateFile()` with proper flags for NVMe device access
     - Handle exclusive access (`O_EXCL` → `FILE_SHARE_*` flags)
     - Manage file descriptors vs Windows `HANDLE`
   - Impact: **Cannot open/close devices**

6. **Admin and I/O Command Passthrough**
   - Current: All passthrough stubbed
   - Needed: Windows IOCTL wrappers for:
     - `nvme_submit_admin_passthru()` 
     - `nvme_submit_io_passthru()`
     - Convert Linux NVMe commands to Windows NVMe protocol commands
   - Reference: `STORAGE_PROTOCOL_COMMAND` structure
   - Impact: **All NVMe commands (identify, get-log, etc.) fail**

#### Implementation Approach:

**Phase 1 - Basic Device Access (Minimal Functionality):**
1. Implement `nvme_open()` using `CreateFile()` for physical drives
2. Implement basic `ioctl()` wrapper for `IOCTL_STORAGE_PROTOCOL_COMMAND`
3. Implement admin passthrough for Identify Controller command
4. Test: `nvme id-ctrl \\.\PhysicalDrive0` should work

**Phase 2 - Device Enumeration:**
5. Implement basic `nvme_scan_topology()` using SetupAPI
6. Enumerate NVMe devices and populate device list
7. Test: `nvme list` should show NVMe devices

**Phase 3 - Full Command Support:**
8. Implement remaining admin commands (get-log, get-feature, etc.)
9. Implement I/O passthrough for data transfer commands
10. Test vendor-specific commands with supported devices

#### Files Requiring Implementation:

- `libnvme/src/platform/windows.h` - Replace `ioctl()` stub
- `libnvme/src/nvme/windows-stubs.c` - Implement device functions
- New file: `libnvme/src/nvme/windows-ioctl.c` (recommended)
- New file: `libnvme/src/nvme/windows-enum.c` (recommended)

#### Testing Requirements:

- **Administrator privileges required** - Windows restricts direct device access
- Need physical NVMe device on Windows test machine
- Cannot test in VM without NVMe passthrough
- Consider using Windows Driver Kit (WDK) samples as reference

---

### 🟡 IMPORTANT: Block Device Operations

**Status:** Partially stubbed  
**Priority:** **HIGH**

Several commands need block device size and properties:
- `nvme format` - needs device size
- `nvme write`, `nvme read` - need block size
- Various log pages reference block counts

**Missing APIs:**
- Block device size detection (IOCTL_DISK_GET_LENGTH_INFO)
- Sector size queries (IOCTL_STORAGE_QUERY_PROPERTY)
- `fstat()` for device files - Windows equivalent needed
- `S_ISCHR()`, `S_ISBLK()` macros - need Windows device type checking

**Current Workarounds:**
- Some operations may work without size info (admin commands)
- I/O commands will need proper implementation

---

### 🟡 IMPORTANT: Permissions and Security

**Status:** Not addressed  
**Priority:** **HIGH**

**Requirements:**
1. **Administrator/Elevated Privileges**
   - Direct device access requires admin rights on Windows
   - Should detect and warn if not elevated
   - Add manifest to request elevation?

2. **Device Access Rights**
   - Windows restricts `FILE_SHARE_*` flags
   - Exclusive access may conflict with system drivers
   - May need to coordinate with Windows NVMe driver

3. **Error Handling**
   - Windows error codes differ from errno
   - `GetLastError()` → translate to errno equivalents
   - Proper error messages for permission denied scenarios

**Implementation:**
- Add `IsUserAnAdmin()` check on startup
- Display warning if not elevated
- Consider UAC elevation prompt

---

### 🟢 NICE TO HAVE: Additional Improvements

**Priority:** **LOW**

1. **Native Windows Paths**
   - Accept both Linux-style and Windows-style paths
   - `/dev/nvme0` → `\\.\PhysicalDrive0` auto-translation
   - Device aliases/friendly names

2. **Windows-Specific Documentation**
   - Update man pages for Windows
   - Document device path format
   - Document privilege requirements
   - Installation instructions for Windows

3. **Windows Installer**
   - MSI or MSIX package
   - Include libnvme DLL
   - Add to PATH automatically
   - Desktop shortcuts

4. **Error Message Improvements**
   - Windows-specific error messages
   - Link to troubleshooting docs
   - Better privilege requirement messages

---

## Summary of Required Work

| Component | Priority | Effort | Blocker |
|-----------|----------|--------|---------|
| Device IOCTL implementation | 🔴 Critical | High | **YES** |
| Device path translation | 🔴 Critical | Medium | **YES** |
| Device enumeration | 🔴 Critical | High | **YES** |
| Admin command passthrough | 🔴 Critical | High | **YES** |
| Block device operations | 🟡 Important | Medium | Partial |
| Permission handling | 🟡 Important | Low | No |
| Documentation | 🟢 Nice to have | Medium | No |

**Bottom Line:** The Windows build is currently a "shell" that compiles but has **zero runtime device functionality**. All the critical I/O operations are stubbed. Implementing Windows NVMe device access is a **significant porting effort** requiring:
- Windows Driver Kit knowledge
- Understanding of Windows storage stack
- Testing hardware with NVMe devices
- ~2-4 weeks for experienced Windows driver developer

---

Last updated: January 23, 2026
