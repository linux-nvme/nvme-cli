# NVMe Controller Ownership Registry

## 1. Problem Statement

Multiple independent NVMe-oF orchestrators can establish controller connections on the same Linux host simultaneously:

- Manual `nvme connect` invocations (stateless, one-shot)
- `nvme-stas` (stateful daemon — `stafd` / `stacd`)
- NBFT firmware boot connections
- `nvme-discoverd` and similar tools
- UDisks (stateful daemon), libblockdev (stateless library)
- Direct writes to `/dev/nvme-fabrics` (e.g. manual or scripted `echo ... > /dev/nvme-fabrics`)

All connected controllers appear in a single flat namespace (`/dev/nvmeX`, `/sys/class/nvme/nvmeX`) with no indication of which orchestrator created or manages each one. Commands like `nvme disconnect-all` are therefore indiscriminate: they cannot distinguish a controller managed by a running daemon from one connected manually.

Connections established without libnvme — direct `/dev/nvme-fabrics` writes — bypass the registry entirely. These controllers will have no registry entry and will be treated as unowned. `disconnect-all` without `--force` will disconnect them freely — consistent with the registry's opt-in model: unregistered connections are unprotected. UDisks and libblockdev both route through libnvme but provide simple user-level connect/disconnect convenience with no plans for registry ownership participation; their connections will correctly appear as unowned.

The ownership registry solves this by allowing orchestrators to declare ownership of controllers and respect each other's boundaries. See [Appendix A](#appendix-a-the-nvme-of-orchestrator-ecosystem) for background on the orchestrator ecosystem and why this coordination is needed.

The registry is a **collaborative tool, not an enforcement mechanism**. All participants are assumed to be cooperative. No cryptographic or OS-level enforcement is possible since all orchestrators run as root — an orchestrator that ignores the registry can disconnect any controller today, with or without the registry. The registry gives well-behaved tools the information they need to avoid doing so accidentally.

---

## 2. Registry Layout

The registry lives at `/run/nvme/registry/`. `/run/` is appropriate because ownership is runtime orchestration state — it is naturally tied to controller lifecycle and does not survive a reboot.

One directory per live controller, named after the kernel device, with one plain text file per attribute — mirroring the sysfs convention of one directory per object, one file per attribute:

```
/run/nvme/registry/
    nvme1/
        owner
    nvme3/
        owner
        note
    nvme5/
        owner
```

**Absence means unowned.** A controller with no registry directory is not managed by any orchestrator. There is no explicit "unowned" marker — a missing directory is the signal.

Each attribute file contains a plain text value. The registry is trivially inspectable without any special tool:

```sh
$ cat /run/nvme/registry/nvme3/owner
stas

$ cat /run/nvme/registry/nvme3/note
boot-path SAN connection

$ ls /run/nvme/registry/
nvme1  nvme3  nvme5
```

### Well-known attributes

| Attribute | Written by | Description |
|-----------|------------|-------------|
| `owner` | libnvme automatically on connect (when `ctx->owner` is non-NULL) | Orchestrator identity string (e.g. `"stas"`, `"nbft"`, `"discoverd"`). A registry entry without an `owner` file has no meaningful ownership. |
| `note` | Caller, optional | Free-form UTF-8 string providing further context, suitable for UI display (e.g. `"boot-path SAN connection"`). |

Unknown attributes are ignored by all registry consumers. Orchestrators may write additional private attributes using the same API.

PCIe and apple-nvme controllers are outside the scope of the registry. They are hardware-enumerated by the kernel, never connected through the fabrics path, and already excluded from `nvme disconnect-all` by existing transport-type checks.

---

## 3. Ownership

**Exclusive ownership**: each controller has at most one registered owner at any time.

Ownership identifies **reconciliation authority** — which orchestrator is managing a given controller. This lets other orchestrators leave it alone, in particular skip it during `disconnect-all`.

When a controller is removed by the kernel, its registry entry is deleted (see [Automatic Cleanup](#4-automatic-cleanup)). Any orchestrator may attempt to reconnect; whoever succeeds first writes the new registry entry and becomes the new owner. Prior ownership confers no priority in that race.

### CRUD operations and atomicity

Write operations use an atomic `tmp → rename` protocol to prevent corruption under concurrent access from multiple processes:

```
write attribute value to <name>.tmp
fsync(<name>.tmp)
rename(<name>.tmp, <name>)
fsync(registry/<device>/)
```

Because attribute files are independent of one another, there is no read-modify-write step: updating one attribute (e.g. `owner`) does not require reading and rewriting others. This eliminates the class of race conditions inherent to formats where the entire record must be rewritten on every update.

| Operation | Mechanism |
|-----------|-----------|
| **C**reate | `mkdir(nvmeN/)` then atomic attribute write |
| **R**etrieve | `open()` + `read()` |
| **U**pdate | Atomic attribute write; creates the directory if absent |
| **D**elete | `rm -rf nvmeN/` |

**Create always overwrites.** After a successful connect, the kernel assigns a fresh device instance number `N`. Any pre-existing `nvmeN/` directory in the registry is stale by definition — the kernel just assigned that instance number to a new controller. The old entry is removed and a fresh one is written unconditionally.

**Ownership transfer.** `libnvmf_registry_update()` replaces the `owner` attribute unconditionally. A higher-capability orchestrator (e.g. nvme-stas with CDC/fabric-zoning knowledge) may claim ownership from one that connected first. This is the intended use of `libnvmf_registry_update()`.

This is a cooperative bilateral arrangement, not a general arbitration mechanism. nvme-discoverd ships by default; nvme-stas is optional. An administrator who installs nvme-stas is making an explicit policy decision: they want CDC-driven fabric zoning (TP8010), and they want nvme-stas in charge of controller management for CDC-governed controllers. The ownership transfer is the expected consequence of that decision, not a conflict between peers. The registry does not implement a priority scheme — priority logic belongs in the orchestrators themselves.

---

## 4. Automatic Cleanup

A udev rule fires on `KOBJ_REMOVE` for NVMe controller devices and removes the corresponding registry directory:

```
ACTION=="remove", SUBSYSTEM=="nvme", \
    RUN+="/bin/rm -rf /run/nvme/registry/%k"
```

`%k` is the kernel device name (e.g. `nvme3`). The rule is safe when no entry exists (unowned controllers, PCIe devices, etc.).

The udev rule ships with `libnvme`, so the cleanup mechanism is present whenever libnvme is installed — independent of whether `nvme-cli` is installed.

**Kernel reconnect behavior.** During a reconnect within `ctrl-loss-tmo`, the kernel reuses the same `struct nvme_ctrl` — same instance number, same device name, no `KOBJ_REMOVE` event. The registry entry is untouched throughout. Only when `ctrl-loss-tmo` expires and the kernel calls `nvme_delete_ctrl()` does the `KOBJ_REMOVE` event fire and the entry get deleted. If an orchestrator later establishes a new connection, it creates a fresh registry entry under the new device name.

**Boot device protection.** Controllers connected during the initramfs stage are automatically protected. The dracut nvmf module invokes `nvme connect-all --nbft`, which goes through libnvme and writes registry entries with `owner=nbft`. `switch_root(8)` explicitly moves `/run` to the new root — *"switch_root moves already mounted /proc, /dev, /sys and /run to newroot"* ([switch_root(8), util-linux](https://man7.org/linux/man-pages/man8/switch_root.8.html)) — so these entries are present in the runtime system with no special handling. No dracut changes are needed beyond using the updated nvme-cli in the initramfs. Boot devices are a first-class case, not a special one.

**Daemons track device presence independently.** Neither nvme-stas nor nvme-discoverd relies on the registry to determine whether a controller is present. Both monitor device removal directly through the uevent stream, and on startup both perform a full audit of the current device tree. The registry is orthogonal to device presence — it records ownership, not existence. A stale registry entry for a removed controller is a minor inconsistency to be cleaned up by the udev rule, not a correctness problem for the daemons. As a belt-and-suspenders measure, nvme-discoverd may perform an aperiodic audit that cross-checks registry entries against the live device tree, removing any entries that refer to controllers no longer present.

**Instance recycling safety.** Before the kernel can recycle instance number N for a new connection, the old `nvmeN` controller must have been removed, firing a `KOBJ_REMOVE` uevent. Any daemon tracking that device will have updated its state before the instance number can be reused. The registry being overwritten is consistent with what the daemons already know from the uevent stream.

---

## 5. Orchestrator Context Integration

The owner name is passed at context creation time and applies to every controller connected through that context:

```c
struct libnvme_global_ctx *libnvme_create_global_ctx(FILE *fp, int log_level,
                                                      const char *owner);
```

`owner` identifies the calling process (e.g. `"stas"`, `"nbft"`, `"discoverd"`). Pass `NULL` if the orchestrator does not participate in the registry — no entry will be written on connect, and `disconnect-all` will treat controllers connected by this context as unowned.

**`owner` is immutable.** It is set once at context creation and cannot be changed afterwards. There is no setter API. This is intentional: ownership identity is a property of the process, not of individual operations, and making it immutable prevents accidental mid-session identity changes.

When `owner` is non-NULL and a fabrics connect succeeds, libnvme automatically writes the registry entry. The orchestrator does not need to call any registration function explicitly.

### Relation to the `application` parameter

`libnvme_global_ctx` previously exposed an `application` field, set via `libnvme_set_application()`. Its sole purpose was to filter subsystem entries when reading a hand-written JSON config file: at connect time, subsystems tagged with a different application name were skipped. This mechanism assumes all orchestrators share a common JSON config file, which does not hold for the real orchestrator landscape:

- **NBFT** — reads firmware tables from `/sys/firmware/acpi/tables/`; no JSON config
- **nvme-stas** — zeroconf/ZTP via DNS-SD; controllers are discovered dynamically
- **nvme-discoverd** — will read the JSON config file to set up initial bootup connections, so the `application` filtering would apply here — but only for the JSON-driven part of its workflow and not any potential mDNS discovered controllers.

The `owner` registry works across all orchestrators through a shared runtime path (`/run/nvme/registry/`) without any shared config file. `owner` supersedes the `application` field, which is being removed in the v3.0 major version cleanup.

---

## 6. API Reference

All registry functions are available when libnvme is built with fabrics support and are declared in `<libnvme.h>`. Registry entry creation is handled automatically by the connect path when `ctx->owner` is non-NULL. The internal function `libnvmf_registry_create()` is not part of the public API and should not be called directly (and therefore left out of the following list).

```c
/*
 * Retrieve the value of an attribute from a controller's registry entry.
 * Returns 0 and fills *value on success; -ENOENT if the controller is not
 * registered or the attribute is not found. Caller must free *value.
 * Example: libnvmf_registry_retrieve("nvme3", "owner", &value);
 */
int libnvmf_registry_retrieve(const char *device, const char *attr, char **value);

/*
 * Update an attribute in a controller's registry entry. Creates the entry if
 * it does not exist. Use to claim or steal ownership.
 * Returns 0 on success, negative errno otherwise.
 * Example: libnvmf_registry_update("nvme3", "owner", "stas");
 */
int libnvmf_registry_update(const char *device, const char *attr, const char *value);

/*
 * Delete the registry entry for a controller.
 * Called by the owner on intentional disconnect.
 * Returns 0 on success, negative errno otherwise.
 */
int libnvmf_registry_delete(const char *device);

/*
 * Iterate over live controller registry entries.
 * Invokes cback for each entry whose /dev/nvmeN device node exists; stale
 * entries (directory present, device absent) are silently skipped.
 * /dev/nvmeX is created synchronously by the kernel via devtmpfs when the
 * controller is registered — before the connect ioctl returns to userspace —
 * so this check is race-free for newly connected controllers.
 * Use libnvmf_registry_retrieve() or libnvmf_registry_attr_for_each() inside
 * the callback to read attributes.
 * The existence check is advisory: a device may be removed between the check
 * and callback execution. Callers should handle ENOENT gracefully.
 * Entries that disappear during iteration are silently skipped; the function
 * still returns 0 in that case.
 * Returns 0 on success, negative errno if the registry directory cannot be
 * opened. Returns 0 when the directory does not exist (nothing registered).
 */
int libnvmf_registry_device_for_each(
        void (*cback)(const char *device, void *user_data),
        void *user_data);

/*
 * Iterate over all attributes of a controller's registry entry.
 * Invokes cback for each attribute file found in the device's registry
 * directory. Attribute files that disappear during iteration (e.g. because
 * the device is removed concurrently) are silently skipped; the function
 * still returns 0 in that case.
 * Returns 0 on success, -ENOENT if the device directory does not exist at
 * the time of the initial open, negative errno otherwise.
 */
int libnvmf_registry_attr_for_each(
        const char *device,
        void (*cback)(const char *attr, const char *value, void *user_data),
        void *user_data);
```

---

## 7. CLI Commands

Registry operations are exposed through a `registry` plugin under `plugins/registry/`. Plugin commands use the `nvme registry` prefix:

| Command | Description |
|---------|-------------|
| `nvme registry list` | List all live registry entries |
| `nvme registry retrieve -d <dev> [-a <attr>]` | Show an attribute |
| `nvme registry update -d <dev> -a <attr> -V <val>` | Update an attribute |
| `nvme registry delete -d <dev>` | Remove a registry entry |

### Ownership-aware `disconnect-all`

`disconnect-all` is a convenience command that operates on all controllers at once rather than a specific one. Because its scope is broad and the caller does not necessarily know which controllers are managed by a running daemon, guardrails are appropriate: by default it only disconnects unowned controllers, protecting anything a daemon depends on.

| Invocation | Behavior |
|------------|----------|
| `nvme disconnect-all` | Disconnect only unowned controllers (new safe default) |
| `nvme disconnect-all --owner <name>` | Disconnect only controllers owned by `<name>` |
| `nvme disconnect-all --force` | Disconnect all controllers regardless of ownership |

`--force` and `--owner` are mutually exclusive. `--force` restores the previous unconditional behavior and requires an explicit confirmation prompt.

### Single `nvme disconnect`

`nvme disconnect <device>` targets a specific controller by name. Because the caller has made an explicit, deliberate choice, no guardrails are needed — the command always disconnects regardless of ownership, with no `--force` flag required or provided.

This asymmetry is intentional: `disconnect-all` is a convenience command with broad scope and therefore carries ownership-aware defaults; `disconnect` is a precise, targeted operation where the caller's intent is unambiguous.

### NBFT connect

`nvme connect-all --nbft` automatically registers all controllers it connects as `owner=nbft`, protecting boot volumes from accidental disconnection.

### Ownership in `nvme list -v`

The verbose form of `nvme list` includes an Orchestrator column:

- Fabrics controller with a registry entry: the owner string (e.g. `stas`, `nbft`)
- Fabrics controller without an entry (unowned): `-`
- PCIe / apple-nvme controller: `kernel` (synthesized; not read from the registry)

---

## Appendix A: The NVMe-oF Orchestrator Ecosystem

### Orchestrators

**Human operators (nvme-cli, one-shot)**

A human invoking `nvme connect`, `nvme connect-all`, or `nvme disconnect-all`. No registry entry is written for manual connections (`owner` is NULL). Manually connected controllers are unowned: `disconnect-all` can disconnect them freely, which is correct since no daemon will attempt to reconnect them.

**UDisks**

A stateful D-Bus daemon providing block-device management to desktop environments and other consumers. It acts as a privileged broker — user-level applications request storage operations via D-Bus, and UDisks enforces policy via polkit before carrying them out. UDisks establishes NVMe-oF connections by calling libblockdev (`bd_nvme_connect`), which in turn calls libnvme (`nvmf_add_ctrl`). UDisks has no direct libnvme dependency of its own.

UDisks provides simple user-level connect/disconnect convenience and has no plans to take registry ownership over controllers the way nvme-stas does. Its connections will appear as unowned in the registry, and `disconnect-all` will treat them as freely disconnectable. This is the correct behavior for user-driven one-shot connects.

**libblockdev**

A C library used by storage management tools including UDisks. Its NVMe plugin (`src/plugins/nvme/nvme-fabrics.c`) links directly against libnvme and calls `nvmf_add_ctrl()` for connects and `nvme_disconnect_ctrl()` for disconnects — it does not shell out to `nvme connect`. Like UDisks, it provides simple connect/disconnect functionality with no plans for registry ownership participation.

**Direct `/dev/nvme-fabrics` writes**

Any process that writes connection parameters directly to `/dev/nvme-fabrics` without going through libnvme — common in embedded systems, kdump environments, and low-level tooling. Note that libnvme itself uses this interface internally (`nvmf_add_ctrl` writes to `/dev/nvme-fabrics`); the distinction is whether a caller goes through libnvme or bypasses it. Connections that bypass libnvme will always be unowned.

**nvme-discoverd**

A daemon-based replacement for the udev rules that react to discovery events by calling `nvme connect-all`. It addresses the main limitations of udev: it can retry failed connections and reconnect after a controller is lost. Because it ships as part of nvme-cli — a default distro package — nvme-discoverd will be present and running by default on most systems. It does not participate in fabric zoning (TP8010).

**nvme-stas (stafd + stacd)**

An optional package providing production-grade NVMe-oF connectivity management. `stafd` discovers Discovery Controllers via DNS-SD (TP8009) and reads their discovery log pages; `stacd` establishes and maintains I/O controller connections. nvme-stas supports TP8010 **fabric zoning** via a Centralized Discovery Controller (CDC), giving it a network-level view of controller access policy that no other host-side tool currently provides.

**NBFT**

Boot-time NVMe controllers configured in firmware tables (`/sys/firmware/acpi/tables/`). `nvme connect-all --nbft` reads these tables and connects to boot volumes, registering them as `owner=nbft` so that other orchestrators and `nvme disconnect-all` leave them alone.

### Why the registry is necessary

nvme-discoverd ships by default; nvme-stas is optional. Both may run simultaneously on the same host. Both react to the same kernel events and may attempt to connect to the same controllers. Without the registry there is no mechanism for either daemon to know whether the other has already claimed a controller, and `nvme disconnect-all` has no way to avoid disconnecting controllers that a running daemon depends on.

The registry resolves this: each orchestrator registers ownership as it connects controllers and respects entries written by others. When nvme-stas determines — through its CDC/fabric-zoning view — that a controller belongs under its management, it calls `libnvmf_registry_update()` to take ownership from whatever orchestrator connected first.

### Limitation: the registry does not prevent reconnection

**Disconnect prevention vs. connect prevention.** The registry prevents accidental disconnection of owned controllers — specifically by broad-scope tools like `disconnect-all` that operate without knowledge of which controllers are managed by running daemons. It does not prevent reconnection.

nvme-discoverd only connects controllers; it never disconnects them. If nvme-stas deliberately disconnects a controller that its fabric zone policy excludes, nvme-discoverd may reconnect it — creating a bounce loop. For environments that require full TP8010 fabric zoning compliance, the recommended approach is to disable or mask nvme-discoverd:

```sh
systemctl [disable|mask] --now nvme-discoverd
```

nvme-stas covers everything nvme-discoverd does and more. Running both simultaneously is only appropriate in environments without fabric zoning where their discovery scopes do not conflict.

A more complete solution — allowing both daemons to run simultaneously even in fabric-zoning environments — requires a separate discovery policy coordination mechanism. This is addressed in `nvme-orchestrator-coexistence-summary.md`, which proposes a runtime exclusion mechanism that nvme-stas can use to tell nvme-discoverd which controllers to leave alone.
