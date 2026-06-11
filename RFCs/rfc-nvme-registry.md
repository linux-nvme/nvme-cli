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

Connections established without libnvme — direct `/dev/nvme-fabrics` writes — bypass the registry entirely. These controllers will have no registry entry and will be treated as unowned. `disconnect-all` without `--force` will disconnect them freely — consistent with the registry's opt-in model: unregistered connections are unprotected. UDisks and libblockdev both route through libnvme but do not participate in registry ownership; their connections correctly appear as unowned.

The ownership registry solves this by allowing orchestrators to declare ownership of controllers and respect each other's boundaries. See `rfc-nvme-orchestrator-coexistence.md` for background on the full orchestrator ecosystem and how the registry fits into the broader coordination picture.

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

### 2.1 Well-known attributes

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

### 3.1 CRUD operations and atomicity

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

Ownership is set at connect time and is not transferred between orchestrators during normal operation. Each orchestrator manages the controllers it connected and leaves other controllers alone; the registry makes that partition visible and enforceable. `libnvmf_registry_update()` can update any attribute including `owner`, but changing ownership between orchestrators is not a designed pattern.

This is a cooperative arrangement, not a general arbitration mechanism. nvme-discoverd ships by default; nvme-stas is optional. When both run simultaneously, each manages the controllers it connected — first-connect-wins, no priority scheme, no stealing. The registry does not implement arbitration; the orchestrators are expected to stay in their own lane.

---

## 4. Automatic Cleanup

A udev rule fires on `KOBJ_REMOVE` for NVMe controller devices and removes the corresponding registry directory. `%k` is the kernel device name (e.g. `nvme3`). For `SUBSYSTEM=="nvme"` the kernel always produces names of the form `nvme[0-9]*`, so path traversal via `%k` is not possible; the `KERNEL==` match makes this constraint explicit and provides defense-in-depth. The rule is safe when no entry exists (unowned controllers, PCIe devices, etc.).

The udev rule ships with `libnvme`, so the cleanup mechanism is present whenever libnvme is installed — independent of whether `nvme-cli` is installed.

**Kernel reconnect behavior.** During a reconnect within `ctrl-loss-tmo`, the kernel reuses the same `struct nvme_ctrl` — same instance number, same device name, no `KOBJ_REMOVE` event. The registry entry is untouched throughout. Only when `ctrl-loss-tmo` expires and the kernel calls `nvme_delete_ctrl()` does the `KOBJ_REMOVE` event fire and the entry gets deleted. If an orchestrator later establishes a new connection, it creates a fresh registry entry under the new device name.

**Boot device protection.** Controllers connected during the initramfs stage are automatically protected. The dracut nvmf module invokes `nvme connect-all --nbft`, which goes through libnvme and writes registry entries with `owner=nbft`. `switch_root(8)` explicitly moves `/run` to the new root — *"switch_root moves already mounted /proc, /dev, /sys and /run to newroot"* ([switch_root(8), util-linux](https://man7.org/linux/man-pages/man8/switch_root.8.html)) — so these entries are present in the runtime system with no special handling. No dracut changes are needed beyond using the updated nvme-cli in the initramfs. Boot devices are a first-class case, not a special one.

**`owner=nbft` protects boot-path controllers from all orchestrator policy enforcement.** NBFT controllers carry `owner=nbft` for their entire lifecycle: set by `nvme connect-all --nbft` at initial connect and preserved by nvme-discoverd on every subsequent reconnect (it passes `--owner nbft` rather than `--owner discoverd` for NBFT-sourced controllers). nvme-stas respects the registry unconditionally — `owner=nbft` means nvme-stas never disconnects them regardless of CDC fabric zoning requests, by the same rule that applies to any other orchestrator's controllers. nvme-discoverd additionally ignores exclusion list entries that match NBFT-sourced controllers, reconnecting unconditionally. In both cases the orchestrator logs a warning when it would otherwise have enforced policy against a boot device — the protection is visible, not silent.

**Daemons track device presence independently.** Neither nvme-stas nor nvme-discoverd relies on the registry to determine whether a controller is present. Both monitor device removal directly through the uevent stream, and on startup both perform a full audit of the current device tree. The registry is orthogonal to device presence — it records ownership, not existence. A stale registry entry for a removed controller is a minor inconsistency to be cleaned up by the udev rule, not a correctness problem for the daemons. As a belt-and-suspenders measure, nvme-discoverd may perform an aperiodic audit that cross-checks the live device tree against the registry in both directions: removing stale entries (registry directory present but device absent) and re-asserting ownership for live controllers it manages (device present but registry entry absent or stale). The bidirectional audit ensures the registry converges to the correct state even after rare cleanup races.

**Instance recycling safety.** The kernel allocates NVMe controller instance numbers using `ida_alloc()` (`nvme_init_ctrl()` in `drivers/nvme/host/core.c`), which returns the **lowest available** ID. When `nvme4` is removed, its instance number is freed immediately and the very next connected controller may receive the same number.

This creates a potential race: the cleanup rule for the old `nvme4` may run after a new controller has already claimed the same ID and written its registry entry, silently deleting a live entry. The rule therefore guards the removal with a device existence check:

```
ACTION=="remove", SUBSYSTEM=="nvme", KERNEL=="nvme[0-9]*", \
    RUN+="/bin/sh -c '[ -e /dev/%k ] || rm -rf /run/nvme/registry/%k'"
```

NVMe controller devices (`nvme0`, `nvme4`, etc.) are char devices — `-e` (exists) is the correct test; `-b` (block device) would never match. The guard works as follows:

- **New controller has already appeared**: its char device `/dev/nvme4` exists at the time the remove rule fires; the test is true and `||` short-circuits — `rm` is skipped and the new registry entry is preserved.
- **New controller has not appeared yet**: `/dev/nvme4` is absent; the test is false and `rm` runs, removing the stale old entry.

There is a harmless false-positive case: if devtmpfs has not yet removed the old `/dev/nvme4` node by the time the rule fires (devtmpfs operates asynchronously via a kthread), the test sees the old node and skips the `rm`, leaving the stale entry on disk. This is safe — `libnvmf_registry_create()` always overwrites on connect, so the new controller's write replaces any stale entry. Any remaining orphan is caught by nvme-discoverd's aperiodic audit (see above), which also re-asserts ownership for live controllers it manages — restoring any entry deleted while the device was alive.

There is also a residual race in the dangerous direction: the shell evaluates `[ -e /dev/nvme4 ]` as false, but between the check and the `rm -rf` a new controller claims instance 4 and libnvme writes its registry entry — `rm -rf` then deletes a live entry. The new controller is temporarily unowned until the next audit cycle re-asserts its entry.

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

### 5.1 Relation to the `application` parameter

`libnvme_global_ctx` previously exposed an `application` field, set via `libnvme_set_application()`. Its sole purpose was to filter subsystem entries when reading a hand-written JSON config file: at connect time, subsystems tagged with a different application name were skipped. This mechanism assumes all orchestrators share a common JSON config file, which does not hold for the real orchestrator landscape:

- **NBFT** — reads firmware tables from `/sys/firmware/acpi/tables/`; no JSON config
- **nvme-stas** — zeroconf/ZTP via DNS-SD; controllers are discovered dynamically
- **nvme-discoverd** — reads its own INI configuration file (`/etc/nvme/discoverd.conf`); the shared JSON config mechanism that `application` was designed for has no relevance to its workflow.

The ownership registry works across all orchestrators through a shared runtime path (`/run/nvme/registry/`) without any shared config file. `owner` supersedes the `application` field, which is being removed in the v3.0 major version cleanup.

---

## 6. API Reference

All registry functions are available when libnvme is built with fabrics support and are declared in `<nvme/registry.h>`. Registry entry creation is handled automatically by the connect path when `ctx->owner` is non-NULL. The internal function `libnvmf_registry_create()` is not part of the public API and should not be called directly (and therefore left out of the following list).

**Implementation note — attribute name sanitization.** The `const char *attr` parameter in the APIs below is used directly as a filename component under `/run/nvme/registry/<device>/` (e.g. `/run/nvme/registry/nvme3/owner` when `attr="owner"`). The implementation must validate `attr` against `[a-zA-Z0-9_-]+` and reject any value containing `/`, `.`, NUL, or other characters that could cause path traversal.

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
 * it does not exist. Pass value=NULL to remove the attribute file.
 * Returns 0 on success, negative errno otherwise.
 * Example: libnvmf_registry_update("nvme3", "note", "boot-path SAN connection");
 * Example: libnvmf_registry_update("nvme3", "note", NULL);  // removes the note
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

### 6.1 Python Bindings

The registry bindings follow the same split as the exclusion list bindings in `nvme.i`: write operations are C functions wrapped by SWIG (to get proper exception handling from C return codes), while read operations are pure Python added via `%pythoncode` (direct file I/O is simpler than marshalling C iterators through SWIG callbacks). Both land in the `nvme` module (`from libnvme import nvme`).

| Operation | Implementation |
|-----------|---------------|
| `registry_retrieve()`, `registry_entries()` | Pure Python in `%pythoncode` — read files directly |
| `registry_update()` | SWIG-wrapped C — calls `libnvmf_registry_update()`; pass `value=None` to remove the attribute file; raises `ValueError` on invalid device name or `attr` (same `[a-zA-Z0-9_-]+` constraint as the C API) |
| `registry_delete()` | SWIG-wrapped C — calls `libnvmf_registry_delete()`; raises `FileNotFoundError` if not found, `OSError` on other failures |

`registry_entries()` is a generator that yields `(device, attrs)` tuples, where `attrs` is a dict of all attribute names to their values. Stale entries (registry directory present but `/dev/nvmeN` absent) are silently skipped, as are temp files and dotfiles left by in-progress atomic writes.

The directory path defaults to `/run/nvme/registry` but can be overridden via the `NVME_REGISTRY_DIR` environment variable, enabling tests to run without root access.

```python
from libnvme import nvme

# --- Runtime check (called by orchestrators before disconnecting) ------------

owner = nvme.registry_retrieve('nvme3', 'owner')
if owner and owner != 'stas':
    return  # owned by another orchestrator — leave it alone

# --- Inspection --------------------------------------------------------------

for device, attrs in nvme.registry_entries():
    print(f'{device}  {attrs.get("owner", "-")}  {attrs.get("note", "")}')

# --- Write operations --------------------------------------------------------

nvme.registry_update('nvme3', 'note', 'boot-path SAN connection')
nvme.registry_delete('nvme3')
```

---

## 7. CLI Commands

Registry operations are exposed through a `registry` plugin under `plugins/registry/`. Plugin commands use the `nvme registry` prefix:

| Command | Description |
|---------|-------------|
| `nvme registry list` | List all live registry entries |
| `nvme registry retrieve -d <dev> [-a <attr>]` | Show an attribute |
| `nvme registry update -d <dev> -a <attr> -V <val>` | Update an attribute (`owner` is rejected — immutable) |
| `nvme registry delete -d <dev>` | Remove a registry entry |

**API vs CLI semantics for `owner`.** The `-EPERM` guard on `owner` writes applies only to the `nvme registry update` CLI command. The C API (`libnvmf_registry_update()`) and Python binding (`registry_update()`) allow writing any attribute including `owner`, with no restriction. This is intentional: library-level code (e.g., nvme-stas in Python) may need to update ownership programmatically, and API callers are expected to know what they are doing. The CLI guard exists solely to prevent accidental human mistakes at the command line.

### 7.1 Ownership-aware `disconnect-all`

`disconnect-all` is a policy-aware orchestrating command that operates on all controllers at once. Because its scope is broad and the caller does not necessarily know which controllers are managed by a running daemon, it respects the ownership registry by default: it only disconnects controllers that have no registered owner, protecting anything a daemon depends on.

| Invocation | Behavior |
|------------|----------|
| `nvme disconnect-all` | Disconnect only unowned controllers (safe default) |
| `nvme disconnect-all --owner <name>` | Disconnect only controllers owned by `<name>` (requires confirmation) |
| `nvme disconnect-all --force` | Disconnect all controllers regardless of ownership (requires confirmation) |

`--force` and `--owner` are mutually exclusive. Both require an explicit confirmation prompt: `--force` because it disconnects all controllers regardless of ownership; `--owner <name>` because it targets a specific owner class by name — including the potentially dangerous `--owner nbft`, which would target firmware boot volumes. Neither flag is suitable for non-interactive use.

How the owner field maps to `disconnect-all` behavior:

| `owner` value | `disconnect-all` (default) | `disconnect-all --owner stas` | `disconnect-all --force` |
|---|---|---|---|
| NULL (unowned) | **Disconnect** | Skip | Disconnect |
| `discoverd` | Skip | Skip | Disconnect |
| `stas` | Skip | **Disconnect** | Disconnect |
| `nbft` | Skip | Skip | Disconnect |

NULL owner is the natural result of connections made by plain `nvme connect-all` (which deliberately does not register ownership) and by any tool that bypasses libnvme. These are always freely disconnectable by `disconnect-all`. This preserves the familiar `connect-all` → `disconnect-all` workflow: `disconnect-all` can always undo what `connect-all` did.

Note: `nvme connect-all --nbft` is the one exception — it registers `owner=nbft` to protect firmware boot volumes (see §7.3 NBFT connect below).

### 7.2 Single `nvme disconnect`

`nvme disconnect <device>` targets a specific controller by name. Because the caller has made an explicit, deliberate choice, no guardrails are needed — the command always disconnects regardless of ownership, with no `--force` flag required or provided.

This asymmetry is intentional: `disconnect-all` is a broad-scope orchestrating command where policy-aware defaults are appropriate; `disconnect` is a precise, targeted operation where the caller's intent is unambiguous. See `rfc-nvme-orchestrator-coexistence.md` for the full orchestrator hierarchy.

### 7.3 NBFT connect

`nvme connect-all --nbft` automatically registers all controllers it connects as `owner=nbft`, protecting boot volumes from accidental disconnection.

### 7.4 Ownership in `nvme list -v`

The verbose form of `nvme list` includes an Orchestrator column:

- Fabrics controller with a registry entry: the owner string (e.g. `stas`, `nbft`)
- Fabrics controller without an entry (unowned): `-`
- PCIe / apple-nvme controller: `kernel` (synthesized; not read from the registry)

---

## Appendix A: The NVMe-oF Orchestrator Ecosystem

See `rfc-nvme-orchestrator-coexistence.md` for the complete picture: orchestrator tiers, which tools check the exclusion list and registry, which produce unowned connections (UDisks, libblockdev, direct `/dev/nvme-fabrics` writes), the natural division of labor between nvme-discoverd and nvme-stas, TP8010 fabric zoning conflict resolution, and mDNS discovery policy.
