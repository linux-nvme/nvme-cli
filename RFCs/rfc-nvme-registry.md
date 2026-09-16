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

The ownership registry solves this by allowing orchestrators to declare ownership of controllers and respect each other's boundaries. See `rfc-nvme-orchestrator-coexistence.md` for background on the full orchestrator ecosystem and how the registry fits into the broader coordination picture.

### 1.1 Connections outside the registry

Connections established without libnvme — direct `/dev/nvme-fabrics` writes — bypass the registry entirely. These controllers will have no registry entry and will be treated as unowned. `disconnect-all` without `--force` will disconnect them freely — consistent with the registry's opt-in model: unregistered connections are unprotected.

One narrow edge case remains, requiring two things to coincide. First, a bypass connection must claim a recycled device ID before the udev rule (§4) has run for the removed controller — the rule's `[ -e /dev/%k ]` guard then sees the new device node and deliberately skips the cleanup, leaving the old entry in place. (In the normal case the udev rule has already removed the old entry by the time the device ID is recycled, and the bypass connection correctly appears unowned.) Second, because the connection bypasses libnvme, `libnvmf_registry_delete_instance()` — which clears stale entries on every libnvme-initiated connect — never runs.

When both conditions hold, the stale entry persists until the udev rule fires on the next removal, or until the next libnvme-based connect for the same device ID overwrites it. In the interim, `disconnect-all` treats the bypass connection as owned and skips it. This is an accepted limitation of the opt-in model; direct `/dev/nvme-fabrics` writers intentionally bypass all libnvme coordination.

UDisks and libblockdev both route through libnvme but do not participate in registry ownership; their connections correctly appear as unowned.

### 1.2 Cooperative, not enforced

The registry is a **collaborative tool, not an enforcement mechanism**. All participants are assumed to be cooperative. No cryptographic or OS-level enforcement is possible since all orchestrators run as root — an orchestrator that ignores the registry can disconnect any controller today, with or without the registry. The registry gives well-behaved tools the information they need to avoid doing so accidentally.

---

## 2. Registry Layout

The registry lives at `/run/nvme/registry/`. `/run/` is appropriate because ownership is runtime orchestration state — it is naturally tied to controller lifecycle and does not survive a reboot.

One directory per live controller, named after the kernel device, with one plain text file per attribute — mirroring the sysfs convention of one directory per object, one file per attribute:

```
/run/nvme/registry/
    nvme1/
        owner
        seqnum
    nvme3/
        owner
        seqnum
    nvme5/
        owner
        seqnum
```

**Absence means unowned.** A controller with no registry directory is not managed by any orchestrator. There is no explicit "unowned" marker — a missing directory is the signal.

Each attribute file contains a plain text value. The registry is trivially inspectable without any special tool:

```sh
$ cat /run/nvme/registry/nvme3/owner
stas

$ ls /run/nvme/registry/
nvme1  nvme3  nvme5
```

### 2.1 Well-known attributes

| Attribute | Written by | Description |
|-----------|------------|-------------|
| `owner` | libnvme automatically on connect (when `ctx->owner` is non-NULL) | Orchestrator identity string (e.g. `"stas"`, `"nbft"`, `"discoverd"`). A registry entry without an `owner` file has no meaningful ownership. |
| `seqnum` | libnvme automatically on connect (best-effort) | Kernel uevent sequence number, read from `/sys/kernel/uevent_seqnum` and stamped on the entry at connect time. The cleanup udev rule (`70-nvmf-registry.rules`) removes an entry on a `remove` event only when the event's `SEQNUM` is greater than this stamp, so a controller that is removed and immediately re-created under the same device name keeps its fresh entry instead of having it deleted by the stale `remove`. A missing stamp makes the rule fall back to its device-existence guard. |

These two attributes are the minimum every registry entry carries: `owner` records *who* owns the controller, and `seqnum` makes cleanup race-free. Unknown attributes are ignored by all registry consumers. Orchestrators may write additional private attributes using the same API.

Directories are created with mode `0755`; attribute files with mode `0644`. The registry is world-readable — any process may inspect ownership — but only root-writable. Both the `/run/nvme/registry/` root and per-device subdirectories are created on demand by libnvme when a registry entry is first written.

PCIe and apple-nvme controllers are outside the scope of the registry. They are hardware-enumerated by the kernel, never connected through the fabrics path, and already excluded from `nvme disconnect-all` by existing transport-type checks.

---

## 3. Ownership

**Exclusive ownership**: each controller has at most one registered owner at any time.

Ownership identifies **reconciliation authority** — which orchestrator is managing a given controller. This lets other orchestrators leave it alone, in particular skip it during `disconnect-all`.

When a controller is removed by the kernel, its registry entry is deleted (see [Automatic Cleanup](#4-automatic-cleanup)). Any orchestrator may attempt to reconnect; whoever succeeds first writes the new registry entry and becomes the new owner. Prior ownership confers no priority in that race.

### 3.1 CRUD operations and atomicity

Write operations use an atomic `tmp → rename` protocol to prevent corruption under concurrent access from multiple processes:

```
mkstemp(<name>.tmp.XXXXXX)         random suffix, mode 0600 → fchmod 0644
write attribute value + newline
fsync(<name>.tmp.XXXXXX)
rename(<name>.tmp.XXXXXX, <name>)
fsync(registry/<device>/)
```

`mkstemp()` atomically creates the temp file with a random suffix, preventing both name prediction and races between concurrent writers of the same attribute. Readers skip any file whose name contains `.tmp.` — an in-flight temp file is never mistaken for an attribute.

Because attribute files are independent of one another, there is no read-modify-write step: updating one attribute (e.g. `owner`) does not require reading and rewriting others. This eliminates the class of race conditions inherent to formats where the entire record must be rewritten on every update.

| Operation | Mechanism |
|-----------|-----------|
| **C**reate | `rm -rf nvmeN/` then `mkdir(nvmeN/)` then atomic attribute write |
| **R**etrieve | `open()` + `read()` |
| **U**pdate | Atomic attribute write; creates the directory if absent |
| **D**elete | `rm -rf nvmeN/` |

**Create always overwrites.** After a successful connect, the kernel assigns a fresh device instance number `N`. Any pre-existing `nvmeN/` directory in the registry is stale by definition — the kernel just assigned that instance number to a new controller. The old entry is removed and a fresh one is written unconditionally.

### 3.2 No ownership transfer

Ownership is set at connect time and is not transferred between orchestrators during normal operation. Each orchestrator manages the controllers it connected and leaves other controllers alone; the registry makes that partition visible and enforceable. `libnvmf_registry_update()` can update any attribute including `owner`, but changing ownership between orchestrators is not a designed pattern.

This is a cooperative arrangement, not a general arbitration mechanism. nvme-discoverd ships by default; nvme-stas is optional. When both run simultaneously, each manages the controllers it connected — first-connect-wins, no priority scheme, no stealing. The registry does not implement arbitration; the orchestrators are expected to stay in their own lane.

---

## 4. Automatic Cleanup

A udev rule fires on `KOBJ_REMOVE` for NVMe controller devices and removes the corresponding registry directory:

```
ACTION=="remove", SUBSYSTEM=="nvme", KERNEL=="nvme[0-9]*", \
    RUN+="/bin/sh -c '[ -e /dev/%k ] || [ $env{SEQNUM} -le $$(cat /run/nvme/registry/%k/seqnum 2>/dev/null || echo 0) ] || rm -rf /run/nvme/registry/%k'"
```

The rule ships with `libnvme`, so the cleanup mechanism is present whenever libnvme is installed — independent of whether `nvme-cli` is installed.

**Why `%k` is safe.** `%k` expands to the kernel device name (e.g. `nvme3`). For `SUBSYSTEM=="nvme"` the kernel always produces names of the form `nvme[0-9]*`, so path traversal via `%k` is not possible; the `KERNEL==` match makes this constraint explicit and provides defense-in-depth. The rule is also safe when no registry entry exists (unowned controllers, PCIe devices, etc.).

### 4.1 Instance recycling and the cleanup guards

The kernel allocates NVMe controller instance numbers using `ida_alloc()` (`nvme_init_ctrl()` in `drivers/nvme/host/core.c`), which returns the **lowest available** ID. When `nvme4` is removed, its instance number is freed immediately and the very next connected controller may receive the same number. This creates a potential race: the cleanup rule for the old `nvme4` may run after a new controller has already claimed the same ID and written its registry entry, silently deleting a live entry. The guard works as follows:

- **New controller has already appeared**: its char device `/dev/nvme4` exists at the time the remove rule fires; the test is true and `||` short-circuits — `rm` is skipped and the new registry entry is preserved.
- **New controller has not appeared yet**: `/dev/nvme4` is absent; the test is false and `rm` runs, removing the stale old entry.

NVMe controller devices (`nvme0`, `nvme4`, etc.) are char devices — `-e` (exists) is the correct test; `-b` (block device) would never match.

A **second guard** closes a narrower race. The `[ -e /dev/%k ]` test and the `rm` run in the same `/bin/sh -c` sub-shell, so an owned connect could in principle complete in the gap between them. To close that, libnvme stamps each entry at connect time with the kernel's global uevent sequence number (`/sys/kernel/uevent_seqnum`, the `seqnum` attribute — §2.1). A stale `remove` for the *old* controller was emitted before the *new* controller's `add`, so its `SEQNUM` is lower than the new entry's stamp; the rule deletes only when the remove event's `SEQNUM` is **greater** than the stamped value (`[ $env{SEQNUM} -le <stamp> ] || rm`). A missing stamp reads as `0`, falling back to the `[ -e ]` check alone.

### 4.2 Why the guard is race-free

There is no false-positive case. devtmpfs device deletion is synchronous: `devtmpfs_delete_node()` dispatches via `devtmpfs_submit_req()`, which calls `wait_for_completion()` and does not return until the node has been removed. Moreover, in `device_del()`, `devtmpfs_delete_node()` is called *before* `kobject_uevent(KOBJ_REMOVE)`. By the time the udev rule fires, `/dev/nvme4` is already gone. The `[ -e ]` test therefore correctly returns false for any device being removed, with no race window.

The guard is also sufficient to protect live registry entries. Two invariants make this so.

First, the kernel creates the device node in devtmpfs synchronously before the connect ioctl returns to userspace — libnvme can only write a registry entry after the node already exists. Therefore, if `[ -e /dev/nvme4 ]` is false at the time the rule runs, no live owned entry can have been written yet, and any entry in the registry for that instance is stale.

Second, when owner is NULL, libnvme explicitly deletes any stale entry for the assigned instance on every successful connect (see §5). So for unowned connections the rule and libnvme both delete the same stale entry — whichever runs first, the result is the same.

The one remaining window — an owned connect completing and writing its entry in the interval between the `[ -e ]` check returning false and `rm -rf` executing — is **closed by the `seqnum` guard** (§4.1, §2.1), not merely improbable: the recycled controller's entry carries a stamp higher than the stale `remove` event's `SEQNUM`, so the rule skips the `rm`. The `[ -e ]` test handles the common case; the `seqnum` comparison handles this sub-shell race. Together they make the cleanup race-free.

### 4.3 Kernel reconnect behavior

During a reconnect within `ctrl-loss-tmo`, the kernel reuses the same `struct nvme_ctrl` — same instance number, same device name, no `KOBJ_REMOVE` event. The registry entry is untouched throughout. Only when `ctrl-loss-tmo` expires and the kernel calls `nvme_delete_ctrl()` does the `KOBJ_REMOVE` event fire and the entry gets deleted. If an orchestrator later establishes a new connection, it creates a fresh registry entry under the new device name.

### 4.4 Boot device protection

Controllers connected during the initramfs stage are automatically protected. The dracut nvmf module invokes `nvme connect-all --nbft`, which goes through libnvme and writes registry entries with `owner=nbft`. `switch_root(8)` explicitly moves `/run` to the new root — *"switch_root moves already mounted /proc, /dev, /sys and /run to newroot"* ([switch_root(8), util-linux](https://man7.org/linux/man-pages/man8/switch_root.8.html)) — so these entries are present in the runtime system with no special handling. No dracut changes are needed beyond using the updated nvme-cli in the initramfs. Boot devices are a first-class case, not a special one.

**`owner=nbft` protects boot-path controllers from all orchestrator policy enforcement.** NBFT controllers carry `owner=nbft` for their entire lifecycle: set by `nvme connect-all --nbft` at initial connect and preserved by nvme-discoverd on every subsequent reconnect (it passes `--owner nbft` rather than `--owner discoverd` for NBFT-sourced controllers). nvme-stas respects the registry unconditionally — `owner=nbft` means nvme-stas never disconnects them regardless of CDC fabric zoning requests, by the same rule that applies to any other orchestrator's controllers — and it logs a warning when it would otherwise have enforced policy against a boot device, so the protection is visible, not silent. The local exclusion list, however, still applies to NBFT controllers: it is the host administrator's explicit, root-only instruction, so nvme-discoverd honours an exclusion entry that matches an NBFT-sourced controller and stops reconnecting it — the supported way to take a boot path out of service for testing or maintenance. `owner=nbft` therefore protects boot devices from *other* orchestrators' policy enforcement, not from the administrator's own deliberate exclusion. Because excluding a boot device can be hazardous, `nvme exclusion add` warns when an entry would match an `owner=nbft` controller (overridable with `--force`).

**FC boot controllers follow a different path.** NBFT is one of three initramfs connection mechanisms; the others are the FC kickstart — issued by dracut's nvmf module (`95nvmf`), whose resulting `FC_EVENT` udev events trigger `nvme connect-all` for FC boot controllers — and the manual `rd.nvmf.*` kernel-command-line arguments parsed by dracut's `74nvmf` module (whose real-world adoption is uncertain). Both the FC-kickstart and `rd.nvmf` connections are made with a NULL owner and are therefore initially unprotected. nvme-discoverd closes this window shortly after startup by adopting the already-connected controllers via idempotent connects carrying `--owner discoverd` (and, for FC, re-issuing the kickstart to pick up any it missed), after which they are protected like any other owned controller. See `rfc-nvme-orchestrator-coexistence.md` §5.2 for the full discussion.

### 4.5 Daemons track device presence independently

Neither nvme-stas nor nvme-discoverd relies on the registry to determine whether a controller is present. Both monitor device removal directly through the uevent stream, and on startup both perform a full audit of the current device tree. The registry is orthogonal to device presence — it records ownership, not existence.

A stale registry entry for a removed controller is a minor inconsistency; the udev rule removes it on the next removal event, and `libnvmf_registry_device_for_each()` already skips entries whose device node is absent. An aperiodic audit is not needed: stale entries (device absent) are caught passively by the udev rule and skipped by iteration; missing entries (device present, no registry entry) are transient and resolved on the next reconnect.

Between removal and reconnect, `disconnect-all` will see the controller as unowned and may disconnect it — the owning daemon reconnects immediately. This is the correct behavior when the registry is temporarily inconsistent.

---

## 5. Orchestrator Context Integration

The owner name is passed at context creation time and applies to every controller connected through that context:

```c
struct libnvme_global_ctx *libnvme_create_global_ctx(FILE *fp, int log_level,
                                                      const char *owner);
```

`owner` identifies the calling process (e.g. `"stas"`, `"nbft"`, `"discoverd"`). Pass `NULL` if the orchestrator does not participate in the registry — `disconnect-all` will treat controllers connected by this context as unowned.

**`owner` is immutable.** It is set once at context creation and cannot be changed afterwards. There is no setter API. This is intentional: ownership identity is a property of the process, not of individual operations, and making it immutable prevents accidental mid-session identity changes.

After every successful fabrics connect, libnvme performs exactly one registry operation — determined by `owner` at the time the kernel returns the instance number:

- **`owner` non-NULL**: `libnvmf_registry_create_instance()` writes the registry entry for the new controller.
- **`owner` NULL**: `libnvmf_registry_delete_instance()` removes any existing entry for the assigned instance number, clearing stale entries left by a previous owner that held the same devid before it was recycled.

The orchestrator does not need to call any registration function explicitly.

### 5.1 Relation to the `application` parameter

`libnvme_global_ctx` previously exposed an `application` field, set via `libnvme_set_application()`. Its sole purpose was to filter subsystem entries when reading a hand-written JSON config file: at connect time, subsystems tagged with a different application name were skipped. This mechanism assumes all orchestrators share a common JSON config file, which does not hold for the real orchestrator landscape:

- **NBFT** — reads firmware tables from `/sys/firmware/acpi/tables/`; no JSON config
- **nvme-stas** — zeroconf/ZTP via DNS-SD; controllers are discovered dynamically
- **nvme-discoverd** — reads its own INI configuration file (`/etc/nvme/discoverd.conf`); the shared JSON config mechanism that `application` was designed for has no relevance to its workflow.

The ownership registry works across all orchestrators through a shared runtime path (`/run/nvme/registry/`) without any shared config file. `owner` supersedes the `application` field, which is being removed in the v3.0 major version cleanup.

---

## 6. API Reference

All registry functions are available when libnvme is built with fabrics support and are declared in `<nvme/registry.h>`.

Registry writes are handled automatically by the connect path. Two internal functions declared in `private-fabrics.h` are called there; neither is part of the public API: `libnvmf_registry_create_instance(int instance, const char *owner)` writes the registry entry when `ctx->owner` is non-NULL, and `libnvmf_registry_delete_instance(int instance)` clears any stale entry for a recycled device ID when `ctx->owner` is NULL. Both are left out of the following API list.

**Implementation note — parameter sanitization.** The `const char *device` parameter is used as a directory name component under `/run/nvme/registry/`. The implementation validates it against the pattern `nvme[0-9]+` — names that do not match this pattern are rejected with `-EINVAL`. The `const char *attr` parameter is used directly as a filename component under `/run/nvme/registry/<device>/` (e.g. `/run/nvme/registry/nvme3/owner` when `attr="owner"`). The implementation validates `attr` against `[a-zA-Z0-9_-]+` and rejects any value containing `/`, `.`, NUL, or other characters that could cause path traversal.

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

`--force` and `--owner` are mutually exclusive. Both prompt for confirmation when run interactively: if stdin is a terminal (`isatty(STDIN_FILENO)`), `nvme disconnect-all` prints a warning describing the scope and requires the user to type `yes`. Non-interactive invocations (scripts, automation) proceed without prompting — passing the flag is itself the explicit statement of intent.

`--force` warns because it disconnects all controllers regardless of ownership; `--owner <name>` warns because the full scope may not be immediately apparent — `--owner nbft` in particular would target firmware boot volumes.

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
