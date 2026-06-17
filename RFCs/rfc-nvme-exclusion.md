# NVMe-oF System-Wide Exclusion List

## 1. Purpose

Multiple NVMe-oF orchestrators can run simultaneously on the same Linux host. The Ownership Registry (see `rfc-nvme-registry.md`) prevents accidental disconnects of controllers managed by another orchestrator. But it cannot prevent unwanted *connects*: ownership is tied to a live kernel controller instance (`nvmeX`), which disappears on disconnect — taking the ownership record with it.

Connect prevention requires a mechanism based on stable transport identifiers — NQN, address, interface — rather than ephemeral device names. The system-wide exclusion list at `/etc/nvme/exclusions/` is that mechanism.

The exclusion list is **human-administered**. Orchestrators do not write to it — it is for the local administrator to configure which controllers orchestrating tools should not connect to. This keeps responsibility boundaries clean: no inter-daemon writes, no callback protocol, no IPC coupling. Each orchestrator reads files independently; a human is the source of policy.

The design center is **auto-discovered** controllers — those that appear dynamically via mDNS browsing or CDC DLP responses — where there is no configuration entry to remove in order to suppress an unwanted connection. The canonical use cases are: blocking a specific mDNS-discovered DC, and blocking all connections over a specific network interface. A controller that is explicitly listed in a static configuration file is suppressed by removing the config entry; the exclusion list is not a substitute for configuration management.

---

## 2. Directory and Location

Single directory: `/etc/nvme/exclusions/` — persistent across reboots.

Orchestrators monitor this directory via inotify and rebuild their effective exclusion set on any file change. Writes by the `nvme exclusion` command are atomic (write to temp file + `rename()`), so inotify always sees a complete file, never a partial write. A short soak timer debounces rapid successive writes before triggering a reconciliation pass.

`nvme-stas` does not write to this directory. Neither does nvme-discoverd. No daemon writes to it.

---

## 3. What Can Be Excluded

Three common use cases, in decreasing order of frequency:

- **Exclude a network interface** — a single `host-iface=<iface>` entry prevents NVMe-oF connections where the orchestrator pins the connection to that interface. Useful to ensure connections never happen over a management NIC. See §3.1 for the matching semantics and limitations.
- **Exclude a Discovery Controller** (CDC or DDC) — a single DC entry blocks all IOCs behind it, since orchestrators never fetch the DLP of an excluded DC. Particularly useful when mDNS discovery is active, since mDNS-discovered DCs have no per-entry config option to suppress them.
- **Exclude an individual IOC** — for finer-grained control; supported but rarely needed in practice.

### 3.1 Interface exclusion semantics

A `host-iface=` entry is effective only for TCP connections: `host_iface` is not used by RDMA or FC transports, so `libnvmf_exclusion_match()` receives `host_iface=NULL` for those and a `host-iface=` entry will never match them.

For RDMA and FC, the local endpoint is identified by `host-traddr` instead — the source IP address for RDMA, the host port name (`nn-0x…:pn-0x…`) for FC. A `host-traddr=<addr>` exclusion entry therefore provides the equivalent of interface exclusion for those transports: it blocks all connections originating from that RDMA source address or FC HBA port.

A `host-iface=` entry matches only when the orchestrator explicitly passes the interface name. If the connection has no interface pinning (`host_iface=NULL`), the entry does not match — NULL means "not pinned to any interface", not "match all interfaces".

nvme-stas applies interface pinning to all auto-discovered controllers: for DLP responses, it pins IOC connections to the interface used to reach the DC; for mDNS-discovered DCs, it pins to the interface where the advertisement arrived. nvme-discoverd will apply the same pinning for mDNS-discovered connections when `iface-pinning=true`; this is a future capability (mDNS release, not part of the initial nvme-discoverd release — see §10 Future Release in `rfc-nvme-discoverd.md`).

The limitation is manually configured `controller=` entries that omit `host-iface=` — those connections are not matched by a host-iface-only exclusion entry, since no interface is specified in their connection parameters.

---

## 4. File Format

Each `.conf` file in the directory holds multiple entries — one `exclusion =` line per entry, using the same semicolon-separated key=value syntax as nvme-stas:

```ini
exclusion = host-iface=enp0s8
exclusion = transport=tcp;traddr=fe80::2c6e:dee7:857:26bb
exclusion = nqn=nqn.2014-08.org.nvmexpress:uuid:some-subsystem
exclusion = transport=tcp;traddr=192.168.1.10;trsvcid=4420;nqn=nqn.2014-08.org.nvmexpress:uuid:...
```

A **minimal-match** approach is used: only the fields present in the entry are checked. An entry with only `host-iface=enp0s8` matches every controller reachable on that interface, regardless of transport, address, or NQN.

Multiple `.conf` files are allowed — one per administrative boundary (e.g. `admin.conf`, `site-policy.conf`, `user.conf`). All files in the directory are merged; the effective exclusion set is their union.

**Unknown keys are fatal.** An exclusion entry containing a key that is not recognized by the parser is invalid. The entry is logged at error level and never matched — it does not silently pass. This prevents a mis-typed or future-format key from being treated as "match everything" or quietly ignored.

**Notes on the format choice:**

- Consistent with nvme-stas `stafd.conf`/`stacd.conf` — administrators familiar with nvme-stas will recognize it immediately.
- Simple enough to parse with a small custom parser; no external library dependency.

---

## 5. Managing Exclusions with `nvme exclusion`

`nvme exclusion` is implemented as an nvme-cli plugin under `plugins/exclusion/`, following the same convention as `nvme registry` (`plugins/registry/`).

Two interaction modes are supported:

- **`nvme exclusion edit --name <NAME>`** — interactive (`vipw`-style): opens `<NAME>.conf` in `$EDITOR` with a file lock held. Best for multi-entry changes in a single editing session.
- **`nvme exclusion add/remove`** — scripted: each command writes atomically. Best for automation, scripts, and `nvme disconnect --exclude`.

### 5.1 List-level operations

| Command | Effect |
|---------|--------|
| `nvme exclusion create --name <NAME>` | Creates `/etc/nvme/exclusions/<NAME>.conf` |
| `nvme exclusion delete --name <NAME>` | Removes the named exclusion list entirely |
| `nvme exclusion edit --name <NAME>` | Opens `<NAME>.conf` in `$EDITOR` with a lock; validates and commits atomically on close |

(All commands take `--name`/`-N`; `add` also takes `--entry`/`-e`.)

### 5.2 Interactive editing (`nvme exclusion edit`)

Mirrors `vipw`/`vigr`: copy `<name>.conf` to a temp file, acquire a lock, launch `$EDITOR` (fall back to `vi` if `$EDITOR` is unset), and on editor close validate the file syntax. If valid, atomically rename the temp over the original — inotify fires exactly once at that point, after the complete edited file is in place. If invalid, report the errors and offer to re-edit; the original file is untouched.

The lock file is `/etc/nvme/exclusions/<name>.lock` and contains the PID of the editing process. A stale lock (PID no longer alive) is broken automatically. This prevents two concurrent interactive editors on the same list. CRUD commands do not acquire the lock — their individual atomic writes are inherently safe without it.

### 5.3 Entry-level operations

| Command | Effect |
|---------|--------|
| `nvme exclusion list` | Lists all exclusion list names (files) in the directory |
| `nvme exclusion list --name <NAME>` | Lists all entries in `<NAME>.conf` |
| `nvme exclusion add --name <NAME> --entry <ENTRY>` | Appends one entry to `<NAME>.conf` (atomic write) |
| `nvme exclusion remove --name <NAME>` | Interactive: lists entries with a throwaway sequential number, prompts for which to remove, then removes by exact content match (atomic write) |

`remove` has no non-interactive form and entries have no persistent ID — nothing in the system removes entries programmatically (orchestrators never write to the exclusion list; see §1), so a numbered prompt scoped to a single command invocation is sufficient and avoids any need for a stable identifier.

---

## 6. API Reference

### 6.1 Exclusion List API

Declared in `<nvme/exclusion.h>`, following the same convention as `<nvme/registry.h>`. Available when libnvme is built with fabrics support.

```c
/*
 * Check whether a controller matches any entry in the system-wide exclusion
 * list. Called by orchestrators before connecting. @tid carries the
 * controller's transport parameters; any field within it may be NULL. A NULL
 * field that IS present in an entry causes that entry not to match — NULL means
 * "this connection has no value for this field" (e.g. no interface pinning), not
 * "match any value". Fields absent from the entry are not checked.
 * Returns true if the controller is excluded, false otherwise.
 * Returns false (not excluded) if the exclusion directory cannot be read.
 *
 * Note: takes a &struct libnvmf_tid (the same TID object used throughout the
 * fabrics API) rather than seven separate string arguments — fewer call-site
 * mistakes and no positional-argument confusion.
 */
bool libnvmf_exclusion_match(const struct libnvmf_tid *tid);

/*
 * Validate an exclusion entry string ("key=value;...") without touching the
 * filesystem: returns true when every key is known and at least one recognized
 * field is present, false otherwise. Use to pre-check hand-edited files.
 */
bool libnvmf_exclusion_entry_valid(const char *entry);

/**
 * Address comparison: `traddr` and `host_traddr` values are compared using
 * libnvme's existing controller-matching logic — the same function used by
 * `nvme list` and the discovery path to identify already-connected controllers.
 * This handles normalization for all transport types: TCP and RDMA addresses
 * are parsed and compared as IP addresses (so `fe80::1` and
 * `fe80:0:0:0:0:0:0:1` compare equal, and IPv4-mapped IPv6 addresses are
 * canonicalized); FC WWN transport addresses (`nn-0x…:pn-0x…`) are compared
 * case-insensitively. Naive case-sensitive string comparison of transport
 * addresses is never used. If address parsing fails for any field (e.g. a
 * malformed address in the entry), the entry does not match — fail-open,
 * logged at warning level.
 */

/*
 * Iterate over the names of all exclusion lists in the directory.
 * Invokes cback for each .conf file found; the name passed to cback is
 * the basename without the .conf suffix.
 * Returns 0 on success, negative errno if the directory cannot be opened.
 * Returns 0 when the directory does not exist (nothing configured).
 */
int libnvmf_exclusion_list_for_each(
        void (*cback)(const char *name, void *user_data),
        void *user_data);

/*
 * Iterate over all entries in a named exclusion list.
 * Invokes cback for each entry with the raw semicolon-separated
 * key=value entry string (e.g. "transport=tcp;traddr=192.168.1.10").
 * The raw string is the stable, ABI-safe representation; callers
 * that need structured access can parse it themselves (e.g. with
 * libnvmf_tid_parse() for controller TIDs).
 * Returns 0 on success, -ENOENT if the list does not exist,
 * negative errno otherwise.
 */
int libnvmf_exclusion_entry_for_each(
        const char *name,
        void (*cback)(const char *entry, void *user_data),
        void *user_data);

/*
 * Create a new exclusion list.
 * Creates /etc/nvme/exclusions/<name>.conf.
 * Returns 0 on success, -EEXIST if the list already exists,
 * negative errno otherwise.
 */
int libnvmf_exclusion_create(const char *name);

/*
 * Delete an exclusion list.
 * Removes /etc/nvme/exclusions/<name>.conf entirely.
 * Returns 0 on success, -ENOENT if the list does not exist,
 * negative errno otherwise.
 */
int libnvmf_exclusion_delete(const char *name);

/*
 * Add an entry to a named exclusion list. Writes atomically.
 * entry is a semicolon-separated key=value string
 * (e.g. "transport=tcp;traddr=192.168.1.10").
 * Creates the list if it does not exist.
 * Returns 0 on success, negative errno otherwise.
 */
int libnvmf_exclusion_add(const char *name, const char *entry);

/*
 * Remove an entry from a named exclusion list by exact content match.
 * entry must match, byte-for-byte, a string as returned by
 * libnvmf_exclusion_entry_for_each(). Writes atomically.
 * Returns 0 on success, -ENOENT if the entry or list does not exist,
 * negative errno otherwise.
 */
int libnvmf_exclusion_remove(const char *name, const char *entry);
```

### 6.2 Python Bindings

The Python bindings expose only the read-only surface — `exclusion_match()`, `exclusion_lists()`, `exclusion_entries()` — as pure Python in a `%pythoncode` block in `nvme.i`. There is no Python `exclusion_add()`/`exclusion_remove()`/`exclusion_create()`/`exclusion_delete()`. Management of the exclusion list is human-only, and that's exactly what the `nvme exclusion` command family is for (§5); a Python API for add/remove/create/delete would imply those operations are meant to be driven programmatically, which contradicts the human-administered design (§1). The same reasoning extends to shell scripts calling `nvme exclusion`: a one-shot `nvme exclusion add` during initial host provisioning is reasonable, but any other operation — and certainly `remove` — needs an informed human, not automation.

`exclusion_entries(name)` is a generator that yields an `entry` `dict` per entry — each key=value pair of the semicolon-separated entry string becomes a dict item. Python callers get structured access with no extra parsing step. It does not expose an entry ID — there is no entry ID concept anywhere in the system. `nvme exclusion remove <name>` is interactive only: it lists entries with a throwaway sequential number scoped to that one invocation and removes by exact content match (§5.3).

```python
from libnvme import nvme

# --- Runtime check (called by orchestrators before connecting) ---------------

if nvme.exclusion_match(host_iface='enp0s8'):
    return  # this interface is excluded — do not connect

if nvme.exclusion_match(transport='tcp', traddr='192.168.1.10', subsysnqn='nqn.2014-08...'):
    return  # this controller is excluded

# --- Read-only inspection -----------------------------------------------------

# Iterate over all lists and their entries
for name in nvme.exclusion_lists():
    for entry in nvme.exclusion_entries(name):
        print(f'{name}  {entry["transport"]}  {entry.get("traddr", "*")}')

# Managing entries (add/remove/create/delete) is not exposed in Python —
# use the `nvme exclusion` command family instead.
```

`exclusion_match()` implements the same minimal-match semantics as the C `libnvmf_exclusion_match()`: for each field present in the exclusion entry, the caller's corresponding parameter must equal the entry's value. If the caller's parameter for an entry field is `None`, the entry does not match — `None` means "this connection has no value for this parameter" (e.g. no interface pinning), not "match any value". Fields absent from the exclusion entry are not checked regardless of what the caller passes. Callers should pass the full set of connection parameters; unset parameters are passed as `None`.

The directory path defaults to `/etc/nvme/exclusions` but can be overridden via the `NVME_EXCLUSION_DIR` environment variable, enabling tests to run without root access.

### 6.3 Key-Value Utilities

*Intentionally not provided.* An earlier draft proposed general-purpose
`libnvme_key_value_list_parse()` / `libnvme_key_value_list_free()` helpers in
`<nvme/util.h>`. They were dropped: `libnvmf_tid_parse()` already converts a
semicolon-separated key=value string into a controller TID — which covers the
actual need — and the exclusion matcher parses entries internally. A standalone
key-value API can be added later if a third consumer appears.

---

## 7. Enforcement Model

Enforcement is cooperative: each orchestrator reads the exclusion list at startup and on inotify change, and skips connecting any controller that matches an exclusion rule. libnvme does not enforce the exclusion list — it is a local administrator policy, not a system-level enforcement mechanism.

### 7.1 NBFT controllers are exempt

nvme-discoverd does not honor exclusion list entries that match NBFT-sourced controllers. Boot-path controllers are firmware-defined connections required for the host's own operation; an exclusion entry targeting a boot device represents a misconfiguration. nvme-discoverd logs a warning and reconnects unconditionally — the override is explicit and visible, not silent.

`nvme connect-all --nbft` is also exempt: when the `--nbft` flag is present, the exclusion list is not consulted. NBFT connections are firmware-defined and required for the host's own operation; an exclusion entry cannot veto them.

### 7.2 Exclusions are forward-only

When an exclusion is added, orchestrators stop connecting matching controllers in the future. Controllers that were already connected are not disturbed.

To also disconnect an existing controller, use `nvme disconnect --exclude`, which derives an exclusion entry from the controller's sysfs attributes — transport, traddr, trsvcid, and subsystem NQN are always included; host-iface is included when the connection is pinned to an interface — writes it to `/etc/nvme/exclusions/user.conf` first, then disconnects. Writing the exclusion first ensures it is in place before the device removal event triggers orchestrator reconnect logic.

**Soak-timer race.** Orchestrators debounce rapid inotify changes to the exclusion directory with a short soak timer. If `nvme disconnect --exclude` writes an exclusion entry and a device removal event fires before the soak timer expires, an orchestrator may attempt a reconnect before it has processed the new exclusion. To close this window, orchestrators must re-read the exclusion list from disk on *every* connect decision — not only after the soak timer fires. The in-memory exclusion set (rebuilt after the soak timer) is used for proactive filtering (e.g. skipping DLP entries); the on-disk re-read is the definitive check immediately before writing to `/dev/nvme-fabrics`.

### 7.3 Raw commands bypass the exclusion list

`nvme connect` and `nvme disconnect` are targeted, unconditional operations — the caller specifies a single controller and the command executes without consulting any policy mechanism. `nvme connect` always connects regardless of policy; the caller's intent is explicit. (In the orchestrator hierarchy defined in `rfc-nvme-orchestrator-coexistence.md`, raw commands are called Tier 1 commands.)

If a user manually connects a controller that is in the exclusion list, the controller stays connected until the user explicitly removes it. nvme-discoverd leaves it alone — it never disconnects. nvme-stas may still disconnect it if CDC fabric zoning (TP8010) demands: nvme-stas skips only controllers owned by another orchestrator; unowned connections are fair game for zoning enforcement.

---

## 8. Authority Hierarchy

The exclusion list acts as a **local veto**: an exclusion entry prevents orchestrators from connecting to a controller even if that controller appears in a DLP returned by a CDC (Centralized Discovery Controller) that controls fabric zoning. The CDC is not notified and remains unaware of the local restriction. The local administrator can therefore restrict which controllers this host connects to independently of what the fabric permits — a local exclusion entry can override a CDC's positive recommendations.

CDC-driven disconnects are scoped to what nvme-stas already owns: if nvme-stas sees a controller removed from a CDC's DLP, it disconnects that controller only if nvme-stas owns it or the controller is unowned. A controller owned by another orchestrator is left alone regardless of what the CDC says; the local exclusion list plays no role in that decision either way.

The two mechanisms are complementary: the exclusion list governs what gets connected in the first place; the ownership registry governs what gets disconnected. Neither can override an explicit ownership claim by another orchestrator.

---

## 9. Relation to the Ownership Registry

The Ownership Registry and the exclusion list solve complementary halves of the orchestrator coexistence problem:

| Mechanism | Prevents | Keyed on |
|---|---|---|
| Ownership Registry | Accidental disconnects | Ephemeral device name (`nvmeX`) |
| Exclusion List | Unwanted connects | Stable transport identifiers (NQN, address, interface) |

Together they close the loop: the registry ensures orchestrators leave each other's live connections alone; the exclusion list ensures they never start a connection that was deliberately excluded.

See `rfc-nvme-orchestrator-coexistence.md` for how these two mechanisms fit into the broader NVMe-oF orchestrator ecosystem.
