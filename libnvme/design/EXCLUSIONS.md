# NVMe-oF Exclusion List

The exclusion list lets a local administrator name NVMe-oF controllers that **no orchestrator may auto-connect**. It is a small, cooperative coordination layer — the administrator's opt-out — that sits alongside the [ownership registry](REGISTRY.md): the registry records *who owns* a controller, while the exclusion list keeps chosen controllers *out of every orchestrator's reach entirely*.

> The code is the source of truth. This document summarizes behavior and intent; for exact signatures see the header kdoc in `src/nvme/exclusion.h` and the `nvme-exclusion-*` man pages.

## Why it exists

NVMe-oF connections on a host are rarely managed by a single actor. Independent **orchestrators** — agents that decide on their own which controllers to connect — coexist on the same machine: the **initramfs** (NBFT / FC-kickstart boot connections), a **human** running `nvme connect-all`, and daemons such as **nvme-discoverd** or **nvme-stas**. An orchestrator that browses mDNS or walks a discovery log page will, left to itself, connect *everything* it finds.

Sometimes that is exactly wrong. An administrator may need to keep a particular subsystem, target, or whole transport out of service — a controller under maintenance, a misbehaving target, a path reserved for another host — without having every orchestrator on the box reconnect it the moment it is torn down. There is no per-controller "do not connect" switch in the kernel, and telling each orchestrator separately does not scale and does not cover the ones not yet installed.

Crucially, the connection intent often comes from a source the administrator **cannot edit**, which is what makes a host-wide opt-out necessary rather than merely convenient:

- **NBFT controllers** are described by a firmware boot table configured in UEFI — there is no host-side text entry to comment out. Excluding the controller is the only way to stop an orchestrator from (re)connecting an NBFT path, for example to take it out of service during testing.
- **Discovered controllers** — a target returned as a DC's discovery log page entry (DLPE), or a controller announced over mDNS — are advertised by the fabric at runtime, not listed in any file on the host. There is nothing local to remove.

For all of these the exclusion list is the only local lever: the one place an administrator can say "not this one", regardless of where the connection request originated.

The exclusion list is that switch: a single, host-wide, admin-authored statement of intent that every cooperating orchestrator consults before connecting. Like the registry, it is a **cooperative tool, not an enforcement mechanism** — every orchestrator runs as root and *could* connect anything. The list simply lets well-behaved tools refrain by agreement.

## What it is

The exclusion list lives in `/etc/nvme/exclusions.conf`, with optional named drop-in lists under `/etc/nvme/exclusions.conf.d/` — **persistent administrative configuration** (in `/etc`, hand-authored, surviving reboot). This is the opposite of the registry, which is *runtime* state under `/run` written by the library itself. The exclusion list is written by a human (or by `nvme disconnect --exclude` on their behalf) and read by orchestrators.

```
/etc/nvme/
    exclusions.conf          # the default list; disconnect --exclude appends here
    exclusions.conf.d/       # optional named drop-in lists
        maintenance.conf
        lab.conf
```

The main `exclusions.conf` is the **default list**, and `nvme disconnect --exclude` appends to it. Additional **named lists** are kept as drop-in files under `exclusions.conf.d/` — the name is just an organizing label an administrator can create for a purpose (e.g. `maintenance`) and remove wholesale when done. This mirrors the systemd `foo.conf` + `foo.conf.d/` convention. Matching considers the main file **and** every drop-in.

Each file holds an `[exclusions]` INI section with any number of **entries**, one per line:

```ini
# NVMe-oF exclusion list

[exclusions]
exclusion = transport=tcp;traddr=192.0.2.10;trsvcid=4420;nqn=nqn.2024-01.com.example:vol1
exclusion = nqn=nqn.2024-01.com.example:retired

# Exclude the eth3 interface (TCP-only)
exclusion = host-iface=eth3
```

- Lines beginning with `#` are comments; blank lines are ignored.
- Each entry is the literal key `exclusion`, an `=`, then a semicolon-separated list of `key=value` fields. An entry's value is **pure transport identity (TID)** — unlike the connection config's `controller =` lines, it never carries connect tunables, because it *identifies* connections rather than establishing them.
- Entries count only inside the `[exclusions]` section. Other sections are reserved for future use: readers ignore their content, so a file from a newer version stays readable. Reading is fail-safe (a stray or malformed line is skipped); writing through the library is strict (a malformed section header or an entry outside `[exclusions]` is rejected with `-EINVAL`, so an editor cannot persist a silently-disarmed entry).
- Files are installed world-readable, root-writable (`0644`); the drop-in directory is created on demand.
- Writes are atomic (`mkstemp` → `fsync` → `rename`), so concurrent writers never corrupt a list and readers never see a half-written file.

### Entry fields

An entry constrains a connection on one or more of these fields. **The keys are named to match the corresponding `nvme connect` options** — what you would type on the command line is what you put in the file:

| Field (`nvme connect` option) | Meaning |
|---|---|
| `transport` | Transport type: `tcp`, `rdma`, `fc`, `loop` |
| `traddr` | Transport (target) address |
| `trsvcid` | Transport service id (e.g. `4420`) |
| `nqn` | Subsystem NQN |
| `host-traddr` | Host (source) address |
| `host-iface` | Host interface (TCP only) |
| `hostnqn` | Host NQN |
| `hostid` | Host Identifier |

Each key has exactly one spelling — the option name, hyphenated where `nvme connect` hyphenates it (`host-traddr`, `host-iface`). The library's C struct spells the same fields with underscores (`subsysnqn`, `host_traddr`, `host_iface`) because C identifiers cannot contain hyphens, but those code-side names are never valid in a file: an unrecognized key (a typo, or a code-style spelling like `subsysnqn`) makes the whole entry invalid, and an invalid entry matches nothing (see [Match semantics](#match-semantics)).

## Match semantics

A controller is **excluded** if it matches **any** entry in **any** list. Matching is intentionally **minimal — only the fields present in an entry are compared**:

- **Field present in the entry, value present on the connection** → compare the two.
- **Field present in the entry, but the connection has no value for it** → the entry does **not** match. A NULL connection field means "this connection has no value here", never "match anything".
- **Field absent from the entry** → not checked; the entry can still match on its other fields.
- **Unknown key in an entry** → that entry **never matches** (fail-safe): a typo weakens nothing.
- **Empty or field-less entry** → never matches; it cannot be used to exclude everything by accident.

This makes an entry as broad or as narrow as the administrator writes it. `nqn=nqn.…:retired` excludes that subsystem on every transport and address; adding `traddr=` and `trsvcid=` narrows it to one path.

Address fields are compared **address-aware, not byte-for-byte**: equivalent IP spellings match (e.g. a compressed vs. expanded IPv6 address), while Fibre Channel addresses are compared case-insensitively. (The connection's identity is captured in a transport-ID value — see `src/nvme/tid.h` — the same building block the registry and discoverd use for a stable per-connection identity.)

If the exclusion files cannot be read at all, matching returns "not excluded" (**fail-open**): a missing or unreadable list never blocks connectivity.

## How orchestrators use it

Before auto-connecting a discovered controller, a cooperating orchestrator asks libnvme whether it is excluded and, if so, skips it:

```c
if (libnvmf_exclusion_match(ctx, tid))
        continue;   /* administrator excluded this controller */
```

`libnvmf_exclusion_match()` re-reads the files on every call (no caching), so an edit takes effect on the next connection attempt without restarting anything. This is the only API an orchestrator needs; the create/add/remove calls are for the management tooling.

`nvme connect-all` is itself such an orchestrating path, and libnvme's discovery-connect code consults the list on its behalf: before connecting anything it *enumerated* — a Discovery Log Page entry (including referral DCs), an NBFT record, or a controller listed in `discovery.conf` / `config.json` — it checks for a match and skips with an INFO-level "skipping excluded controller" note. A Discovery Controller named explicitly on the command line (`nvme discover` / `connect-all` with an address) is a targeted human action and is not checked — though the entries *it* enumerates still are.

The match is by design *not* allowed to **block** `nvme connect <args>` or `nvme disconnect <device>`: those are single, targeted human actions where the operator's intent is explicit. The list governs the *orchestrating* paths that decide on their own. As a courtesy, `nvme connect --verbose` does *consult* the list and prints a note when the target matches — a heads-up that you are overriding your own opt-out — but it still connects.

## Managing the list

From the CLI (all mutating commands require root):

```sh
nvme exclusion list                       # all lists
nvme exclusion list -N user               # entries in one list
nvme exclusion add    -N user -e "transport=tcp;traddr=192.0.2.10;nqn=nqn.…:vol1"
nvme exclusion remove -N user             # interactively pick an entry to remove
nvme exclusion edit   -N user             # open the list in $EDITOR (visudo-style)
nvme exclusion create -N maintenance      # start a new, empty named list
nvme exclusion delete -N maintenance      # remove a whole list
```

`nvme disconnect --exclude` (`-x`) is the common producer: it records a matching entry in the default list (`exclusions.conf`) *before* tearing a controller down, so an orchestrator sees the exclusion in place before the removal event fires and does not immediately reconnect.

The C API mirrors the commands (`libnvmf_exclusion_create` / `_delete` / `_add` / `_add_ctrl` / `_add_subsysnqn` / `_remove` / `_list_for_each` / `_entry_for_each` / `_match`, plus `_read` / `_write` for the read-modify-write editor), and SWIG exposes `exclusion_lists()`, `exclusion_entries()`, and `exclusion_match()` to Python. `libnvmf_exclusion_add_ctrl()` and `libnvmf_exclusion_add_subsysnqn()` build the entry inside libnvme so callers never encode the on-disk format themselves.

   * [ ] For testing, `libnvme_set_test_base_dir()` reroots the exclusion files (and the registry) under a throwaway `/tmp` sandbox; the shell-invoked `nvme` binary uses `--set-options test-base-dir=/tmp/<sandbox>` for the same purpose. Both are confined to `/tmp` so a test can never redirect writes onto a production path.

## Relationship to the registry

The exclusion list and the ownership registry are complementary cooperative layers for the same goal — letting independent orchestrators share a host:

| | Registry | Exclusion list |
|---|---|---|
| Question | *Who owns this controller?* | *May anyone connect this controller?* |
| Guards against | accidental **disconnect** | accidental **connect** |
| Location | `/run/nvme/registry/` (runtime, per-boot) | `/etc/nvme/exclusions.conf` + `.conf.d/` (persistent config) |
| Author | libnvme, automatically on connect | the administrator (or `nvme disconnect --exclude`) |
| Consulted by | `disconnect-all` (protect owned controllers) | every orchestrator before auto-connecting |

The two are mirror images: the registry stops a sweeping command like `disconnect-all` from **accidentally disconnecting** a controller some component still depends on, while the exclusion list stops an orchestrator from **accidentally (re)connecting** a controller the administrator wants left alone. Both rest on the same transport-ID identity and the same principle: cooperation by convention, not enforcement.

## Further reading

- `src/nvme/exclusion.h` — full API kdoc
- `src/nvme/tid.h` — the transport-ID identity used for matching
- `Documentation/nvme-exclusion-*.txt` — man pages for the CLI commands
- [REGISTRY.md](REGISTRY.md) — the companion ownership registry
