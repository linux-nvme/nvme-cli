# NVMe Controller Ownership Registry

The registry records **which orchestrator owns each connected NVMe-oF controller**. It is a small, cooperative coordination layer that lets independent tools share a host without stepping on each other's controllers — most importantly, so that a sweeping command like `nvme disconnect-all` does not tear down a connection some other component depends on.

> The code is the source of truth. This document summarizes behavior and intent; for exact signatures see the header kdoc in `src/nvme/registry.h` and the `nvme-registry-*` man pages.

## Why it exists

NVMe-oF connections on a host are rarely managed by a single actor. Independent **orchestrators** — agents that decide on their own which controllers to connect and disconnect — coexist on the same machine and share one flat device namespace (`/dev/nvmeX`), with no record of who created or manages each controller.

This holds even on a plain system with no daemons installed. There are already at least two orchestrators: the **initramfs** (NBFT and FC-kickstart connections made during early boot) and a **human** running `nvme connect-all` / `nvme disconnect-all`. Installing `nvme-discoverd` or `nvme-stas` only adds more.

Not every command is an orchestrator:

- `nvme connect` / `nvme disconnect` — single, targeted actions; here the *human* is the orchestrator, deciding what to connect or disconnect.
- `nvme connect-all` / `nvme disconnect-all` — orchestrating commands that, once invoked, decide on their own. `connect-all` reads a discovery controller's discovery log page (DLP), connects every DLP entry, and follows referrals into further discovery controllers, recursing through several layers; `disconnect-all` tears down across the whole host.
- `nvme discover` — in between: it reads a discovery controller's DLP and prints it, but does not connect DLP entries or follow referrals. It is read-mostly; its only state-changing option is `--persistent`, which keeps the discovery connection itself.

The trigger was [issue #2913](https://github.com/linux-nvme/nvme-cli/issues/2913): `disconnect-all` has host-wide scope but no way to tell a boot-critical NBFT connection — or one a daemon depends on — from a throwaway manual connect, so it would disconnect them all. To coordinate, an orchestrator must know who owns what.

**This is why the registry is a new kind of state for `nvme`.** `nvme` already reads configuration (host identity, saved connections) and kernel state from sysfs, but it kept no memory of what it had *done* — each invocation was independent. The registry is that memory: runtime state `nvme`/libnvme writes itself, automatically, as a controller is connected (under `/run` — per-boot, not across reboot), recording which orchestrator owns each controller and read back by a later invocation or any other tool on the host.

The registry is a **cooperative tool, not an enforcement mechanism**. Every orchestrator runs as root and could disconnect anything regardless. The registry simply lets well-behaved tools avoid doing so by accident.

## What it is

The registry lives under `/run/nvme/registry/` — runtime state that is tied to controller lifecycle and does not survive a reboot. It mirrors the sysfs convention: one directory per live controller, one plain-text file per attribute.

```
/run/nvme/registry/
    nvme1/
        owner
        seqnum
    nvme3/
        owner
        seqnum
```

```sh
$ cat /run/nvme/registry/nvme3/owner
nbft
```

- **Absence means unowned.** A controller with no directory (or no `owner` file) is managed by nobody. There is no explicit "unowned" marker.
- The well-known attribute is **`owner`** — the orchestrator identity string (e.g. `stas`, `nbft`, `discoverd`). Orchestrators may write additional private attributes; unknown attributes are ignored by everyone else.
- libnvme also writes a reserved **`seqnum`** attribute next to `owner` — the value of `/sys/kernel/uevent_seqnum` captured at connect. It is internal bookkeeping for the cleanup rule (see *Automatic cleanup*); orchestrators neither set nor read it.
- Directories are `0755`, attribute files `0644`: **world-readable, root-writable**. Both the root and per-device directories are created on demand on first write.
- Writes are atomic (`mkstemp` → `fsync` → `rename`), so concurrent writers never corrupt an entry and readers never see a half-written value.
- Controllers the kernel manages directly — PCIe and other memory-based transports — are out of scope: they are not reached over a fabric, and `disconnect-all`'s transport-type check already excludes them.

## Setting an owner

An orchestrator declares its identity once, then every controller it connects through that context is registered automatically on a successful connect:

```c
struct libnvme_global_ctx *ctx = libnvme_create_global_ctx(...);
libnvme_set_owner(ctx, "stas");   /* registers owner=stas on every connect */
```

A process that does not call `libnvme_set_owner()` produces **unowned** connections. On connect, libnvme writes the entry when an owner is set — stamping it with the current `/sys/kernel/uevent_seqnum` (used by the cleanup rule below) — and clears any stale entry for a recycled instance number when it is not.

From the CLI, pass `--owner NAME` to register ownership at connect time:

```sh
nvme connect     --owner discoverd ...
nvme discover    --owner discoverd ...
nvme connect-all --owner discoverd ...
nvme connect-all --nbft                 # NBFT controllers, owner=nbft
nvme connect-all --owner boot --nbft    # NBFT controllers, owner=boot (overrides nbft)
```

`nvme connect-all --nbft` records `owner=nbft` automatically to protect firmware boot volumes. That `nbft` is only a default, though: an explicit `--owner NAME` given alongside `--nbft` overrides it, so `nvme connect-all --owner NAME --nbft` records the controllers as `NAME`. A plain `--nbft` (no `--owner`) keeps `owner=nbft`, which is what lets existing boot scripts get ownership for free without being changed. Without `--owner` and without `--nbft`, connections are unowned.

## Automatic cleanup

A controller's entry must be removed once the controller goes away, or stale entries accumulate and a recycled device name looks owned. **Creation and removal deliberately live in different places.** Entries are *written* by libnvme on connect (see *Setting an owner* above) because only the connecting process knows the owner — it lives in that process's libnvme context, never in sysfs or the uevent — so nothing else, a udev rule included, could supply it. *Removal* needs no owner, only the device name, and it must happen even when the kernel drops a controller on its own (connectivity loss, `ctrl-loss-tmo` expiry) with no orchestrator involved, and even on a host running no orchestrator daemon at all. So removal is driven by the device-removal event and performed by a single, always-present agent — udevd: exactly one party cleans up, and it works with no daemon required.

libnvme ships a udev rule for exactly this. The udev daemon — present on essentially every system — removes a controller's registry entry when the kernel removes the controller:

```
ACTION=="remove", SUBSYSTEM=="nvme", KERNEL=="nvme[0-9]*", \
    RUN+="/bin/sh -c '[ -e /dev/%k ] || [ $env{SEQNUM} -le $$(cat /run/nvme/registry/%k/seqnum 2>/dev/null || echo 0) ] || rm -rf /run/nvme/registry/%k'"
```

(`$$` passes a literal `$` to the shell; `$env{SEQNUM}` is the remove event's sequence number, substituted by udev.)

**Why removal is guarded.** udev rules run asynchronously: udevd processes a `remove` uevent some time *after* the kernel emits it. Meanwhile the kernel is free to recycle the just-freed instance number — it allocates the lowest available id, so the very next controller to connect can be handed the same `nvmeN`. This opens a rare race: a controller is removed and, at almost the same instant, a new one is connected and inherits its id, all before udevd gets around to running the remove rule for the old controller. By the time that rule finally fires, `nvmeN` already refers to a *different*, live controller that has written its own registry entry — and a blind `rm` would clobber it.

Concretely, the dangerous interleaving for the name `nvme4`:

1. The kernel removes the old `nvme4`, frees instance 4, and emits a `remove` uevent — now queued in udevd.
2. Before udevd runs that queued rule, a new controller connects. The kernel allocates the lowest free instance — 4 again — creates `/dev/nvme4` (devtmpfs, synchronously), and libnvme, *in the connecting process*, writes `/run/nvme/registry/nvme4/owner`.
3. udevd finally runs the queued `remove` rule for the *old* `nvme4`. Without a guard it would `rm -rf /run/nvme/registry/nvme4` and delete the **new, live** controller's entry.

The rule defends against this in two layers.

**First, the `[ -e /dev/%k ]` check.** devtmpfs removes a controller's device node *synchronously*, before the kernel emits `KOBJ_REMOVE`, so for the controller actually being removed `/dev/nvmeN` is already gone, whereas a recycled-and-live `nvmeN` exists again. If `/dev/nvmeN` is absent the entry is presumed stale; if it exists the id has been recycled, `[ -e /dev/%k ]` is true, the `||` short-circuits, and `rm` is skipped — preserving the new owner's entry. This catches the common recycling case.

**Second, the `seqnum` comparison, which closes the residual window.** The device-existence check alone still leaves a sub-shell TOCTOU: the new controller could create `/dev/nvme4` and write its entry in the instant between `[ -e ]` returning false and `rm` running. To close it, libnvme stamps each entry at connect with the global, monotonic `/sys/kernel/uevent_seqnum`, and the rule removes only when the *remove* event's own `SEQNUM` (from the udev event environment) exceeds that stamp. The stale `remove` for the old `nvme4` was emitted *before* the new `nvme4`'s `add`, so its `SEQNUM` is necessarily lower than the new entry's stamp: the comparison holds, the `||` short-circuits, and the entry survives — independent of timing or scheduling. A genuine removal of the current controller carries a `SEQNUM` higher than that controller's own connect-time stamp, so its entry is removed as intended. (An entry with no stamp — e.g. one written by an older libnvme — compares as `0`, and the rule falls back to the device-existence check alone.)

**Entries appear and disappear atomically.** A new entry would still be vulnerable for the instant between creating its directory and writing the `seqnum` file — the rule could read the missing stamp as `0` and delete the entry the library is still populating. libnvme avoids this by building each entry in a temporary directory, writing its attributes, and `rename()`-ing it into place, so an entry is only ever observed complete or absent. Library-driven removals are atomic the same way: the entry is renamed to a hidden sibling and then purged. This is why a missing stamp means a *legacy* entry from an older libnvme, never a half-written one. (The udev rule's own `rm -rf` is not atomic, but it only ever deletes an entry that is already going away.)

Note that udevd serialising udev *events* does not cover this race: the new controller's entry was written by libnvme during `connect()` — not by a udev rule — so udevd never ordered that write against the remove rule. The two signals the rule does rely on — live device-node state and the monotonic `seqnum` stamp — are exactly what distinguishes a stale entry from a recycled-and-live one without depending on event ordering.

Because the rule lives in libnvme, cleanup works whenever libnvme is installed, independent of nvme-cli.

## `disconnect-all` behavior

This is the payoff. `disconnect-all` respects ownership by default:

| Invocation | Disconnects |
|---|---|
| `nvme disconnect-all` | only **unowned** controllers (safe default) |
| `nvme disconnect-all --owner NAME` | only controllers owned by `NAME` (confirmation required) |
| `nvme disconnect-all --force` | **all** fabric controllers regardless of ownership (confirmation required) |

`--owner` and `--force` are mutually exclusive. Both prompt for a typed `yes` when stdin is a terminal; non-interactive callers (scripts) proceed, since passing the flag is itself the statement of intent.

In every case, controllers the kernel manages directly (PCIe and other memory-based transports) are left alone — the transport-type check excludes non-fabric controllers before ownership (or `--force`) is even considered, so `--force` cannot reach them. This means `nvme disconnect-all --force` behaves exactly like the original `nvme disconnect-all` did: it tears down every fabric controller and never touches locally-attached devices. The ownership-aware default is the only new behavior layered on top.

By contrast, `nvme disconnect <device>` targets one named controller and always disconnects it — the caller's intent is unambiguous, so no guardrail applies.

## Inspecting the registry

```sh
nvme registry list                       # all live entries
nvme registry retrieve <device> -a <attr>
nvme registry update   <device> -a note -V "boot-path SAN"
nvme registry delete   <device> [-a <attr>]   # whole entry, or one attribute
nvme list -v                             # adds an Orchestrator column: owner,
                                         # '-' (unowned), or 'kernel' (PCIe)
```

Changing an owner (`update -a owner`) or removing an entry (`delete`) can stop an orchestrator from protecting a controller, so when run interactively these prompt for a `[y/N]` confirmation (default no). Updates to other attributes, non-interactive callers, and the C and Python APIs proceed without prompting. This is a guard against accidental mistakes, not access control — anyone with root can edit the files under `/run/nvme/registry/` directly.

## Further reading

- `src/nvme/registry.h` — full API kdoc
- `Documentation/nvme-registry-*.txt` — man pages for the CLI commands
