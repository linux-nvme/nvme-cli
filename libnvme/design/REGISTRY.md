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
    nvme3/
        owner
```

```sh
$ cat /run/nvme/registry/nvme3/owner
nbft
```

- **Absence means unowned.** A controller with no directory (or no `owner` file) is managed by nobody. There is no explicit "unowned" marker.
- The well-known attribute is **`owner`** — the orchestrator identity string (e.g. `stas`, `nbft`, `discoverd`). Orchestrators may write additional private attributes; unknown attributes are ignored by everyone else.
- Directories are `0755`, attribute files `0644`: **world-readable, root-writable**. Both the root and per-device directories are created on demand on first write.
- Writes are atomic (`mkstemp` → `fsync` → `rename`), so concurrent writers never corrupt an entry and readers never see a half-written value.
- Controllers the kernel manages directly — PCIe and other memory-based transports — are out of scope: they are not reached over a fabric, and `disconnect-all`'s transport-type check already excludes them.

## Setting an owner

An orchestrator declares its identity once, then every controller it connects through that context is registered automatically on a successful connect:

```c
struct libnvme_global_ctx *ctx = libnvme_create_global_ctx(...);
libnvme_set_owner(ctx, "stas");   /* registers owner=stas on every connect */
```

A process that does not call `libnvme_set_owner()` produces **unowned** connections.

What a connect does to the entry depends on the owner and on whether the kernel just created the controller:

| owner | new controller | already connected |
|---|---|---|
| a name | write the entry, overwriting any existing one | write the entry (an explicit claim) |
| never set | clear the entry | leave the entry alone |
| set to `""` | clear the entry | clear the entry (an explicit disown) |

A new controller is cleared because it cannot legitimately be owned by anybody: the entry can only be what a removed controller with the same name left behind. An already-connected controller may belong to another orchestrator, so an unstated intent must not touch it.

From the CLI, pass `--owner NAME` to register ownership at connect time:

```sh
nvme connect     --owner discoverd ...
nvme discover    --owner discoverd ...
nvme connect-all --owner discoverd ...
nvme connect-all --nbft                 # NBFT controllers, owner=pre-os
nvme connect-all --owner boot --nbft    # NBFT controllers, owner=boot (overrides pre-os)
nvme connect     --owner= ...           # explicitly disown
```

`nvme connect-all --nbft` records `owner=pre-os` automatically to protect firmware boot volumes. That `pre-os` is only a default, though: an explicit `--owner NAME` given alongside `--nbft` overrides it, so `nvme connect-all --owner NAME --nbft` records the controllers as `NAME`. A plain `--nbft` (no `--owner`) keeps `owner=pre-os`, which is what lets existing boot scripts get ownership for free without being changed. Without `--owner` and without `--nbft`, new connections are unowned and an already-connected controller keeps whatever entry it has.

`pre-os` is the owner of the pre-OS environment, the firmware and the initrd, whatever technology set up the connection. Its old name `nbft` is the same owner: `--owner nbft` records `pre-os`, and an `nbft` entry an initrd with an older nvme-cli recorded matches `pre-os` (`libnvmf_owner_equal()`, `libnvmf_registry_attr_equal()`), for example in `nvme disconnect-all --owner pre-os`.

An empty `--owner=` is the explicit disown, and it beats the `--nbft` default: `nvme connect-all --owner= --nbft` leaves the controllers unowned.

## Stale entries

Nothing removes the entry of a controller the kernel removed, whether an orchestrator disconnected it or the kernel dropped it on its own (connectivity loss, `ctrl-loss-tmo` expiry). The entry stays until the name is used again:

- **A connect replaces it.** The kernel gives a new controller the lowest free instance number, so a removed controller's name comes back soon. The connect that gets it writes or clears the entry (see *Setting an owner*), in the connecting process, right after the kernel returned the instance number.
- **Readers skip it.** `libnvmf_registry_retrieve()`, `libnvmf_registry_attr_equal()`, `libnvmf_registry_attr_for_each()` and `libnvmf_registry_device_for_each()` treat an entry whose controller is not in sysfs (`/sys/class/nvme/nvmeN`) as absent. `nvme registry delete` removes one by hand.

The kernel and the tools are asynchronous: a uevent reaches userspace after the kernel already moved on, and by then the name can belong to another controller. So the registry is kept by the processes that connect, which know what they just did, and not by a udev rule that acts on a removal some time later. 3.0 to 3.2 shipped such a rule (`70-nvmf-registry.rules`); a queued REMOVE event could delete the entry the next controller with the same name had just written.

Known limitation: a controller that gets a reused name without going through libnvme's connect, e.g. from a tool on libnvme 1, does not replace the entry, and reads as owned by the old owner. Mixing libnvme 1 and libnvme 3 tools that connect controllers on one host is not supported.

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

## `connect-all` / `discover --device` behavior

The exclusion list governs connections that don't exist yet; the registry governs ones that already do. Enumerating a discovery controller's log page is an operation on a live controller, so `nvme connect-all --device <dev>` and `nvme discover --device <dev>` check that controller's registry owner before proceeding: an unregistered or matching-owner DC proceeds, but a DC owned by someone else is skipped with a log line, regardless of whether `--owner` was given — there is no ownerless exemption, since the DC's ownership extends to everything discovered through it.

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
