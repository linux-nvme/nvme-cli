# nvme-discoverd — Design RFC

**Author:** Martin Belanger, Dell Technologies Inc.
**Date:** 2026-06-09
**Status:** Design phase

---

## 1. What it is

A persistent daemon that replaces the udev-rule-based `nvme connect-all` approach. Three motivating factors drive its existence:

1. The existing udev rules are complex and hard to maintain.
2. There is no retry on connection failure.
3. Support for mDNS/DNS-SD discovery (TP8009) — planned for a future release (see §10. Future Release).

It ships inside `nvme-cli` (not a separate package), is default-on, and targets the nvme-cli 3.0 / SUSE sl16.2 release cycle.

**Why it cannot be a separate package:** nvme-discoverd replaces components that are already part of the nvme-cli package — specifically the NVMe-oF udev rules and `nvmefc-boot-connections.service`. Additionally, nvme-discoverd invokes `nvme connect` at runtime, so nvme-cli must be installed for the daemon to function. The two are inseparable: nvme-discoverd is nvme-cli's built-in connectivity manager.

**Build option — static replacement, not dynamic masking:** nvme-discoverd is controlled by a meson build option (`-Dnvme-discoverd=enabled|disabled`). When enabled, `nvme-discoverd.service` is installed and the NVMe-oF udev rules, `nvmefc-boot-connections.service`, `nvmf-autoconnect.service`, and the FC udev rules are **not** installed — discoverd handles all of that. When disabled, those components are installed as before and nvme-discoverd is absent. There is no dynamic switching: the choice is made at package build time, and the replaced components are simply not installed rather than masked. This avoids any ambiguity during daemon restarts, crashes, or maintenance windows.

**Some design choices in the initial release:** the exclusion list mechanism, the `zeroconf` config knob, and the `zeroconf=false` default — are deliberately shaped by the anticipated future mDNS support, even though mDNS itself is not yet implemented.

nvme-discoverd is **connect-only by design**. It never disconnects a live controller during steady-state operation; disconnects occur only via systemd unit stop at shutdown (`ExecStop=`), and `StopUnit` is invoked only for devices already removed by the kernel. This eliminates the entire connect/disconnect ordering complexity at the cost of TP8010 Fabric Zoning support, which belongs to nvme-stas.

---

## 2. Explicitly Out of Scope

| Item | Reason |
|------|--------|
| TP8010 Fabric Zoning | Requires stateful DLPE delta + disconnect; belongs to nvme-stas |
| Stateful DLPE delta reconciliation | No disconnect mechanism; connect-only by design |
| NCC bit, DIM registration | CDC-specific; TP8010 only |
| nvme-stas third-party callback model | Registry + exclusion list achieve the same coordination without coupling |
| Legacy `discovery.conf` | New project; `discoverd.conf` only |
| D-Bus for discoverd's own client-facing IPC | discoverd's socket uses varlink (§3.7); systemd unit management currently requires D-Bus — see §3.9 for rationale |

---

## 3. Architecture

### 3.1 Event loop

Single `sd_event` loop from libsystemd. No threads in the daemon itself. nvme-discoverd is built when `want_fabrics` is set and libsystemd is available — both are required. If either condition is not met, nvme-discoverd is not built.

The source lives in a new `nvme-discoverd/` directory under the nvme-cli root.

### 3.2 Transient Unit Design

Every write to `/dev/nvme-fabrics` blocks the calling process in uninterruptible D state until the kernel completes or times out the connection. To prevent this from stalling the event loop, nvme-discoverd never writes to `/dev/nvme-fabrics` directly. Instead, it delegates all connections — both DC and IOC — to child processes managed by systemd transient units.

A transient unit is created via the D-Bus method `org.freedesktop.systemd1.Manager.StartTransientUnit`. No unit file is written to disk and no daemon-reload is required; the unit exists only in systemd's memory. `Type=oneshot` is used because the connection process exits immediately after writing to `/dev/nvme-fabrics` — the kernel maintains the connection afterwards. `RemainAfterExit=yes` keeps the unit active after the process exits so that systemd continues to consider it part of the ordering graph at shutdown time.

#### 3.2.1 Unit naming

discoverd provides the unit name to `StartTransientUnit`; systemd does not generate one. The name is derived from the connection's TID — the tuple `(transport, traddr, trsvcid, subsysnqn, host_traddr, host_iface, host_nqn)` — by concatenating the fields in that canonical order and computing an MD5 hash over the result, encoded as 32 lower-case hexadecimal characters. The unit name is `nvme-discoverd-<32hexchars>.service`.

This is the same approach (and the same field order) as nvme-stas's TID hashing in `staslib/trid.py`, and produces a stable, deterministic name with no coordinator state needed. MD5 here is not a security primitive — collision resistance against an adversary is not required — so discoverd can embed a small standalone MD5 implementation with no crypto-library dependency and no FIPS-mode concern.

#### 3.2.2 Shutdown ordering and transport awareness

systemd reverses `After=` ordering at shutdown, so `After=network.target` on a TCP or RDMA unit means: start after `network.target` at boot, stop before `network.target` at shutdown. With `RemainAfterExit=yes` keeping the unit active, this reversal is enforced.

Units are transport-aware: TCP and RDMA units include `After=network.target`; FC units omit it entirely since Fibre Channel is independent of the IP network stack. All RDMA variants — pure InfiniBand, RoCEv1, RoCEv2, and iWARP — are treated uniformly. For pure InfiniBand (dedicated IB HCA with no `net_device`) the dependency is satisfied trivially with no practical effect on ordering, but distinguishing it from RoCEv2/iWARP at unit generation time would add implementation complexity for no real benefit.

This transport-aware approach solves the shutdown ordering problem described in [issue #3309](https://github.com/linux-nvme/nvme-cli/issues/3309), which cannot be fixed with `nvme connect-all` since it mixes all transport types in a single invocation.

All transient units — every transport — additionally carry `Before=nvme-discoverd.service`. At start time this edge is inert: discoverd is already running when it creates the unit, and ordering constraints only apply to jobs queued in the same transaction. At shutdown the order reverses: discoverd terminates before any connection unit runs its `ExecStop=` disconnect. This matters because discoverd reacts to device removals (§3.5) — if it were still running while shutdown tears down the connections, it would observe each removal and try to schedule reconnects: `RestartUnit` for TCP/RDMA, or worse, a fresh FC kickstart leading to `StartTransient` of brand-new units mid-shutdown. Stopping discoverd first guarantees the daemon never sees shutdown-time removals.

The devid files that the units' `ExecStop=` lines need remain available after discoverd stops because `RuntimeDirectoryPreserve=yes` keeps `/run/nvme/discoverd` intact (§3.8). Note that `Before=` is an ordering edge only, not a requirement dependency: stopping or restarting discoverd alone does not stop the connection units — they keep running unmanaged, exactly as the warm-restart design intends (§3.6).

**RDMA variants:**

| Variant | Physical hardware | Protocol | `network.target` |
|---------|-----------------|----------|-----------------|
| Pure InfiniBand | Dedicated IB HCA | IB native — no IP | Trivially satisfied — no practical effect |
| RoCEv1 | Ethernet NIC | IB over Ethernet (L2 only, not routable) | Yes |
| RoCEv2 | Ethernet NIC | IB over UDP/IP (port 4791) — routable | Yes |
| iWARP | Ethernet NIC | RDMA over TCP/IP — routable | Yes |

RoCEv2 is the primary NVMe-oF RDMA variant. It uses UDP rather than TCP because the InfiniBand reliable-connected transport in the RNIC already handles reliability at the hardware level — TCP would be redundant overhead. RoCEv1 is a legacy L2-only variant; iWARP runs RDMA over the full TCP stack, trading PFC lossless fabric requirements for higher latency.

#### 3.2.3 Disconnect at unit stop

The actual disconnect is performed by `ExecStop=`, which runs `nvme disconnect -d <device>` before systemd proceeds to deactivate `network.target`. Without `ExecStop=`, stopping the unit would be a no-op — there is no process to kill in a `Type=oneshot` unit, and the kernel connection would remain alive when the network interface tears down, causing I/O errors on in-flight NVMe requests.

#### 3.2.4 Capturing the device name

The device name is not known at unit creation time; it is assigned by the kernel when `/dev/nvme-fabrics` is written and returned synchronously to `nvme connect` on success. For idempotent connections (`--idempotent`) — in other words, connections that already exist — libnvme detects the existing connection via sysfs scan before writing to `/dev/nvme-fabrics`, so the device name is already known from sysfs.

A new `--devid-file` option allows `nvme connect --devid-file FILE` to capture it in both cases: on success, `nvme connect` writes the `nvmeX` name to `FILE`; `ExecStartPost=`, `ExecStop=`, and `ExecStopPost=` all read it back. The path uses systemd specifiers — `%t` (runtime directory, `/run` for system services) and `%N` (unit name without the `.service` suffix) — so the same literal string works across all four lines without discoverd needing to embed anything at unit creation time.

#### 3.2.5 State directory hooks

`ExecStartPost=` runs immediately after `ExecStart=` succeeds. It reads the device name from the `.devid` file, creates the controller state directory (`/run/nvme/discoverd/controllers/<devid>/`, described in §3.6), and writes the unit name (`%n`) to `unit` within that directory. `ExecStartPost=` only runs when `ExecStart=` succeeds — if `nvme connect` fails, no state directory is created, which is the correct behaviour. systemd specifier `%n` expands to the full unit name (e.g. `nvme-discoverd-3cbb0e7a51f04c9c9d4f2b67c3a2e8a0.service`) before the shell sees it.

`ExecStopPost=` runs after `ExecStop=` regardless of whether `ExecStop=` succeeded. It reads the devid from the `.devid` file, removes the file, then removes the controller state directory — handling both cleanup steps atomically from within the unit. Together with `ExecStartPost=`, state directory management in the unit-stop path is self-contained inside the unit.

The exception is device removal by the kernel: when a `KOBJ_REMOVE` event fires for a controller, discoverd's event handler removes the state directory from `controllers/` and the corresponding `units/%N.devid` file (§3.5). All other creates and deletes are performed by the unit itself.

`TimeoutStopSec=10` bounds the shutdown wait: `nvme disconnect` on an unresponsive target typically takes 1–3 s; without a bound, systemd's 90 s default would apply. `CollectMode=inactive-or-failed` tells systemd to garbage-collect failed transient units automatically once no job is pending — without it, units whose initial `nvme connect` failed would linger in the unit table until discoverd explicitly called `ResetFailedUnit`.

#### 3.2.6 Units survive discoverd restarts

The transient unit's `ExecStart=` line contains the full `nvme connect` invocation with all parameters baked in. Because transient units belong to systemd (not to discoverd), they **survive a discoverd crash or restart** — they remain `active (exited)` in systemd until explicitly stopped. While the unit is alive, `RestartUnit` is sufficient to reconnect using the original parameters without re-fetching anything from any source. If the unit has been garbage-collected (e.g. after a failed connect attempt), discoverd falls back to `StartTransient` using parameters from its in-memory caches.

### 3.3 DC connection management

For DC connections, the transient unit runs `nvme connect --keep-alive-tmo=30`:

```ini
[Unit]
Description=NVMe Discovery Controller connection to <subnqn>
Before=nvme-discoverd.service
# TCP and RDMA connections only — omit for FC units
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nvme connect \
  --transport=<trtype> \
  --traddr=<traddr> \
  --trsvcid=<trsvcid> \
  --nqn=<subnqn> \
  --hostnqn=<hostnqn> \
  [--host-traddr=<host_traddr>] \
  [--host-iface=<host_iface>] \
  --keep-alive-tmo=30 \
  --idempotent \
  --owner discoverd \
  --devid-file=%t/nvme/discoverd/units/%N.devid
ExecStartPost=-/bin/sh -c 'DEV=$(cat %t/nvme/discoverd/units/%N.devid 2>/dev/null) && mkdir -p %t/nvme/discoverd/controllers/$DEV && echo %n > %t/nvme/discoverd/controllers/$DEV/unit'
ExecStop=-/bin/sh -c 'DEV=$(cat %t/nvme/discoverd/units/%N.devid 2>/dev/null); [ -n "$DEV" ] && [ "$(cat %t/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "%n" ] && nvme disconnect -d $DEV'
ExecStopPost=-/bin/sh -c 'DEV=$(cat %t/nvme/discoverd/units/%N.devid 2>/dev/null); rm -f %t/nvme/discoverd/units/%N.devid; [ -n "$DEV" ] && [ "$(cat %t/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "%n" ] && rm -rf %t/nvme/discoverd/controllers/$DEV'
TimeoutStopSec=10
CollectMode=inactive-or-failed
```

`nvme connect` is used instead of `nvme discover --persistent` because `nvme discover` always issues a Get Log Page immediately — nvme-discoverd fetches the DLP separately via ioctl after the DC device appears, so it would be redundant.

`--keep-alive-tmo=30` sets the keep-alive timeout explicitly: `nvme connect`'s automatic 30 s discovery KATO only fires for the well-known discovery NQN (`nqn.2014-08.org.nvmexpress.discovery`). NVMe Base Spec 2.x allows DCs to use a unique NQN; for those, neither nvme-cli nor the kernel recognizes the connection as a discovery session, and the kernel falls back to its 5 s I/O-controller default (`NVME_DEFAULT_KATO`). Setting the option explicitly gives every DC session the DC-appropriate 30 s value regardless of which NQN it uses.

DC units whose TID is present in the NBFT cache carry `--owner nbft` instead of `--owner discoverd` — the NBFT records the Discovery Controller the firmware used to find the boot targets. The substitution rule is shared with IOC units and described in §3.4.

`nvme connect` establishes the connection and exits; the kernel maintains the session and delivers future AENs on it. nvme-discoverd monitors for the resulting device-add event; after a ~1 s sysfs soak (sysfs attributes are not fully populated at the moment the `add` event fires), it checks the `cntrltype` attribute to confirm the device is a Discovery Controller. Once the device name is known (e.g., `/dev/nvme0`), libnvme is called directly (`libnvme_scan_ctrl` + `libnvmf_get_discovery_log`) to fetch the DLP via Get Log Page — a short ioctl on the already-connected device, not a `/dev/nvme-fabrics` write.

Each DLPE in the DLP is processed based on its `subtype`:
- `NVME_NQN_NVME` — I/O Controller: create a transient IOC unit.
- `NVME_NQN_DISC` — Referral to another DC: create a transient DC unit for the referred DC. When that DC's device appears, its DLP is fetched and processed identically. Referral chains of arbitrary depth are followed naturally through the event loop — no explicit recursion is needed. Note: `nvme connect-all` traverses referrals the same way; `nvme discover` does not (it only fetches one level). If a referral DC becomes permanently unreachable, its per-DC DLP cache entry is eventually evicted; IOCs reachable exclusively through that referral chain fizzle out naturally as their connections drop and are not reconnected. This is intentional — the desired set is derived from current cache state. See §11 (Open Questions) for a proposed stale-cache aging mechanism.
- `DUPRETINFO` flag set — duplicate information: skip.

Future AENs from the DC arrive as udev events and trigger a DLP re-fetch.

For full event loop protection, the libnvme DLP fetch can be moved to a thread in a future hardening pass.

When the DC is a DDC, the Get Log Page command may set the PLEO (Port Local Entries Only) bit to request only entries reachable through the port that received the command. Per NVMe Base Spec 2.3 §5.2.12, PLEO is a DDC capability (not CDC). nvme-stas already uses it; nvme-discoverd should set it too — deferred to a future release.

### 3.4 IOC connection management

IOC connections use the same transient unit design:

```ini
[Unit]
Description=NVMe I/O Controller connection to <subnqn>
Before=nvme-discoverd.service
# TCP and RDMA connections only — omit for FC units
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nvme connect \
  --transport=<trtype> \
  --traddr=<traddr> \
  --trsvcid=<trsvcid> \
  --nqn=<subnqn> \
  --hostnqn=<hostnqn> \
  [--host-traddr=<host_traddr>] \
  [--host-iface=<host_iface>] \
  --idempotent \
  --owner discoverd \
  --devid-file=%t/nvme/discoverd/units/%N.devid
ExecStartPost=-/bin/sh -c 'DEV=$(cat %t/nvme/discoverd/units/%N.devid 2>/dev/null) && mkdir -p %t/nvme/discoverd/controllers/$DEV && echo %n > %t/nvme/discoverd/controllers/$DEV/unit'
ExecStop=-/bin/sh -c 'DEV=$(cat %t/nvme/discoverd/units/%N.devid 2>/dev/null); [ -n "$DEV" ] && [ "$(cat %t/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "%n" ] && nvme disconnect -d $DEV'
ExecStopPost=-/bin/sh -c 'DEV=$(cat %t/nvme/discoverd/units/%N.devid 2>/dev/null); rm -f %t/nvme/discoverd/units/%N.devid; [ -n "$DEV" ] && [ "$(cat %t/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "%n" ] && rm -rf %t/nvme/discoverd/controllers/$DEV'
TimeoutStopSec=10
CollectMode=inactive-or-failed
```

**NBFT-sourced units use `--owner nbft`.** The NBFT can describe Discovery Controllers as well as I/O subsystems — the firmware records the DC it used to discover the boot targets — so this rule applies to both unit types. When discoverd creates a transient unit, DC or IOC, for a controller present in its NBFT cache, it substitutes `--owner nbft` for `--owner discoverd` in the `ExecStart=` line — the only difference between an NBFT unit and a regular unit. Because `RestartUnit` replays the original `ExecStart=` verbatim, all subsequent reconnects also carry `--owner nbft`, preserving the `owner=nbft` lifetime invariant without any reconnect-time special-casing. At unit-creation time, discoverd selects the template variant based on a cache lookup: TID present in the NBFT cache → `--owner nbft`; otherwise → `--owner discoverd`.

**Collision detection for static config and DLP entries.** The NBFT cache lookup runs regardless of which source initiated the connection. If a static `controller=` entry (in `[Discovery Controllers]` or `[I/O Controllers]`) or a DLPE matches a TID already in the NBFT cache, discoverd logs an error-level journal message (the entry is a misconfiguration — NBFT is the authoritative source for that controller) and uses `--owner nbft` rather than `--owner discoverd`. The NBFT source takes precedence; connectivity is not disrupted, but the duplicate entry should be removed from the config or the DC that advertises it should be excluded.

### 3.5 Unit lifecycle

nvme-discoverd is not passive. When the kernel removes a controller (`ctrl-loss-tmo` expires or manual disconnect), a udev `remove` event fires. The daemon removes the state directory and in-memory entry, then decides whether to reconnect. Two checks must pass before a reconnect is scheduled:

1. **Exclusion check** — the controller must not match any entry in the system-wide exclusion list (see `rfc-nvme-exclusion.md`). Exception: NBFT-sourced controllers bypass this check — discoverd reconnects them unconditionally regardless of any matching exclusion entry, and logs a warning.
2. **Desired-set check** — the controller must still be part of the desired connection set: present in the config file, in the NBFT cache, or in a current cached DLP. nvme-discoverd never disconnects controllers in response to configuration changes during normal operation, but when a controller is removed by an external entity (kernel timeout, manual disconnect, another orchestrator), it must verify the controller is still wanted before reconnecting. A controller that was removed from the config or dropped from all DLPs while the connection was live should not be silently reconnected.

### 3.6 State Files

Location: `/run/nvme/discoverd/controllers/` (tmpfs — does not survive reboot).

One **directory** per controller, named by the kernel-assigned device name (`nvmeX`) — the same convention used by the ownership registry. Each directory contains a single file — the one piece of information that sysfs does not carry:

```
/run/nvme/discoverd/controllers/
  nvme0/
    unit    # systemd transient unit name
            # (e.g. "nvme-discoverd-3cbb0e7a51f04c9c9d4f2b67c3a2e8a0.service")
```

All transport parameters (transport, traddr, trsvcid, subnqn, hostnqn, host-traddr, host-iface, cntrltype) are read from sysfs when needed — storing them in state files would duplicate data the kernel already owns authoritatively. The connection origin (nbft, manual, DLP-sourced) is re-derived at reconnect time: a TID (Transport ID) present in the NBFT cache or config cache is classified accordingly; a TID absent from both is assumed to be DLP-sourced.

Discovery Log Page caches are **not** persisted to disk. They are in-memory only and rebuilt by re-fetching DLPs from each DC as it reconnects at startup. See §4. In-Memory Caches.

State directories are created by `ExecStartPost=` inside the transient unit itself (see §3.2.5), not by discoverd. For normal connections, `nvme connect` writes the kernel-assigned device name to `--devid-file`; `ExecStartPost=` reads it and creates the state directory. For pre-existing connections (idempotent path), libnvme finds the matching device via sysfs scan before returning, so `--devid-file` is populated from the sysfs-known name — `ExecStartPost=` then creates the state directory identically. In both cases, discoverd knows the state directory exists as soon as the `JobRemoved` signal arrives with a success result.

At startup, discoverd cross-references state files against sysfs. This serves three purposes:

- **Warm restart** — on intentional restart, reconstruct the connected set immediately from state files without re-running discovery.
- **Crash recovery** — same as warm restart but unplanned; the startup audit catches any devices lost during the restart window.
- **Late-start resilience** — adopt connections already present in sysfs (e.g. NBFT boot controllers from initramfs).

| State file | In sysfs | Meaning | Action |
|---|---|---|---|
| yes | yes | Normal — connection alive | Adopt; rebuild in-memory entry |
| no | yes | Pre-existing connection (e.g. initramfs) | Create transient unit; write state file ¹ |
| yes | no | Device removed while discoverd was down | ² |

**¹ Pre-existing connection (no state file):** all connection parameters are read from sysfs. Before proceeding, discoverd applies two filters.

First, it checks the desired set: the controller's TID must be present in the NBFT cache or the config cache. Controllers not in either cache are outside discoverd's scope — discoverd skips them and logs an informational message. (DLP-sourced controllers are not in the desired set at startup since the per-DC DLP caches are not yet warm; if a DC reconnects and its DLP still lists them, they will be connected via the normal DLP processing path.) FC controllers are not subject to this filter: pre-existing FC connections at startup are handled by the kickstart event path — discoverd re-issues kickstart at startup, and the resulting `FC_EVENT=="nvmediscovery"` uevents drive adoption with `--idempotent` for already-connected targets.

Second, discoverd checks the ownership registry. If the controller already has a registry entry and the owner is neither `discoverd` nor `nbft`, discoverd logs a warning and skips this controller — leaving it in the hands of the orchestrator that owns it. This prevents discoverd from inadvertently claiming ownership of a controller managed by nvme-stas or another tool.

If the TID is in the desired set and no entry exists (or the owner is `discoverd` or `nbft`), discoverd calls `StartTransient` using the standard unit template — the `--idempotent` option carried by every unit (§3.3, §3.4) makes `nvme connect` exit 0 when the controller is already connected, so the unit succeeds regardless of whether this invocation did the connecting or a previous one did. This is more precise than the `-` prefix on `ExecStart=` (which suppresses all errors): genuine failures — wrong transport, unreachable target, TLS key missing — still mark the unit as failed.

`nvme connect --idempotent` detects the existing connection via libnvme's sysfs scan without writing to `/dev/nvme-fabrics`; since the device name is known from that scan, it is written to `--devid-file` before returning. `ExecStartPost=` then creates the state directory identically to the normal connect path. discoverd waits for the `JobRemoved` signal: success → the unit is adopted with its state directory in place; failure → the normal reconnect logic handles recovery.

**² Device removed while discoverd was down:** the reconnect decision is origin-aware:

- **TID in NBFT cache or config cache** — schedule `RestartUnit` immediately; these sources are always desired.
- **TID absent from both (DLP-sourced)** — defer until the per-DC DLP caches are warm (all DCs from NBFT and config have reconnected and sent their DLPs). Then apply the desired-set check: if the TID is still in a DC's current DLP, schedule `RestartUnit`; if not, call `StopUnit` — the IOC was removed from the DLP while the daemon was down and should not be reconnected.

Adoption of pre-existing connections is described further in §7. Discovery Sources.

### 3.7 IPC

This section describes nvme-discoverd's own IPC interface — the mechanism by which external clients (CLI plugins, monitoring tools) communicate with the running daemon. This is distinct from the D-Bus interface discoverd uses internally to communicate with systemd (`org.freedesktop.systemd1.Manager.StartTransientUnit` etc.).

nvme-discoverd exposes a varlink interface over `/run/nvme/discoverd.socket`. Compile-time optional. Initial scope: a CLI status plugin (`nvme discoverd status`) — request/reply only, no pub/sub needed.

### 3.8 nvme-discoverd.service

```ini
[Unit]
Description=NVMe-oF Discovery Daemon
Before=remote-fs.target

[Service]
Type=notify-reload
ExecStart=/usr/sbin/nvme-discoverd
Restart=on-failure
RuntimeDirectory=nvme/discoverd nvme/discoverd/units nvme/discoverd/controllers
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
```

`Type=notify-reload` — extends `Type=notify` with integrated reload signalling. On startup, nvme-discoverd calls `sd_notify("READY=1")` once its event loop is running and two fast synchronous steps have completed — parsing the config file and reading the NBFT table — the prerequisites before the daemon is considered operational. NVMe-oF connections themselves are not complete at this point (they are initiated asynchronously after `READY=1`).

On `systemctl reload`, systemd sends SIGHUP directly to the main process — no `ExecReload=` line is needed. nvme-discoverd calls `sd_notify("RELOADING=1")` when it begins processing the reload and `sd_notify("READY=1")` when done; `systemctl reload` blocks until that final `READY=1` arrives, giving callers a proper synchronization point. `sd_notify` uses a plain Unix domain socket (SOCK_DGRAM), not varlink and not D-Bus, so there is no additional IPC dependency. Requires systemd v253 or later.

`Before=remote-fs.target` — the daemon is running before systemd attempts to mount remote filesystems. This is necessary but not sufficient: `READY=1` fires when the event loop is up, not when NVMe-oF connections are complete. The full discovery path — connecting to a DC, retrieving its Discovery Log Page, and connecting each IOC — takes significant time after the daemon signals ready.

Services that need specific NVMe-oF block devices must not rely on `remote-fs.target` alone. They should use the `_netdev` option in `/etc/fstab` or explicit `After=dev-nvmeXnY.device` dependencies to wait for the actual block device node to appear via udev.

`RuntimeDirectoryPreserve=yes` — prevents systemd from removing `/run/nvme/discoverd` when the service stops. Without it, systemd deletes the runtime directory on every stop, restart, or crash (`no` is the default), which would destroy the devid files still needed by active transient units' `ExecStop=` lines and eliminate the state directories that the startup audit relies on for warm-restart and crash recovery.

No `After=network.target` or `After=network-online.target` for the daemon itself — nvme-discoverd does not perform network I/O directly. Only the forked transient units do, and they declare their own network ordering individually. `DefaultDependencies=yes` (the default) implicitly covers `After=sysinit.target` and `After=basic.target`.

### 3.9 Systemd Interface: D-Bus

**Design intent — varlink.** Not depending on D-Bus was a design wish: systemd has been steadily replacing D-Bus interfaces with varlink, and new code should follow that trajectory. However, the varlink interface is incomplete as of today — therefore nvme-discoverd communicates with systemd over D-Bus.

**What systemd varlink provides today.** systemd v261 (in development, unreleased as of this writing) adds `io.systemd.Unit.StartTransient` on the `io.systemd.Unit` varlink interface, accessible over the `/run/systemd/io.systemd.Manager` socket. This method creates transient units and, via streaming mode (`notifyJobChanges`), delivers job-completion notifications equivalent to the D-Bus `JobRemoved` signal.

**Why varlink is not sufficient yet.** `StopUnit`, `RestartUnit`, and `ResetFailedUnit` have no varlink equivalent even in v261. nvme-discoverd needs all three:

- `RestartUnit` — reconnect after a device loss when the unit is still `active (exited)` and its parameters are baked in
- `StopUnit` — stop a unit when the desired-set check determines a DLP-sourced IOC should not be reconnected
- `ResetFailedUnit` — clean up failed units not automatically collected by `CollectMode=inactive-or-failed`

A hybrid approach — varlink for unit creation, D-Bus for stop/restart — would require maintaining two separate IPC connections to systemd. On top of that, `io.systemd.Unit.StartTransient` first appears in v261, which is not yet released and will not be available in the target distributions at the time of the nvme-cli 3.0 / sl16.2 release. The minimum systemd version would jump from v253 (for `Type=notify-reload`) to v261 with no practical benefit in the initial release.

**Current implementation.** nvme-discoverd uses the `org.freedesktop.systemd1.Manager` D-Bus interface for all unit lifecycle operations (`StartTransientUnit`, `StopUnit`, `RestartUnit`, `ResetFailedUnit`, and the `JobRemoved` signal). The D-Bus calls go through `sd-bus`, systemd's own D-Bus implementation, which is part of `libsystemd` — a library nvme-discoverd already depends on for `sd_event`. No additional library dependency is introduced. The D-Bus usage is scoped exclusively to the systemd interface; discoverd's own client-facing IPC (§3.7) remains varlink-only.

**Path forward.** Once `StopUnit`, `RestartUnit`, and `ResetFailedUnit` are available over varlink, discoverd should migrate away from D-Bus entirely. See §11 Open Questions item 5.

---

## 4. In-Memory Caches

Discoverd maintains three in-memory caches in the initial release; a fourth is added with mDNS support. None are persisted to state files — they are rebuilt at startup.

- **NBFT cache** — populated at startup from the NBFT ACPI table; static for the daemon's lifetime.
- **Config cache** — populated at startup from `discoverd.conf`; rebuilt on SIGHUP.
- **Per-DC DLP cache** — a map from DC TID to the set of IOC TIDs in that DC's last-fetched Discovery Log Page. Populated as each DC connects and its DLP is fetched. Updated on each AEN via clean per-DC replacement: `dc_cache[dc_tid] = new_dlp`. No origin tag is needed on individual entries — the per-DC structure provides that naturally.
- **mDNS DC cache** *(future release)* — the set of DC TIDs discovered via mDNS/DNS-SD. Populated dynamically as mDNS advertisements are received; entries age out per `zeroconf-stale-timeout`. See §10. Future Release.

The **desired connection set** is the union of all caches: NBFT cache ∪ config cache ∪ union of all per-DC DLP caches ∪ mDNS DC cache *(future)*. This is a derived view, not a separate data structure; at reconnect time discoverd checks the caches directly.

**FC kickstart has no corresponding cache.** FC-NVMe targets are discovered by writing `add` to `/sys/class/fc/fc_udev_device/nvme_discovery`, which causes the FC HBA firmware to probe all reachable targets and fire `FC_EVENT=="nvmediscovery"` uevents for each. Discoverd creates a transient unit per event without caching the discovered TIDs. The kickstart is re-issued at startup and again whenever an FC controller drops — the fabric's current response is authoritative each time. FC kickstart is to FC what mDNS is to TCP: event-driven, no stale-cache problem, no TID list to maintain. The desired set for FC connections is implicitly defined by what the kickstart currently discovers.

**Origin classification heuristic at startup:** a TID found in a state file that is absent from both the NBFT cache and the config cache is assumed to be DLP-sourced. This is correct in practice — the same TID can appear in both a DLP and the config cache, but NBFT and config entries are checked first; a TID absent from both is classified as DLP-sourced.

---

## 5. Connection Lifecycle and Failure Handling

**Two kernel timeouts to understand:**

- **Initial connect:** `nvme connect` writes to `/dev/nvme-fabrics`; if the target is unreachable the kernel gives up after a transport-dependent timeout (typically a few seconds on TCP; varies for RDMA and FC) and `nvme connect` exits with an error. No device appears; the transient unit goes to `failed`. The kernel does not retry — that is discoverd's job.
- **Lost connectivity (ctrl-loss-tmo):** Once a connection is established and then drops, the kernel retries automatically every `reconnect-delay` seconds (default 10 s) for up to `ctrl-loss-tmo` seconds. The device stays in sysfs throughout. Only when `ctrl-loss-tmo` expires without success does the kernel remove the device and fire a `device remove` uevent. Discoverd does not intervene during the kernel retry loop.

**Sysfs race on device-add:** the kernel sends the `add` uevent slightly before sysfs attributes are fully populated. Discoverd waits ~1 s (soak timer) before reading `cntrltype`, `transport`, `traddr`, etc. from a newly appeared device. This is the same workaround used by nvme-stas.

**Failure detection (initial connect):** discoverd subscribes to the `org.freedesktop.systemd1.Manager.JobRemoved` D-Bus signal for each unit it starts. When the job completes with `done`, the connection succeeded — `ExecStartPost=` has already written the state directory. When the job completes with `failed`, the connection failed; `CollectMode=inactive-or-failed` garbage-collects the unit. discoverd schedules a `StartTransient` call with exponential backoff (1 s, 2 s, 4 s … capped at a configurable maximum). The exclusion list is checked before each retry. No timer is needed — `JobRemoved` is the authoritative completion signal for both new and idempotent connections.

**Retry policy:** discoverd retries indefinitely for all controller types. Manually-configured and DLP-sourced controllers represent deliberate intent — there is no give-up horizon. For mDNS-discovered DCs, `zeroconf-stale-timeout` handles the natural expiry once both the mDNS advertisement and the connection are lost (see §4. In-Memory Caches).

**Device removal:** when `device remove` fires, discoverd removes the state dir and in-memory entry, then makes two checks before deciding to reconnect:

1. **Exclusion check.** If the controller matches an exclusion entry, call `StopUnit` — do not reconnect. Exception: NBFT-sourced controllers (those present in the NBFT cache) bypass this check — discoverd reconnects them unconditionally and logs a warning.
2. **Desired-set check (DLP-sourced IOCs only).** If the TID is not in the NBFT cache, the config cache, or (in a future release) the mDNS DC cache, it is DLP-sourced. Discoverd then checks whether the TID is still present in any DC's per-DC DLP cache. If the IOC is no longer in any current DLP, the DLPE was removed from the DLP while the connection was live — the connect-only design let it persist at that time, but now that the connection has dropped, do not reconnect. Call `StopUnit`.

If both checks pass, the reconnect mechanism depends on transport:

- **TCP and RDMA:** the unit is left `active (exited)` as a reconnect placeholder. After the backoff timer, discoverd calls `RestartUnit` — the unit is still `active (exited)` with all parameters baked in, so no re-derivation is needed. `ExecStop=` and `ExecStopPost=` run as part of the stop phase (cleanup), then `ExecStart=` reconnects with the original parameters. If that reconnect attempt also fails, the unit goes to `failed` and is garbage-collected; subsequent retries use `StartTransient` with parameters taken from discoverd's in-memory caches (NBFT, config, DLP).

- **FC:** discoverd calls `StopUnit` to cleanly remove the old unit (running `ExecStop=` and `ExecStopPost=`), then re-issues kickstart to the FC subsystem. New `FC_EVENT=="nvmediscovery"` uevents arrive for all currently reachable targets, and discoverd creates a new `StartTransient` for each. The fabric's current response is authoritative — there is no cached TID list to replay. For TIDs that are already connected and managed (have a state file), discoverd skips creating a duplicate unit.

The reconnect mechanism therefore depends on transport and unit state:

| Transport | Unit state | Situation | Mechanism |
|---|---|---|---|
| TCP / RDMA | `active (exited)` | device lost by kernel (ctrl-loss-tmo) | `RestartUnit` — parameters baked in |
| TCP / RDMA | `failed` / gone | connect attempt failed, unit garbage-collected | `StartTransient` — parameters from in-memory caches |
| FC | any | device lost, any reason | `StopUnit`; re-issue kickstart; new `FC_EVENT` drives `StartTransient` |

**Recoverable corner case — device removed while discoverd restarts:** the startup audit (state files vs. sysfs cross-reference) detects any `nvmeX` directory whose device is no longer in sysfs. The corresponding unit survived in systemd (it belongs to systemd, not to discoverd), so `RestartUnit` recovers the connection with no extra parameter re-derivation.

**SIGHUP reconciliation:** on config reload, discoverd computes `controllers-to-connect` (NBFT + config entries + active DLP-sourced entries + mDNS DCs) and starts a new `StartTransient` for any TID in `controllers-to-connect` that is not already in the in-memory table. No disconnects are issued — connect-only means there is no `controllers-to-disconnect` to be evaluated. Controllers removed from the config remain connected until `ctrl-loss-tmo` or manual disconnect.

The per-DC DLP cache for a removed DC entry is **not** immediately evicted; it persists until the DC's connection itself drops (ctrl-loss-tmo). Until then, IOCs learned from that DC's DLP remain in the desired connection set. Once the DC connection drops and its DLP cache entry is evicted, IOCs that were in the desired set exclusively via that DC's DLP will not be reconnected if they subsequently drop. IOCs that also appear in another source (a second DC's DLP, a static config entry, or the NBFT cache) remain desired by the union of the remaining sources.

---

## 6. Configuration File

`/etc/nvme/discoverd.conf` — INI-style `key=value`, same format convention as nvme-stas. Reloaded on SIGHUP. INI is chosen over JSON to reduce dependencies and maximize portability, including to minimal and embedded platforms where json-c may not be available.

The config parser follows systemd conventions. Boolean values accept `1`/`yes`/`y`/`true`/`t`/`on` and `0`/`no`/`n`/`false`/`f`/`off` (all case-insensitive), matching the behavior of systemd's `parse_boolean()`. The implementation can be lifted directly from `src/basic/parse-util.c` in the systemd source tree (LGPL-2.1-or-later — compatible with nvme-cli's GPL-2.0-only, provided the SPDX header and copyright notice are preserved).

**Initial release:**

```ini
[Global]
# nbft = true
# zeroconf = false

[Discovery Controllers]
# controller = transport=tcp;traddr=192.168.1.1;trsvcid=8009

[I/O Controllers]
# controller = transport=tcp;traddr=192.168.1.1;trsvcid=4420;nqn=<subsystem-nqn>
```

`nbft` and `zeroconf` both live in `[Global]` — they are discovery source toggles and belong together. `zeroconf` defaults to `false` — the inverse of stafd, for opposite but symmetric reasons. stafd is an optional package; installing it signals that the user wants mDNS-based auto-discovery and is willing to have the host be managed by a Centralized DC (CDC). nvme-discoverd ships with nvme-cli and will be installed on most systems by default, including desktops, laptops, and servers with no NVMe-oF fabric. Enabling mDNS on all of those by default would be *surprising* and *unnecessary* (to say the least).

`[Discovery Controllers]` and `[I/O Controllers]` use `controller=` entries with the same syntax as nvme-stas; all connection parameters are specified per-entry inline, so no global defaults are needed.

Additional options will be added to `[Global]`, `[Discovery Controllers]`, and `[I/O Controllers]` when mDNS is implemented — see §10. Future Release for the full list.

---

## 7. Discovery Sources

### 7.1 Initial release

Discovery sources for the initial release include:

| Event | Purpose |
|-------|---------|
| `SUBSYSTEM=="nvme"`, `NVME_AEN=="0x70f002"` | DC Discovery Log Page changed; re-fetch DLP and create units for new IOCs |
| `SUBSYSTEM=="nvme"`, `NVME_EVENT=="rediscover"`, `cntrltype=="discovery"` | DC reconnected; re-read its DLP |
| Device add (`nvmeX`, `cntrltype=="discovery"`) | DC connection completed; after ~1 s sysfs soak, fetch DLP; IOC entries → create IOC units; referral entries (`subtype=NVME_NQN_DISC`) → create new DC units (followed naturally through the event loop) |
| Device add (`nvmeX`, `cntrltype=="io"`) | IOC connection confirmed in sysfs; state directory already written by `ExecStartPost=` |
| Device remove (`nvmeX`) | Remove state dir and in-memory entry; apply exclusion check, then desired-set check (DLP-sourced IOCs only); if both pass: TCP/RDMA leaves unit `active (exited)` and schedules `RestartUnit`; FC calls `StopUnit` then re-issues kickstart |
| NBFT (`/sys/firmware/acpi/tables/NBFT`) | Read at startup; adopt already-connected boot controllers or connect missing ones (both DCs and IOCs). Also reconnects NBFT-listed controllers that drop mid-run — the NBFT table is static firmware data, so no re-fetch is ever needed. Controlled by `nbft = true|false` (default `true`). Note: discoverd detects NBFT-sourced controllers (they are in its NBFT cache) and passes `--owner nbft` rather than `--owner discoverd` for those reconnects, preserving the original ownership label. Without this, `owner=nbft` would be overwritten with `owner=discoverd`: nvme-stas would be unaffected (it skips any controller it does not own), but `nvme disconnect-all --owner discoverd` would target the controller — and disconnecting a boot-path controller can cause I/O errors or an unbootable system. |
| `/etc/nvme/discoverd.conf` `[Discovery Controllers]` and `[I/O Controllers]` | Both DCs (`controller=` in `[Discovery Controllers]`) and IOCs (`controller=` in `[I/O Controllers]`) entries are reconnected at startup. No legacy `discovery.conf` support |
| FC Kickstart PDUs | Both at startup and on every FC controller drop: write `add` to `/sys/class/fc/fc_udev_device/nvme_discovery` (idempotent), then handle `SUBSYSTEM=="fc"`, `FC_EVENT=="nvmediscovery"` uevents — each event represents one currently reachable FC-NVMe target. Kickstart is the FC reconnect mechanism: the fabric's current response after each re-issue is authoritative, so no TID cache is needed (see §4). Replaces `nvmefc-boot-connections.service` and the FC udev rules; neither is installed when nvme-discoverd is built (see §1. What it is). dracut (`95nvmf`) continues to do the FC Kickstart in the initramfs unchanged |

### 7.2 Planned for a future release

Discovery sources for a future release include:

| Source | Notes |
|--------|-------|
| mDNS/DNS-SD (TP8009) | See §10. Future Release for requirements and design |

---

## 8. Coexistence with nvme-stas

The ownership registry, exclusion list, orchestrator hierarchy, and natural division of labor between nvme-stas and nvme-discoverd are described in `rfc-nvme-orchestrator-coexistence.md`. The full exclusion list design (file format, use cases, `nvme exclusion` command reference, enforcement model) is in `rfc-nvme-exclusion.md`.

nvme-discoverd's role in this framework:

- It registers ownership on every connection via `--owner discoverd` passed to `nvme connect`.
- It monitors `/etc/nvme/exclusions/` via inotify and skips connecting any controller that matches an exclusion entry.
- The exclusion list is included in the initial release (before mDNS) because coexistence should be solved before mDNS is enabled, not after.

---

## 9. Required Changes to Existing nvme-cli Commands

**`nvme connect --idempotent`** — new option. When set and the controller is already connected, `nvme connect` exits 0 (instead of exiting 1 with `ENVME_CONNECT_ALREADY`) and writes the device name (e.g. `nvme3`) to `--devid-file`. libnvme detects the existing connection via sysfs scan without writing to `/dev/nvme-fabrics`; the sysfs-known device name is used for the `--devid-file` write. Used in transient units for pre-existing connection adoption at startup: a connection established by an earlier process (e.g. initramfs NBFT) does not mark the unit as failed, and the device name is still captured in the devid file for `ExecStartPost=`, `ExecStop=`, and `ExecStopPost=` to use.

**`nvme connect --owner <name>`** — new option. Since nvme-discoverd forks `nvme connect` rather than calling libnvme directly, it cannot register ownership in the registry without this option. Both generated DC and IOC units include `--owner discoverd`. When used with `--idempotent`, the registry entry is written using the sysfs-known device ID even when the controller was already connected — so the ownership record is always authoritative regardless of who made the initial connection.

**`nvme connect --devid-file FILE`** — new option. On successful connection, writes the device name (e.g. `nvme3`) to `FILE`. For new connections, the name is returned synchronously by the kernel when `/dev/nvme-fabrics` is written. For idempotent connections (`--idempotent`), libnvme detects the existing connection via sysfs scan without writing to `/dev/nvme-fabrics`; since the device name is known from that scan, it is written to `FILE` before returning. Used by `ExecStartPost=` (to create the state directory), `ExecStop=` (to identify the device to disconnect), and `ExecStopPost=` (to clean up). The path uses systemd specifiers (`%t/nvme/discoverd/units/%N.devid`) so the same literal string works across all four lines without discoverd embedding anything at unit creation time. Files land in `/run/nvme/discoverd/units/` (tmpfs — does not survive reboot).

---

## 10. Future Release: mDNS/DNS-SD (TP8009)

mDNS/DNS-SD discovery allows Discovery Controllers to advertise themselves on the local network with no manual IP configuration on the host. This enables zeroconf networking and zero-touch provisioning — a host boots, discoverd browses `_nvme-disc._tcp`, connects to the DC, retrieves the DLP, and connects to all IOCs, without the administrator having to specify any IP addresses.

mDNS is not part of the initial release. Three prerequisites must be met first:

1. **systemd-resolved minimum version.** Browsing `_nvme-disc._tcp` service advertisements requires systemd v258+ (released September 2025), which introduced `io.systemd.Resolve.BrowseServices` — a varlink streaming subscription that pushes service add/remove events as they occur. Earlier versions of systemd-resolved supported only hostname resolution and DNS-SD service *resolution* (looking up a known service instance by name), but not *browsing* (enumerating all instances of a service type). Requiring v258 avoids an Avahi/D-Bus dependency.

2. **Interface pinning (hard requirement).** mDNS advertisements arrive on a specific network interface. If discoverd connects to the DC over the routing table's default route instead, the connection may land on the management network (typically a slow 1 Gbps link) rather than the high-bandwidth storage fabric. nvme-discoverd must use `SO_BINDTODEVICE` to pin connections to the interface where the advertisement was received — controlled by `iface-pinning=true` (the default). Setting `iface-pinning=false` while `zeroconf=true` is a fatal configuration error. This failure mode has been observed in production (nvme-stas).

3. **nvme-stas coexistence.** The exclusion list cannot solve this: it is system-wide and applies to all orchestrators equally, so an entry that prevents nvme-discoverd from connecting to a DC also prevents nvme-stas from connecting to it. The only correct solution is to enable mDNS in exactly one orchestrator. nvme-stas enforces this: at startup it reads `/etc/nvme/discoverd.conf` and logs an error-level journal entry if `zeroconf=true` is set, prompting the administrator to disable mDNS in one of the two daemons.

**Config additions for the future mDNS release** (not in initial version):

The defaults shown in the tables below are the kernel's own defaults — the values the kernel uses when a parameter is absent from the string written to `/dev/nvme-fabrics` (i.e. `nvme connect` builds the string with only options provided to it). Specifying a value in the config overrides the kernel's default.

These options are particularly important for automatically discovered controllers (mDNS/DNS-SD) because there is no per-entry configuration opportunity for those — unlike manual `controller=` entries where all parameters are specified inline. Note that `iface-pinning` applies independently per section, allowing different interface-pinning policy for DC and IOC connections.

To `[Global]`:

| Option | Default | Description |
|--------|---------|-------------|
| `zeroconf-ip-family` | ipv4+ipv6 | Address family selector for mDNS-discovered DCs (`ipv4`, `ipv6`, or `ipv4+ipv6`). Per spec, a service publisher must advertise all IP addresses of the interface, so receiving both IPv4 and IPv6 for the same DC is common. This option selects which to use, preventing duplicate connections to the same DC. Has no effect on manual `controller=` entries or NBFT entries. |
| `zeroconf-stale-timeout` | 72hours | How long to retain a mDNS-discovered DC after it stops advertising and its connection fails. Without this, auto-discovered DCs that disappear from the network would accumulate as stale entries until the daemon restarts. Values: `-1` (retain forever), `0` (remove immediately), or a time span — a unit-less integer in seconds, or a string such as `72hours`, `3days 5hours`. |

To `[Discovery Controllers]`:

| Option | Default | Description |
|--------|---------|-------------|
| `iface-pinning` | true | For mDNS-discovered DCs, use `SO_BINDTODEVICE` to pin the DC connection to the interface where the advertisement arrived. Has no effect on manually configured `controller=` entries, which specify `host-iface=` directly. **Required** when mDNS is active — `iface-pinning=false` with `zeroconf=true` is a fatal configuration error |
| `hdr-digest` | false | TCP PDU header digest |
| `data-digest` | false | TCP PDU data digest |
| `kato` | 30 | Keep-alive timeout (seconds). 30 s is the correct value for DC sessions; also applied to manually-configured DCs with unique NQNs (see §3.3 DC connection management) |
| `queue-size` | 128 | I/O queue depth |
| `reconnect-delay` | 10 | Reconnect retry delay (seconds) |
| `ctrl-loss-tmo` | 600 | Controller loss timeout (seconds; -1 = retry forever) |
| `disable-sqflow` | false | Disable SQ flow control |
| `pleo` | true | Request Port Local Entries Only from DDCs. When enabled and supported, asks the DDC to return only entries reachable through the port that received the Get Log Page command, avoiding unreachable entries for transports other than the one in use |

To `[I/O Controllers]`:

| Option | Default | Description |
|--------|---------|-------------|
| `iface-pinning` | true | For DLP-discovered IOCs, use `SO_BINDTODEVICE` to pin IOC connections to the same interface used to connect to the DC the DLP was retrieved from. Has no effect on manually configured `controller=` entries, which specify `host-iface=` directly. |
| `hdr-digest` | false | TCP PDU header digest |
| `data-digest` | false | TCP PDU data digest |
| `kato` | 5 | Keep-alive timeout (seconds). The kernel default is 5 s (`NVME_DEFAULT_KATO` in `host/nvme.h`) |
| `nr-io-queues` | (kernel default) | Number of I/O queues created by the driver; kernel determines the default based on CPU count |
| `nr-write-queues` | (kernel default) | Additional queues dedicated to write I/O |
| `nr-poll-queues` | (kernel default) | Additional queues for polling latency-sensitive I/O |
| `queue-size` | 128 | I/O queue depth |
| `reconnect-delay` | 10 | Reconnect retry delay (seconds) |
| `ctrl-loss-tmo` | 600 | Controller loss timeout (seconds; -1 = retry forever) |
| `fast-io-fail-tmo` | -1 | Time (seconds) after which in-flight I/O is failed when the controller is reconnecting. -1 disables fast-fail; I/O is held until `ctrl-loss-tmo` expires. Has no effect on DC connections (no block I/O) |
| `disable-sqflow` | false | Disable SQ flow control |

---

## 11. Open Questions

1. **Kernel uevents vs udev events** — Reading kernel uevents directly avoids the udevd dependency but requires custom filtering and large receive buffers. udev event monitoring is more comfortable but adds latency. Not yet resolved. Note: if udev monitoring is chosen, `nvme-discoverd.service` must add `After=systemd-udevd.service` to ensure udevd is ready before the daemon starts listening for events.

2. **Referral DC and stale DLP cache aging** — If a referral DC (or any configured DC) becomes permanently unreachable, IOCs reachable exclusively through it stop being reconnected once their connections drop and the per-DC DLP cache entry is evicted. A configurable stale-timeout — similar to `zeroconf-stale-timeout` planned for mDNS DCs — applied to all per-DC caches would provide a grace period before dropping the DLP of a defunct DC. Worth considering whether this should be a global DC stale-timeout rather than mDNS-specific.

3. **Shutdown ordering vs. mounted filesystems** — Transient connection units carry only `After=network.target`. This does not guarantee they stop after filesystems mounted from those controllers are unmounted. The standard systemd pattern is `Before=remote-fs-pre.target` on the connection units: at shutdown (ordering reverses), units stop after `remote-fs-pre.target`; `_netdev` mount units have `After=remote-fs-pre.target` and therefore stop before it, ensuring unmount before disconnect. Needs verification and testing before adding to the unit templates.

4. **NBFT root controller at shutdown** — NBFT connection units carry `ExecStop=nvme disconnect`. For a controller backing the root filesystem, this disconnect at shutdown can cause a hang or data loss, since the root filesystem is never unmounted. Standard mitigations include omitting `ExecStop=` from NBFT units, or adding ordering constraints to prevent their stop at shutdown. Design decision needed.

5. **Systemd unit management: migrate to varlink** — discoverd currently uses `org.freedesktop.systemd1.Manager` D-Bus for all unit lifecycle operations. systemd v261 (in development) adds `io.systemd.Unit.StartTransient` over varlink with streaming job-completion notifications, but `StopUnit`, `RestartUnit`, and `ResetFailedUnit` have no varlink equivalent yet. When the full unit lifecycle API is available over varlink, discoverd should migrate away from D-Bus. See §3.9.

---

## 12. Glossary

| Term | Definition |
|------|------------|
| AEN | Asynchronous Event Notification — a kernel mechanism by which an NVMe controller signals the host that something has changed (e.g. the Discovery Log Page was updated) |
| Avahi | Open-source implementation of mDNS/DNS-SD for Linux |
| CDC | Centralized Discovery Controller — a TP8010 discovery controller that aggregates entries from multiple DDCs and manages fabric zoning; requires an NVMe-oF fabric to reach |
| ctrl-loss-tmo | Controller Loss Timeout — the kernel parameter controlling how long to wait before declaring a controller lost and removing it from sysfs |
| D state | Uninterruptible sleep state in the Linux kernel; a process in D state cannot be killed and blocks until the kernel operation it is waiting on completes or times out |
| DC | Discovery Controller — an NVMe-oF controller whose purpose is to return a list of I/O controllers (see DDC and CDC) |
| DDC | Direct Discovery Controller — a discovery controller co-located with the NVM subsystem it advertises; the most common type in NVMe-oF deployments |
| DIM | Discovery Information Management — a TP8010 mechanism by which a DDC registers itself with a CDC |
| DLP | Discovery Log Page — the log page (LID 0x70) returned by a Discovery Controller listing available I/O controllers and/or referral DCs. |
| DLPE | Discovery Log Page Entry — one record within the DLP, describing a single reachable I/O controller or referral DC. |
| DNS-SD | DNS Service Discovery — the protocol used alongside mDNS to advertise and browse named services |
| dracut | The initramfs generator used by most Linux distributions; the `95nvmf` module handles NVMe-oF connectivity during early boot |
| FC | Fibre Channel — a high-speed network technology used as an NVMe-oF transport |
| FC Kickstart | The mechanism that triggers FC-NVMe discovery by writing `add` to `/sys/class/fc/fc_udev_device/nvme_discovery` |
| HCA | Host Channel Adapter — the InfiniBand equivalent of a NIC |
| iface-pinning | nvme-discoverd config option; for mDNS-discovered DCs it binds the DC connection to the interface where the advertisement arrived; for DLP-discovered IOCs it binds the IOC connection to the same interface used to reach the DC; implemented via `SO_BINDTODEVICE`; hard requirement for mDNS |
| IB | InfiniBand — a high-speed interconnect fabric; the underlying transport for RoCEv1, RoCEv2, and pure IB |
| initramfs | Initial RAM filesystem — a minimal root filesystem loaded into memory at boot, before the real root filesystem is mounted |
| IOC | I/O Controller — an NVMe controller that provides access to NVM storage namespaces (as opposed to a Discovery Controller) |
| IPC | Inter-Process Communication |
| iWARP | Internet Wide Area RDMA Protocol — RDMA layered over TCP/IP; used as an NVMe-oF transport |
| kato | Keep-Alive Timeout — how often the host sends a keep-alive to the controller to maintain the connection |
| kdump | Kernel crash dump mechanism; uses its own initramfs environment to capture a memory dump when the primary kernel panics |
| mDNS | Multicast DNS — a zero-configuration protocol that allows devices to announce and discover services on a local network without a central DNS server |
| NBFT | NVM Express Boot Firmware Table — an ACPI table written by firmware that lists the NVMe-oF controllers used to boot the system |
| NCC | Not Connected Count — a TP8010 field indicating how many times a CDC failed to connect to a DDC; used for connection management decisions |
| NQN | NVMe Qualified Name — a unique identifier for an NVMe host or subsystem (e.g. `nqn.2014-08.org.nvmexpress:uuid:...`) |
| NVMe-oF | NVMe over Fabrics — the extension of NVMe to remote transports (TCP, RDMA, FC) |
| PFC | Priority Flow Control — an Ethernet mechanism that prevents packet loss by pausing transmission on a per-priority basis; required for lossless RoCEv2 fabrics |
| PLEO | Port Local Entries Only — a bit in the Get Log Page command that asks a DDC to return only entries reachable through the port that received the command |
| RC | Reliable Connected — the InfiniBand transport type used by NVMe-oF RDMA; reliability is handled in hardware by the RNIC |
| RDMA | Remote Direct Memory Access — a technology that allows direct memory access between two computers without involving the CPU |
| RNIC | RDMA-capable NIC |
| RoCEv1 | RDMA over Converged Ethernet v1 — InfiniBand transport over Ethernet (L2 only; not routable) |
| RoCEv2 | RDMA over Converged Ethernet v2 — InfiniBand transport over UDP/IP (port 4791); the primary NVMe-oF RDMA variant |
| sd\_event | The event loop API provided by libsystemd |
| SIGHUP | Unix signal used to ask a daemon to reload its configuration |
| SO\_BINDTODEVICE | Linux socket option that forces all traffic on a socket to go out through a specific network interface |
| subnqn | Subsystem NQN — the NQN identifying the NVMe subsystem (target) |
| switch\_root | The point in the Linux boot process where the initramfs hands control to the real root filesystem |
| TID | Transport ID — the tuple of transport parameters (trtype, traddr, trsvcid, subnqn, hostnqn, host-traddr, host-iface) that uniquely identifies a controller connection |
| tmpfs | A filesystem backed by RAM (and optionally swap); `/run` is a tmpfs and does not survive reboot |
| TP8009 | NVMe Technical Proposal 8009 — defines mDNS/DNS-SD-based automated discovery of NVMe-oF Discovery Controllers |
| TP8010 | NVMe Technical Proposal 8010 — defines the Centralized Discovery Controller (CDC), fabric zoning, and the DIM registration mechanism |
| traddr | Transport Address — the IP address or FC WWN of the target controller |
| trsvcid | Transport Service ID — the TCP/UDP port number of the target controller |
| trtype | Transport Type — the NVMe-oF transport: `tcp`, `rdma`, or `fc` |
| udev | Linux device manager; processes kernel uevents and manages `/dev` entries |
| uevent | A kernel notification sent to user space (via netlink socket) when a device is added, changed, or removed |
| varlink | A simple IPC protocol used by systemd for service management and inter-daemon communication |
