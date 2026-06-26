# nvme-discoverd — Design RFC

**Author:** Martin Belanger, Dell Technologies Inc.
**Date:** 2026-06-09
**Status:** Design phase

**Terminology:** **DC** = Discovery Controller; **IOC** = I/O Controller; **DLP** = Discovery Log Page; **DLPE** = Discovery Log Page Entry; **TID** = Transport ID — the tuple `(transport, traddr, trsvcid, subsysnqn, host_traddr, host_iface, host_nqn)`; **DDC** = Direct Discovery Controller; **CDC** = Centralized Discovery Controller; **NBFT** = NVMe Boot Firmware Table.

---

## 1. What it is

A persistent daemon that replaces the udev-rule-based `nvme connect-all` approach.

**What it is.** nvme-discoverd is a static-configuration connectivity manager for the host's NVMe-oF fabric connections:

- it works from **static configuration** — it does not do stateful DLP-delta reconciliation, and it carries no per-controller filtering or exclusion logic of its own (the exclusion list is a separate, system-wide mechanism it merely consults);
- it **manages a global resource** — the host's fabric connections — directly, without requiring a third party to register callbacks or otherwise hook into it.

Two concrete capabilities motivate replacing the legacy udev path:

1. **Retry on connection failure** — the udev-rule path has none.
2. **mDNS/DNS-SD discovery (TP8009)** — planned for a future release (see §10. Future Release).

It ships inside `nvme-cli` (not a separate package), is default-on, and targets the nvme-cli 3.0 release cycle.

**Why it cannot be a separate package:** nvme-discoverd replaces components that are already part of the nvme-cli package — specifically the NVMe-oF udev rules and `nvmefc-boot-connections.service`. Additionally, nvme-discoverd invokes `nvme connect` at runtime, so nvme-cli must be installed for the daemon to function. The two are inseparable: nvme-discoverd is nvme-cli's built-in connectivity manager.

**Build option — static replacement, not dynamic masking:** nvme-discoverd is controlled by a meson build option (`-Dnvme-discoverd=enabled|disabled`). When enabled, `nvme-discoverd.service` is installed and the legacy autoconnect components — the NVMe-oF autoconnect udev rules, `nvmefc-boot-connections.service`, `nvmf-autoconnect.service`, `nvmf-connect-nbft.service`, and its NetworkManager dispatcher script — are **not** installed; discoverd handles all of that (see §12 for the full inventory). When disabled, those components are installed as before and nvme-discoverd is absent. There is no dynamic switching: the choice is made at package build time, and the replaced components are simply not installed rather than masked. This avoids any ambiguity during daemon restarts, crashes, or maintenance windows.

**Some design choices in the initial release:** the exclusion list mechanism, the `zeroconf` config knob, and the `zeroconf=false` default — are deliberately shaped by the anticipated future mDNS support, even though mDNS itself is not yet implemented.

nvme-discoverd is **connect-only by design** — meaning it never *disconnects* a live controller in response to discovery state, not that it only connects. It discovers controllers and drives their connections, but it has no stateful path that decides "this controller dropped out of the discovery log page, disconnect it" — that DLP-delta reconciliation is TP8010 Fabric Zoning, which belongs to nvme-stas. The only disconnects discoverd causes are a side effect of a systemd unit stop (shutdown or manual stop) via `ExecStop=`, and `StopUnit` is invoked only for devices already removed by the kernel. This eliminates the entire connect/disconnect ordering complexity at the cost of TP8010 support.

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

Every write to `/dev/nvme-fabrics` blocks the calling process in uninterruptible D state until the kernel completes or times out the connection. To prevent this from stalling the event loop, nvme-discoverd never writes to `/dev/nvme-fabrics` directly. Instead, it delegates all connections — both DC (Discovery Controller) and IOC (I/O Controller) — to child processes managed by systemd transient units.

A transient unit is created via the D-Bus method `org.freedesktop.systemd1.Manager.StartTransientUnit`. No unit file is written to disk and no daemon-reload is required; the unit exists only in systemd's memory. `Type=oneshot` is used because the connection process exits immediately after writing to `/dev/nvme-fabrics` — the kernel maintains the connection afterwards. `RemainAfterExit=yes` keeps the unit active after the process exits so that systemd continues to consider it part of the ordering graph at shutdown time.

Although the unit has no on-disk file, it is a fully-fledged unit in systemd's table once created: `systemctl stop <name>` works and is exactly what runs the `ExecStop=` disconnect — both at shutdown (via the ordering edges) and on demand. `RemainAfterExit=yes` is what makes `stop` meaningful for a `Type=oneshot` unit: without it the unit would already be inactive once `ExecStart=` exits, leaving nothing to stop. What `systemctl` cannot do is `start` the unit again after it has been garbage-collected, since there is no unit file to load — recreating it is discoverd's job via `StartTransient`/`RestartUnit`.

#### 3.2.1 Unit naming

discoverd provides the unit name to `StartTransientUnit`; systemd does not generate one. The unit name cannot be derived from the device name — `nvmeX` is not assigned until after the connection completes (§3.2.4) — so it is derived from the connection's TID instead: the tuple `(transport, traddr, trsvcid, subsysnqn, host_traddr, host_iface, host_nqn)`, concatenated in that canonical order and reduced to a short token by a non-cryptographic hash, encoded as 12 lower-case hexadecimal characters. The unit name is `nvme-discoverd-<12hexchars>.service`.

This uses the same field order as nvme-stas's TID hashing in `staslib/trid.py`, and produces a stable, deterministic name with no coordinator state needed. The hash is not a security primitive — collision resistance against an adversary is not required, only a stable, filesystem- and systemd-safe token — so discoverd uses a small in-tree non-cryptographic hash (FNV-1a, a few lines, no crypto-library dependency and no FIPS-mode concern) truncated to 48 bits. 48 bits keeps the name short (12 hex characters) while making collisions negligible at realistic scale: for a host with ~200 concurrently-connected controllers — the lab scalability reference — the birthday-bound collision probability is on the order of 1 in 10¹⁰ (≈1 in 14 billion). A bare crc32 (32 bits / 8 hex) was considered, but at ~200 controllers its collision probability is ~1 in 215,000, closer than warranted for four saved characters.

As a belt-and-suspenders guard, discoverd verifies at unit-creation time that the computed name is not already mapped to a *different* TID in its in-memory table. A collision would therefore be detected and logged — never silently leaving a controller unmanaged — and the token width or algorithm can be revised later without affecting anything else.

The connection's human-readable identity is deliberately **not** encoded in the unit name. NQNs are spec-limited to 223 bytes and contain characters systemd must escape in a unit name (`:` and `.` become `\x3a` etc.), so embedding one would make the name both long and mangled. The readable identity is carried in the unit's `Description=` instead — which is what `systemctl status` prints (see the templates in §3.3 and §3.4) — giving the operator the clue they want in the place they look for it, without paying the length and escaping cost in the unit name.

Hashing the TID also makes the unit name robust against hostile or malformed NQNs. An NQN can in practice contain unexpected bytes — UTF-8 sequences, or even an embedded newline — but none of that can reach the unit name, which is always a fixed-width hex token regardless of the NQN's contents. The NQN value itself is still passed verbatim to `nvme connect` as a literal argv element (not interpolated into a shell line — see §3.2.4), where the kernel validates it on the `/dev/nvme-fabrics` write.

#### 3.2.2 Shutdown ordering and transport awareness

systemd reverses `After=` ordering at shutdown, so `After=network.target` on a TCP or RDMA unit means: start after `network.target` at boot, stop before `network.target` at shutdown. With `RemainAfterExit=yes` keeping the unit active, this reversal is enforced.

`After=network.target` covers only one half of the shutdown-ordering problem, though — it keeps the link up while the disconnect runs. It does **not** guarantee that filesystems mounted from a controller are unmounted before that controller is torn down; that ordering (the `remote-fs-pre.target` / `_netdev` pattern) is a separate piece still to be validated on real hardware, tracked in §13 Open Question 2. (The daemon's *own* ordering is the opposite concern, covered in §3.8: discoverd deliberately does not order itself behind `network.target` / `network-online.target` at all.)

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

A new `--devid-file` option allows `nvme connect --devid-file FILE` to capture it in both cases: on success, `nvme connect` writes the `nvmeX` name to `FILE`; `ExecStartPost=`, `ExecStop=`, and `ExecStopPost=` all read it back. The file is `/run/nvme/discoverd/units/<unit>.devid`, where `<unit>` is the unit name without the `.service` suffix.

**The device id is validated before it is used in a path.** The `Exec` lines that read the `.devid` back require its content to be exactly one `nvmeX` token (matching `^nvme[0-9]+$`); an empty or malformed value is rejected and the step is skipped. This is robustness against a truncated or corrupt write, **not** a security control: the file lives under a root-owned, mode-`0700` runtime directory, so a non-root process cannot plant one, and a root process could delete the state directly regardless — no unit-script guard changes that. The guard's purpose is narrow but real: it ensures the captured value can only ever name a single device leaf, so the `ExecStopPost=` cleanup (`rm -rf …/controllers/$DEV`, §3.4) can never be turned into a wider deletion by a bad value. The `controllers/$DEV/unit == <unit>.service` cross-check in the same `Exec` lines further ensures a unit only removes the state directory it created.

**Specifiers cannot be used here.** An earlier revision of this design wrote the path with systemd specifiers (`%t` for the runtime directory, `%N`/`%n` for the unit name) on the assumption that systemd would expand them across all four `Exec` lines. It does not: **systemd expands specifiers only when parsing a unit *file*; a transient unit created through the D-Bus `StartTransientUnit` API receives its `Exec` arguments as a literal argv and they are passed through verbatim.** This was confirmed both against a running system (the connect succeeds but `nvme connect` then fails to open a file literally named `%t/nvme/discoverd/units/%N.devid`) and in the systemd source (v261): `config_parse_exec()` in `src/core/load-fragment.c` expands specifiers via `unit_full_printf()` at unit-file parse time, whereas `bus_set_transient_exec_command()` in `src/core/dbus-execute.c` stores the argv verbatim and never calls `unit_*printf`, with no expansion at exec time either. It is by design — the D-Bus API takes already-resolved values. discoverd therefore substitutes the real runtime directory (`/run`) and unit name into every `Exec` line itself when it builds the unit. (systemd's `RuntimeDirectory=`/`$RUNTIME_DIRECTORY` was considered as an alternative but does not fit: discoverd needs a shared, daemon-owned, restart-surviving `/run/nvme/discoverd`, and `$RUNTIME_DIRECTORY` would not expand in `nvme connect`'s non-shell `ExecStart=` anyway.)

#### 3.2.5 State directory hooks

`ExecStartPost=` runs immediately after `ExecStart=` succeeds. It reads the device name from the `.devid` file, creates the controller state directory (`/run/nvme/discoverd/controllers/<devid>/`, described in §3.6), and writes the full unit name (e.g. `nvme-discoverd-3cbb0e7a51f0.service`) to `unit` within that directory. `ExecStartPost=` only runs when `ExecStart=` succeeds — if `nvme connect` fails, no state directory is created, which is the correct behaviour. discoverd substitutes the unit name into the command when it builds the unit (systemd does not expand the `%n`/`%N` specifiers in transient-unit arguments — see §3.2.4).

`ExecStopPost=` runs after `ExecStop=` regardless of whether `ExecStop=` succeeded. It reads the devid from the `.devid` file, removes the file, then removes the controller state directory — handling both cleanup steps atomically from within the unit. Together with `ExecStartPost=`, state directory management in the unit-stop path is self-contained inside the unit.

The exception is device removal by the kernel: when a `KOBJ_REMOVE` event fires for a controller, discoverd's event handler removes the state directory from `controllers/` and the corresponding `units/<unit>.devid` file (§3.5). All other creates and deletes are performed by the unit itself.

`TimeoutStopSec` bounds the shutdown wait so an unresponsive target cannot hold up shutdown indefinitely (without a bound, systemd's 90 s default applies). The bound must sit *above* realistic disconnect time, not below it: a healthy `nvme disconnect` is not instantaneous on large configurations — on a host with ~200 namespaces, 8 paths and 80 CPUs it can take 30–40 s, and larger setups longer still (the kernel's disconnect path makes heavy use of `rcu_sync`). A bound that is too low would `SIGTERM` a disconnect that is still making progress and leave the controller half-torn-down — worse than no bound at all. discoverd therefore uses a generous default (well above the observed worst case) and exposes it as a `discoverd.conf` knob so large deployments can raise it further; the value only needs to be low enough to cap a *stuck* disconnect, not a slow-but-progressing one. (Speeding up the kernel disconnect path itself — e.g. the `rcu_sync` cost — is a separate, worthwhile effort, but orthogonal to discoverd, which must tolerate whatever the disconnect latency is.) `CollectMode=inactive-or-failed` tells systemd to garbage-collect failed transient units automatically once no job is pending — without it, units whose initial `nvme connect` failed would linger in the unit table until discoverd explicitly called `ResetFailedUnit`.

#### 3.2.6 Units survive discoverd restarts

The transient unit's `ExecStart=` line contains the full `nvme connect` invocation with all parameters baked in. Because transient units belong to systemd (not to discoverd), they **survive a discoverd crash or restart** — they remain `active (exited)` in systemd until explicitly stopped. While the unit is alive, `RestartUnit` is sufficient to reconnect using the original parameters without re-fetching anything from any source. If the unit has been garbage-collected (e.g. after a failed connect attempt), discoverd falls back to `StartTransient` using parameters from its in-memory caches.

### 3.3 DC connection management

For DC connections, the transient unit runs `nvme connect --keep-alive-tmo=30`:

```ini
[Unit]
Description=NVMe Discovery Controller <subnqn> @ <traddr>:<trsvcid>
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
  --devid-file=/run/nvme/discoverd/units/<unit>.devid
ExecStartPost=-/bin/sh -c 'DEV=$(cat /run/nvme/discoverd/units/<unit>.devid 2>/dev/null) && mkdir -p /run/nvme/discoverd/controllers/$DEV && echo <unit>.service > /run/nvme/discoverd/controllers/$DEV/unit'
ExecStop=-/bin/sh -c 'DEV=$(cat /run/nvme/discoverd/units/<unit>.devid 2>/dev/null); [ -n "$DEV" ] && [ "$(cat /run/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "<unit>.service" ] && /usr/sbin/nvme disconnect -d $DEV'
ExecStopPost=-/bin/sh -c 'DEV=$(cat /run/nvme/discoverd/units/<unit>.devid 2>/dev/null); rm -f /run/nvme/discoverd/units/<unit>.devid; [ -n "$DEV" ] && [ "$(cat /run/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "<unit>.service" ] && rm -rf /run/nvme/discoverd/controllers/$DEV'
TimeoutStopSec=<disconnect-timeout>   # discoverd.conf knob; default generous, above worst-case disconnect
CollectMode=inactive-or-failed
```

`nvme connect` is used instead of `nvme discover --persistent` because `nvme discover` always issues a Get Log Page immediately — nvme-discoverd fetches the DLP separately via ioctl after the DC device appears, so it would be redundant.

`--keep-alive-tmo=30` sets the keep-alive timeout explicitly: `nvme connect`'s automatic 30 s discovery KATO only fires for the well-known discovery NQN (`nqn.2014-08.org.nvmexpress.discovery`). NVMe Base Spec 2.x allows DCs to use a unique NQN; for those, neither nvme-cli nor the kernel recognizes the connection as a discovery session, and the kernel falls back to its 5 s I/O-controller default (`NVME_DEFAULT_KATO`). Setting the option explicitly gives every DC session the DC-appropriate 30 s value regardless of which NQN it uses.

DC units whose TID is present in the NBFT cache carry `--owner nbft` instead of `--owner discoverd` — the NBFT records the Discovery Controller the firmware used to find the boot targets. The substitution rule is shared with IOC units and described in §3.4.

`nvme connect` establishes the connection and exits; the kernel maintains the session and delivers future AENs on it. nvme-discoverd monitors for the resulting device-add event; after a ~1 s sysfs soak (sysfs attributes are not fully populated at the moment the `add` event fires), it checks the `cntrltype` attribute to confirm the device is a Discovery Controller. Once the device name is known (e.g., `/dev/nvme0`), libnvme is called directly (`libnvme_scan_ctrl` + `libnvmf_get_discovery_log`) to fetch the DLP via Get Log Page — a short ioctl on the already-connected device, not a `/dev/nvme-fabrics` write.

Each DLPE in the DLP is processed based on its `subtype`:
- `NVME_NQN_NVME` — I/O Controller: create a transient IOC unit.
- `NVME_NQN_DISC` — Referral to another DC: create a transient DC unit for the referred DC. When that DC's device appears, its DLP is fetched and processed identically. Referral chains of arbitrary depth are followed naturally through the event loop — no explicit recursion is needed. Note: `nvme connect-all` traverses referrals the same way; `nvme discover` does not (it only fetches one level). If a referral DC becomes permanently unreachable, its per-DC DLP cache entry is eventually evicted; IOCs reachable exclusively through that referral chain fizzle out naturally as their connections drop and are not reconnected. This is intentional — the desired set is derived from current cache state. See §11 (DC Retention Policy) for the planned design.
- `DUPRETINFO` flag set — duplicate information: skip.

Future AENs from the DC arrive as udev events and trigger a DLP re-fetch.

For full event loop protection, the libnvme DLP fetch can be moved to a thread in a future hardening pass.

When the DC is a DDC, the Get Log Page command may set the PLEO (Port Local Entries Only) bit to request only entries reachable through the port that received the command. Per NVMe Base Spec 2.3 §5.2.12, PLEO is a DDC capability (not CDC). nvme-stas already uses it; nvme-discoverd should set it too — deferred to a future release.

### 3.4 IOC connection management

IOC connections use the same transient unit design:

```ini
[Unit]
Description=NVMe I/O Controller <subnqn> @ <traddr>:<trsvcid>
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
  --devid-file=/run/nvme/discoverd/units/<unit>.devid
ExecStartPost=-/bin/sh -c 'DEV=$(cat /run/nvme/discoverd/units/<unit>.devid 2>/dev/null) && mkdir -p /run/nvme/discoverd/controllers/$DEV && echo <unit>.service > /run/nvme/discoverd/controllers/$DEV/unit'
ExecStop=-/bin/sh -c 'DEV=$(cat /run/nvme/discoverd/units/<unit>.devid 2>/dev/null); [ -n "$DEV" ] && [ "$(cat /run/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "<unit>.service" ] && /usr/sbin/nvme disconnect -d $DEV'
ExecStopPost=-/bin/sh -c 'DEV=$(cat /run/nvme/discoverd/units/<unit>.devid 2>/dev/null); rm -f /run/nvme/discoverd/units/<unit>.devid; [ -n "$DEV" ] && [ "$(cat /run/nvme/discoverd/controllers/$DEV/unit 2>/dev/null)" = "<unit>.service" ] && rm -rf /run/nvme/discoverd/controllers/$DEV'
TimeoutStopSec=<disconnect-timeout>   # discoverd.conf knob; default generous, above worst-case disconnect
CollectMode=inactive-or-failed
```

**NBFT-sourced units use `--owner nbft`.** The NBFT can describe Discovery Controllers as well as I/O subsystems — the firmware records the DC it used to discover the boot targets — so this rule applies to both unit types. When discoverd creates a transient unit, DC or IOC, for a controller present in its NBFT cache, it substitutes `--owner nbft` for `--owner discoverd` in the `ExecStart=` line — the only difference between an NBFT unit and a regular unit. Because `RestartUnit` replays the original `ExecStart=` verbatim, all subsequent reconnects also carry `--owner nbft`, preserving the `owner=nbft` lifetime invariant without any reconnect-time special-casing. At unit-creation time, discoverd selects the template variant based on a cache lookup: TID present in the NBFT cache → `--owner nbft`; otherwise → `--owner discoverd`.

**Collision detection for static config and DLP entries.** The NBFT cache lookup runs regardless of which source initiated the connection. If a static `controller =` entry (in a `[Discovery Controller]` or `[Subsystem]` section) or a DLPE matches a TID already in the NBFT cache, discoverd logs an error-level journal message (the entry is a misconfiguration — NBFT is the authoritative source for that controller) and uses `--owner nbft` rather than `--owner discoverd`. The NBFT source takes precedence; connectivity is not disrupted, but the duplicate entry should be removed from the config or the DC that advertises it should be excluded.

**The NBFT `unavailable` flag is advisory, not a verdict.** An SSNS record may carry an unavailable indication (`NBFT_SSNS_UNAVAIL_NAMESPACE_*`). Per the Boot Spec this is only a point-in-time hint — it reports that the namespace was unreachable *to the pre-OS driver* and explicitly does **not** guarantee availability at any future point. discoverd therefore does not treat it as a reason to skip the entry or give up: it attempts the connection anyway (matching the historical `connect-all --nbft` behaviour) and, because the controller is in its desired set, retries on the normal schedule — which naturally covers the common case where a target unreachable in the firmware environment becomes reachable once the OS network is fully configured. The `unavailable` flag and any extended-info diagnostics are logged for observability but do not gate the connect decision.

### 3.5 Unit lifecycle

nvme-discoverd is not passive. When the kernel removes a controller (`ctrl-loss-tmo` expires or manual disconnect), a udev `remove` event fires. The daemon removes the state directory and in-memory entry, then decides whether to reconnect. Two checks must pass before a reconnect is scheduled:

1. **Exclusion check** — the controller must not match any entry in the system-wide exclusion list (see `rfc-nvme-exclusion.md`). This applies to **all** controllers, including NBFT-sourced ones: the exclusion list is the host administrator's explicit, root-only instruction, so discoverd honours a matching entry and does not reconnect — the supported way to take a boot path out of service for testing or maintenance. (`owner=nbft` still protects boot devices from *other* orchestrators via the registry; only discoverd's own reconnect yields to the local exclusion. `nvme exclusion add` warns when an entry would match an `owner=nbft` controller.)
2. **Desired-set check** — the controller must still be part of the desired connection set: present in the config file, in the NBFT cache, or in a current cached DLP. nvme-discoverd never disconnects controllers in response to configuration changes during normal operation, but when a controller is removed by an external entity (kernel timeout, manual disconnect, another orchestrator), it must verify the controller is still wanted before reconnecting. A controller that was removed from the config or dropped from all DLPs while the connection was live should not be silently reconnected.

### 3.6 State Files

Location: `/run/nvme/` (tmpfs — does not survive reboot). The complete runtime layout below is taken from a live run — four fabric controllers (a Discovery Controller and the three I/O Controllers it advertised) — and shows how the three subtrees relate:

```
/run/nvme
├── discoverd/         # discoverd-private (RuntimeDirectoryPreserve=yes, §3.8)
│   ├── controllers/   # one dir per live controller, keyed by nvmeX
│   │   ├── nvme1/
│   │   │   └── unit   # nvme-discoverd-a53608f50edc.service
│   │   ├── nvme2/
│   │   │   └── unit   # nvme-discoverd-99f2d6804cac.service
│   │   ├── nvme3/
│   │   │   └── unit   # nvme-discoverd-8c6bc8ad6d9b.service
│   │   └── nvme4/
│   │       └── unit   # nvme-discoverd-7d5e24b2ac28.service
│   │
│   └── units/         # one .devid per transient unit (§3.2.4)
│       ├── nvme-discoverd-7d5e24b2ac28.devid   # nvme4
│       ├── nvme-discoverd-8c6bc8ad6d9b.devid   # nvme3
│       ├── nvme-discoverd-99f2d6804cac.devid   # nvme2
│       └── nvme-discoverd-a53608f50edc.devid   # nvme1
│
└── registry/          # shared ownership registry — NOT discoverd-private
    │                  #   written by `nvme connect --owner` (§9),
    ├── nvme1/         #   pruned by 70-nvmf-registry.rules on removal
    │   ├── owner      # discoverd
    │   └── seqnum     # kernel seqnum at connect time
    ├── nvme2/
    │   ├── owner      # discoverd
    │   └── seqnum     # kernel seqnum at connect time
    ├── nvme3/
    │   ├── owner      # discoverd
    │   └── seqnum     # kernel seqnum at connect time
    └── nvme4/
        ├── owner      # discoverd
        └── seqnum     # kernel seqnum at connect time
```

Two of these subtrees are discoverd's own state, both under `/run/nvme/discoverd/`:

- **`controllers/<nvmeX>/unit`** — one directory per controller, named by the kernel-assigned device name (`nvmeX`), each holding a single file: the systemd transient unit name. This is the one piece of information that sysfs does not carry.
- **`units/<unit>.devid`** — the device-name capture file written by `nvme connect --devid-file` and read back by the unit's `ExecStartPost=`/`ExecStop=`/`ExecStopPost=` lines (§3.2.4).

The third subtree, **`/run/nvme/registry/<nvmeX>/owner`**, is the shared ownership registry — written by `nvme connect --owner` (§9) and pruned by `70-nvmf-registry.rules` when a controller is removed. It is shown here only to complete the `/run/nvme` picture: it is owned by the registry mechanism, not discoverd. discoverd only **reads** it, during its startup audit, to decide whether another orchestrator already owns a controller (the startup-audit "second filter" described later in this section).

All transport parameters (transport, traddr, trsvcid, subnqn, hostnqn, host-traddr, host-iface, cntrltype) are read from sysfs when needed — storing them in state files would duplicate data the kernel already owns authoritatively. The connection origin (nbft, manual, DLP-sourced) is re-derived at reconnect time: a TID (Transport ID) present in the NBFT cache or config cache is classified accordingly; a TID absent from both is assumed to be DLP-sourced.

Discovery Log Page caches are **not** persisted to disk. They are in-memory only and rebuilt by re-fetching DLPs from each DC as it reconnects at startup. See §4. In-Memory Caches.

State directories are created by `ExecStartPost=` inside the transient unit itself (see §3.2.5), not by discoverd. For normal connections, `nvme connect` writes the kernel-assigned device name to `--devid-file`; `ExecStartPost=` reads it and creates the state directory. For pre-existing connections (idempotent path), libnvme finds the matching device via sysfs scan before returning, so `--devid-file` is populated from the sysfs-known name — `ExecStartPost=` then creates the state directory identically. In both cases, discoverd knows the state directory exists as soon as the `JobRemoved` signal arrives with a success result.

At startup, discoverd cross-references state files against sysfs. This serves three purposes:

- **Warm restart** — on intentional restart, reconstruct the connected set immediately from state files without re-running discovery.
- **Crash recovery** — same as warm restart but unplanned; the startup audit catches any devices lost during the restart window.
- **Late-start resilience** — adopt connections already present in sysfs (e.g. NBFT boot controllers from initramfs).

| State file | In sysfs | Meaning | Action |
|---|---|---|---|
| yes | yes | Normal — connection alive | Adopt; rebuild in-memory entry (and fetch the DLP if it is a DC ³) |
| no | yes | Pre-existing connection (e.g. initramfs) | Create transient unit; write state file ¹ |
| yes | no | Device removed while discoverd was down | ² |

**¹ Pre-existing connection (no state file):** all connection parameters are read from sysfs. Before proceeding, discoverd applies two filters.

First, it checks the desired set: the controller's TID must be present in the NBFT cache or the config cache. Controllers not in either cache are outside discoverd's scope — discoverd skips them and logs an informational message. (DLP-sourced controllers are not in the desired set at the very start, because the per-DC DLP caches are not yet warm — see ³ for how startup adoption warms them.) FC controllers are not subject to this filter: pre-existing FC connections at startup are handled by the kickstart event path — discoverd re-issues kickstart at startup, and the resulting `FC_EVENT=="nvmediscovery"` uevents drive adoption with `--idempotent` for already-connected targets.

Second, discoverd checks the ownership registry. If the controller already has a registry entry and the owner is neither `discoverd` nor `nbft`, discoverd logs a warning and skips this controller — leaving it in the hands of the orchestrator that owns it. This prevents discoverd from inadvertently claiming ownership of a controller managed by nvme-stas or another tool.

If the TID is in the desired set and no entry exists (or the owner is `discoverd` or `nbft`), discoverd calls `StartTransient` using the standard unit template — the `--idempotent` option carried by every unit (§3.3, §3.4) makes `nvme connect` exit 0 when the controller is already connected, so the unit succeeds regardless of whether this invocation did the connecting or a previous one did. This is more precise than the `-` prefix on `ExecStart=` (which suppresses all errors): genuine failures — wrong transport, unreachable target, TLS key missing — still mark the unit as failed.

`nvme connect --idempotent` detects the existing connection via libnvme's sysfs scan without writing to `/dev/nvme-fabrics`; since the device name is known from that scan, it is written to `--devid-file` before returning. `ExecStartPost=` then creates the state directory identically to the normal connect path. discoverd waits for the `JobRemoved` signal: success → the unit is adopted with its state directory in place; failure → the normal reconnect logic handles recovery.

**² Device removed while discoverd was down:** the reconnect decision is origin-aware:

- **TID in NBFT cache or config cache** — schedule `RestartUnit` immediately; these sources are always desired.
- **TID absent from both (DLP-sourced)** — defer until the per-DC DLP caches are warm (every DC from NBFT and config has been adopted or reconnected and its DLP fetched — see ³). Then apply the desired-set check: if the TID is still in a DC's current DLP, schedule `RestartUnit`; if not, call `StopUnit` — the IOC was removed from the DLP while the daemon was down and should not be reconnected.

**³ Warming the DLP on adoption:** when startup adoption finds a **live DC** (the `yes`/`yes` row above), discoverd fetches that DC's DLP immediately, exactly as it would on a fresh DC connect. This is required because an already-connected DC produces **no device-add uevent** — the normal trigger for a DLP fetch — so without an explicit fetch at adoption, the DC's DLP-sourced IOCs would never enter the desired set. The visible symptom (observed on a running system before this was added): after a warm restart, the adopted IOCs keep running, but if one drops, discoverd logs *"not desired — dropping"* and does not reconnect it, because the cold DLP cache makes it look unwanted. Fetching the DLP at adoption puts those IOCs back in the desired set; already-adopted IOCs are not duplicate-connected because the per-TID unit is already tracked.

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

**The daemon deliberately does not order itself behind `network.target` or `network-online.target`.** Those targets say nothing reliable about whether any given interface is actually up and configured — `network-online.target` in particular is coarse and best-effort — and if the network comes up late, partially, or not at all, ordering discoverd behind it would delay or entirely prevent the daemon from starting, which is exactly when it needs to be running so its retry loop can connect paths the moment they become usable. discoverd's correctness therefore rests on no systemd-provided network-readiness state: the recovery mechanism is its own periodic reconnect loop (§5), optionally accelerated by link-up events but never gated on them (§12.5). This is also what makes it behave identically under NetworkManager, systemd-networkd, or no network manager at all.

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

**Path forward — a long horizon, not a pending switch.** D-Bus (`org.freedesktop.systemd1`) is discoverd's supported, primary unit-management path for the foreseeable future, not a transitional thing on its way out. Only `StartTransient` exists over varlink today; the rest of the unit lifecycle does not, and even once it lands it has to age into the systemd baseline that distributions actually ship — realistically years away. There is therefore no plan to drop the D-Bus path until the full varlink unit-lifecycle API is both complete *and* broadly available in the targeted baselines, so an nvme-cli that rebases ahead of systemd never loses unit management. This is also independent of the legacy autoconnect components (§12), which are gated by their own build option: a distribution that is not ready can simply build with `-Dnvme-discoverd=disabled` and keep the old units. The two need not flip in lockstep. See §13 Open Questions item 4.

---

## 4. In-Memory Caches

Discoverd maintains three in-memory caches in the initial release; a fourth is added with mDNS support. None are persisted to state files — they are rebuilt at startup.

- **NBFT cache** — populated at startup from the NBFT ACPI table; static for the daemon's lifetime.
- **Config cache** — populated at startup from `discoverd.conf` and `connections.d/*.conf`; rebuilt on SIGHUP.
- **Per-DC DLP cache** — a map from DC TID to the set of IOC TIDs in that DC's last-fetched Discovery Log Page. Populated as each DC connects and its DLP is fetched. Updated on each AEN via clean per-DC replacement: `dc_cache[dc_tid] = new_dlp`. No origin tag is needed on individual entries — the per-DC structure provides that naturally.
- **mDNS DC cache** *(future release)* — the set of DC TIDs discovered via mDNS/DNS-SD. Populated dynamically as mDNS advertisements are received; entries age out per `discovery-retention-time`. See §10 and §11. Future Releases.

The **desired connection set** is the union of all caches: NBFT cache ∪ config cache ∪ union of all per-DC DLP caches ∪ mDNS DC cache *(future)*. This is a derived view, not a separate data structure; at reconnect time discoverd checks the caches directly.

**FC kickstart has no corresponding cache in the initial release.** FC-NVMe targets are discovered by writing `add` to `/sys/class/fc/fc_udev_device/nvme_discovery`, which causes the FC HBA firmware to probe all reachable targets and fire `FC_EVENT=="nvmediscovery"` uevents for each. Discoverd creates a transient unit per event without caching the discovered TIDs. The kickstart is re-issued at startup and again whenever an FC controller drops — the fabric's current response is authoritative each time. The desired set for FC connections is implicitly defined by what the kickstart currently discovers. Note: the DC retention policy (§11.3) will require tracking which FC DC TIDs appeared in the last kickstart response in order to start the retention timer when a TID stops appearing.

**Origin classification heuristic at startup:** a TID found in a state file that is absent from both the NBFT cache and the config cache is assumed to be DLP-sourced. This is correct in practice — the same TID can appear in both a DLP and the config cache, but NBFT and config entries are checked first; a TID absent from both is classified as DLP-sourced.

---

## 5. Connection Lifecycle and Failure Handling

**Two kernel timeouts to understand:**

- **Initial connect:** `nvme connect` writes to `/dev/nvme-fabrics`; if the target is unreachable the kernel gives up after a transport-dependent timeout (typically a few seconds on TCP; varies for RDMA and FC) and `nvme connect` exits with an error. No device appears; the transient unit goes to `failed`. The kernel does not retry — that is discoverd's job.
- **Lost connectivity (ctrl-loss-tmo):** Once a connection is established and then drops, the kernel retries automatically every `reconnect-delay` seconds (default 10 s) for up to `ctrl-loss-tmo` seconds. The device stays in sysfs throughout. Only when `ctrl-loss-tmo` expires without success does the kernel remove the device and fire a `device remove` uevent. Discoverd does not intervene during the kernel retry loop.

**Sysfs race on device-add:** the kernel sends the `add` uevent slightly before sysfs attributes are fully populated. Discoverd waits ~1 s (soak timer) before reading `cntrltype`, `transport`, `traddr`, etc. from a newly appeared device. This is the same workaround used by nvme-stas.

**Failure detection (initial connect):** discoverd subscribes to the `org.freedesktop.systemd1.Manager.JobRemoved` D-Bus signal for each unit it starts. When the job completes with `done`, the connection succeeded — `ExecStartPost=` has already written the state directory. When the job completes with `failed`, the connection failed; `CollectMode=inactive-or-failed` garbage-collects the unit. discoverd schedules a `StartTransient` call with exponential backoff (1 s, 2 s, 4 s … capped at a configurable maximum). The exclusion list is checked before each retry. No timer is needed — `JobRemoved` is the authoritative completion signal for both new and idempotent connections.

**Retry policy:** discoverd retries indefinitely for statically configured and NBFT-derived controllers — they represent deliberate intent and have no give-up horizon. For dynamically discovered DCs (mDNS, referrals, FC kickstart), `discovery-retention-time` handles the natural expiry once the discovery source becomes unavailable and the connection is lost (see §11. DC Retention Policy).

**Structurally-unreachable HFI / `host_traddr` bindings.** A DLP or NBFT entry can bind a target to a host interface or source address that structurally cannot reach the target's subnet (the classic mixed-subnet DLP). This is a misconfiguration of the *source*, not something discoverd can fix: discoverd connects what it is told and does not rewrite the binding it was handed — second-guessing it would mean overriding the source's stated intent. Such a target simply fails to connect and is retried at the capped backoff interval, so it is a cheap, slow retry rather than a hot loop, and multipath (where present) has already failed over. What discoverd does contribute is visibility: on repeated failure it logs the binding (`host_iface`/`host_traddr` → `traddr`) at a throttled rate, so an operator can see that a target is bound to an interface that cannot reach its subnet instead of watching silent retries. The fix belongs at the source — correct the DLP/NBFT entry or the host routing.

**Device removal:** when `device remove` fires, discoverd removes the state dir and in-memory entry, then makes two checks before deciding to reconnect:

1. **Exclusion check.** If the controller matches an exclusion entry, call `StopUnit` — do not reconnect. This applies to NBFT-sourced controllers too: the exclusion list is the administrator's explicit instruction, so a matching entry stops the reconnect (`owner=nbft` still protects the controller from *other* orchestrators, but not from the host's own deliberate exclusion). `nvme exclusion add` warns when an entry would match an `owner=nbft` controller.
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

discoverd's configuration is **INI-style** (`key = value` with `[Section]` headers), the same format convention as nvme-stas, reloaded on SIGHUP. INI is chosen over JSON to reduce dependencies and maximize portability, including to minimal and embedded platforms where json-c may not be available.

It is split across two locations with distinct roles:

- **`/etc/nvme/discoverd.conf`** — the daemon's own configuration plus global connection defaults. It contains a single `[Global]` section.
- **`/etc/nvme/discoverd/connections.d/*.conf`** — the statically configured connections, organized by *host persona*. discoverd reads every `*.conf` file in this directory.

### 6.1 `discoverd.conf` — daemon config and defaults

`discoverd.conf` carries the daemon's own configuration and the *default* connection parameters, in three sections. It holds no actual connections — those live in `connections.d/` (§6.2).

**`[Global]`** holds two kinds of keys: discovery-source toggles and daemon behavior (`nbft`, `zeroconf`, `fc-kickstart-interval-minutes`, `discovery-retention-time`, …), and **global defaults for connection parameters** (`ctrl-loss-tmo`, `reconnect-delay`, `keep-alive-tmo`, digests, queue counts, …) that apply to *every* configured connection — DC or IOC — unless something more specific overrides them (§6.2.2).

**`[Discovery Controller Defaults]`** and **`[I/O Controller Defaults]`** hold defaults that apply only to connections of that *type*. They exist because some parameters want a different default per controller class — most clearly the keep-alive timeout: `kato = 30` is right for a Discovery Controller, `kato = 5` (the kernel default) for an I/O Controller. They override `[Global]` for their respective type. These sections are also the **only** configuration point for **auto-discovered** controllers (mDNS-discovered DCs, DLP-discovered IOCs), which have no endpoint section of their own to carry inline parameters.

```ini
[Global]
nbft = true                          # adopt NBFT boot connections (default true)
# zeroconf = false                   # mDNS discovery (default false; future release)
ctrl-loss-tmo = 600                  # global default — lowest precedence
fc-kickstart-interval-minutes = 0

[Discovery Controller Defaults]
kato = 30                            # DC keep-alive default
# iface-pinning = true              # (future, mDNS) pin discovered DCs to the advertising interface

[I/O Controller Defaults]
kato = 5                            # IOC keep-alive default (kernel default)
```

`nbft` and `zeroconf` both live in `[Global]` — they are discovery source toggles and belong together. `zeroconf` defaults to `false` — the inverse of stafd, for opposite but symmetric reasons. stafd is an optional package; installing it signals that the user wants mDNS-based auto-discovery and is willing to have the host be managed by a Centralized DC (CDC). nvme-discoverd ships with nvme-cli and will be installed on most systems by default, including desktops, laptops, and servers with no NVMe-oF fabric. Enabling mDNS on all of those by default would be *surprising* and *unnecessary* (to say the least).

### 6.2 `connections.d/` — statically configured connections

Each file under `connections.d/` describes the connections for **one host persona**: an optional `[Host]` block followed by one or more **endpoint sections**.

- **`[Host]`** — the host identity (`hostnqn`, `hostid`, `dhchap-secret`, …) used for every connection in that file. **A file with no `[Host]` connects as the system default identity** (`/etc/nvme/hostnqn` / `hostid`). Presenting *different* identities to different fabrics is done by splitting them across multiple files.
- **`[Discovery Controller]`** — a Discovery Controller to connect to. Its NQN is the section's `nqn =`; if omitted it defaults to the well-known discovery NQN (`nqn.2014-08.org.nvmexpress.discovery`). discoverd supplies this default itself: because it connects to DCs with `nvme connect` (not `nvme discover`), the discovery-NQN default that `discover`/`connect-all` apply is not in play, so discoverd fills it into the DC's TID so the unit name, registry entry, and connect command all agree.
- **`[Subsystem]`** — an I/O subsystem to connect to, named by its `nqn =`.

The **role is the section name** — there is no `type=` key. Within an endpoint section, each **`controller =` line is one path** to that endpoint; repeating it expresses multipath (§6.2.1). Per-endpoint keys (`tls`, `tls-key`, `dhchap-*`, `ctrl-loss-tmo`, …) override the `[Global]` defaults for that endpoint and all its paths.

```ini
# connections.d/prod-fabric.conf
[Host]
hostnqn       = nqn.2014-08.org.nvmexpress:uuid:1111…-A
dhchap-secret = DHHC-1:00:…

[Discovery Controller]
nqn        = nqn.2014-08.org.example:cdc.prod
tls        = true
tls-key    = NVMeTLSkey-1:01:…cdc
controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009

[Discovery Controller]
<another discover controller>

[Subsystem]
nqn           = nqn.2024-01.com.example:prod.vol1
tls           = true
tls-key       = NVMeTLSkey-1:01:…vol1     # bound to (this host, this subsysnqn)
ctrl-loss-tmo = 1800                       # overrides the [Global] 600 default
controller    = transport=tcp;traddr=10.0.0.9;trsvcid=4420;host-iface=eth0
controller    = transport=tcp;traddr=10.0.0.10;trsvcid=4420;host-iface=eth1

[Subsystem]
<another subsystem>

[Subsystem]
<yet another subsystem>
```

**`controller =` address syntax.** Each path is a `controller =` line whose value is a `;`-separated `key=value` list using the `nvme connect` field names — `transport`, `traddr`, `trsvcid`, and optionally `host-traddr` / `host-iface` for per-path host binding (the two paths above are pinned to `eth0` and `eth1`). This is the same address form nvme-stas uses (and the legacy `discovery.conf`), minus the subsystem `nqn` — which now comes from the section header. A URL form (`tcp://10.0.0.10:4420`) was considered and rejected: it carries only the target triple (no `host-traddr`/`host-iface`, which are genuinely per-path in multi-NIC multipath), and it is ambiguous for FC, whose WWN traddr is full of colons and has no port. One uniform, transport-agnostic form is preferred over a URL-plus-extension hybrid.

#### 6.2.1 Multipath

A `[Subsystem]` (or `[Discovery Controller]`) names one endpoint; each `controller =` line under it is **one path = one controller** the host instantiates via `nvme connect`. The subsystem's namespaces are reachable through every path — native NVMe multipath groups all controllers reporting that subsysnqn. The parser **accepts any number** of `controller =` lines: **1 is normal** (single path), and there is **no upper bound and no power-of-two rule** (2 is merely the common dual-fabric deployment; 3, 4, … are equally valid — a Discovery Log Page can return N entries for one subsysnqn). Per-link security (TLS PSK / DH-CHAP) sits at the **section** level, not per path: the PSK identity is bound to the **(hostnqn, subsysnqn)** pair, constant across all paths.

#### 6.2.2 Precedence

A connection parameter is resolved most-specific-first:

**`controller =` line > endpoint section (`[Discovery Controller]`/`[Subsystem]`) > `[Host]` > type defaults (`[Discovery Controller Defaults]` / `[I/O Controller Defaults]`) > `[Global]` > kernel default**

The type-defaults level is selected by the controller's class — a DC connection draws from `[Discovery Controller Defaults]`, an IOC from `[I/O Controller Defaults]` — and both still fall through to `[Global]` for anything not set there. So a `kato` on a `controller =` line wins over its `[Subsystem]` section, which wins over the file's `[Host]`, which wins over the type default, which wins over `[Global]`, which wins over the kernel built-in. `nvme discoverd config show` renders the merged, fully-resolved result.

**Exception — per-link security stays at the section level.** `tls-key` (and the DH-CHAP keys) are *not* overridable on a `controller =` line: the PSK identity is bound to the `(hostnqn, subsysnqn)` pair, so it is constant across all paths to an endpoint (§6.2.1) and belongs on the endpoint section. Everything else — `ctrl-loss-tmo`, `kato`, digests, queue counts, `reconnect-delay`, etc. — can be overridden per path on the `controller =` line.

#### 6.2.3 How it resolves at runtime

discoverd is a **connection manager**: its runtime unit is the *controller*, and a connection *is* a controller. The config files resolve, at parse time, into exactly **two static lists** — the configured Discovery Controllers and the configured I/O Controllers. A `[Subsystem]` with N `controller =` lines is an authoring convenience that **expands into N I/O-controller connections**, one per path; the grouping then evaporates. Runtime IOCs learned from a DC's Discovery Log Page or from AENs are **not** part of this file format — they are discovered, not configured (§7) — and the DLP/AEN runtime set is out of scope for the config. discoverd sees only DCs and IOCs; subsystems and namespaces are downstream of the connection.

### 6.3 Parser conventions

The config parser follows systemd conventions. Boolean values accept `1`/`yes`/`y`/`true`/`t`/`on` and `0`/`no`/`n`/`false`/`f`/`off` (all case-insensitive), matching the behavior of systemd's `parse_boolean()`. The implementation can be lifted directly from `src/basic/parse-util.c` in the systemd source tree (LGPL-2.1-or-later — compatible with nvme-cli's GPL-2.0-only, provided the SPDX header and copyright notice are preserved). Additional `[Global]` and per-endpoint keys are added when mDNS is implemented — see §10. Future Release.

### 6.4 Why not reuse the legacy config files?

A reasonable question is why discoverd does not simply read the existing `config.json` or `discovery.conf` that nvme-cli already ships. Each is rejected for concrete reasons.

**`config.json` (JSON / json-c).** The `connections.d/` model deliberately mirrors config.json's *structure* — a host identity with its subsystems and their per-path addresses — but not its format, for two reasons. First, **portability**: parsing JSON pulls in a hard dependency on json-c. discoverd is meant to run everywhere nvme-cli does, including minimal and embedded targets where json-c may be unavailable or unwanted; an INI parser is a few hundred lines with no external dependency (the boolean parser is lifted from systemd, §6.3). Second, **ergonomics**: JSON's syntax is rigid and, critically, has no comment support. An administrator cannot temporarily comment out a single controller entry, nor can the shipped file be self-documenting — carrying inline notes that explain each parameter. The commented-out lines and inline `#` notes shown above are not expressible in JSON at all.

**`discovery.conf`.** This file is, by its own man page, "a list of connect-all commands to run" — each line a set of `--transport/--traddr/--trsvcid/--host-traddr/--host-iface` arguments addressing a single **Discovery Controller**. It is DC-only by construction: it has no way to express an I/O Controller entry, a host identity, a global discovery-source toggle (`nbft`, `zeroconf`), or any of the additional knobs the mDNS milestone will add (§10). discoverd must configure the full set — DCs, IOCs, host personas, and global behavior — so a format that can only enumerate discovery controllers is structurally insufficient, independent of the dependency argument.

This is why discoverd defines its own `discoverd.conf` + `connections.d/` (see also §2, "Explicitly Out of Scope") rather than extending or reusing either legacy file.

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
| `connections.d/*.conf` (`[Discovery Controller]` / `[Subsystem]` sections) | Both DCs and IOCs declared in the per-host connection files are reconnected at startup — each `controller =` line is one connection, and a `[Subsystem]` expands to one IOC per path (§6.2). No legacy `discovery.conf` support |
| FC Kickstart PDUs | Both at startup and on every FC controller drop: write `add` to `/sys/class/fc/fc_udev_device/nvme_discovery` (idempotent), then handle `SUBSYSTEM=="fc"`, `FC_EVENT=="nvmediscovery"` uevents — each event represents one currently reachable FC-NVMe target. Kickstart is the FC reconnect mechanism: the fabric's current response after each re-issue is authoritative. No TID cache is needed in the initial release (see §4); the future DC retention policy (§11.3) will add one. Replaces `nvmefc-boot-connections.service` and the FC udev rules; neither is installed when nvme-discoverd is built (see §1. What it is). dracut (`95nvmf`) continues to do the FC Kickstart in the initramfs unchanged |

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

**`nvme connect --devid-file FILE`** — new option. On successful connection, writes the device name (e.g. `nvme3`) to `FILE`. For new connections, the name is returned synchronously by the kernel when `/dev/nvme-fabrics` is written. For idempotent connections (`--idempotent`), libnvme detects the existing connection via sysfs scan without writing to `/dev/nvme-fabrics`; since the device name is known from that scan, it is written to `FILE` before returning. Used by `ExecStartPost=` (to create the state directory), `ExecStop=` (to identify the device to disconnect), and `ExecStopPost=` (to clean up). The path is `/run/nvme/discoverd/units/<unit>.devid`, which discoverd substitutes into all four `Exec` lines when it builds the unit — systemd does not expand `%t`/`%N`/`%n` specifiers in transient-unit arguments (see §3.2.4). Files land in `/run/nvme/discoverd/units/` (tmpfs — does not survive reboot).

---

## 10. Future Release: mDNS/DNS-SD (TP8009)

mDNS/DNS-SD discovery allows Discovery Controllers to advertise themselves on the local network with no manual IP configuration on the host. This enables zeroconf networking and zero-touch provisioning — a host boots, discoverd browses `_nvme-disc._tcp`, connects to the DC, retrieves the DLP, and connects to all IOCs, without the administrator having to specify any IP addresses.

mDNS is not part of the initial release. Three prerequisites must be met first:

1. **systemd-resolved minimum version.** Browsing `_nvme-disc._tcp` service advertisements requires systemd v258+ (released September 2025), which introduced `io.systemd.Resolve.BrowseServices` — a varlink streaming subscription that pushes service add/remove events as they occur. Earlier versions of systemd-resolved supported only hostname resolution and DNS-SD service *resolution* (looking up a known service instance by name), but not *browsing* (enumerating all instances of a service type). Requiring v258 avoids an Avahi/D-Bus dependency.

2. **Interface pinning (hard requirement).** mDNS advertisements arrive on a specific network interface. If discoverd connects to the DC over the routing table's default route instead, the connection may land on the management network (typically a slow 1 Gbps link) rather than the high-bandwidth storage fabric. nvme-discoverd must use `SO_BINDTODEVICE` to pin connections to the interface where the advertisement was received — controlled by `iface-pinning=true` (the default). Setting `iface-pinning=false` while `zeroconf=true` is a fatal configuration error. This failure mode has been observed in production (nvme-stas).

3. **nvme-stas coexistence.** The exclusion list cannot solve this: it is system-wide and applies to all orchestrators equally, so an entry that prevents nvme-discoverd from connecting to a DC also prevents nvme-stas from connecting to it. The only correct solution is to enable mDNS in exactly one orchestrator. nvme-stas enforces this without reading discoverd's config file: it queries discoverd's **runtime** mDNS state over discoverd's varlink interface (§3.7) — a best-effort, edge-triggered check (a failed query is skipped) — and logs an error-level journal entry if discoverd reports mDNS enabled, prompting the administrator to disable it in one of the two daemons. Reading `/etc/nvme/discoverd.conf` directly was considered and rejected: it would couple nvme-stas to discoverd's config-file format, so a format change would silently break the check. See `rfc-nvme-orchestrator-coexistence.md` §8.

**Config additions for the future mDNS release** (not in initial version):

The defaults shown in the tables below are the kernel's own defaults — the values the kernel uses when a parameter is absent from the string written to `/dev/nvme-fabrics` (i.e. `nvme connect` builds the string with only options provided to it). Specifying a value in the config overrides the kernel's default.

These options are particularly important for automatically discovered controllers (mDNS/DNS-SD) because there is no per-entry configuration opportunity for those — unlike manual `controller=` entries where all parameters are specified inline. Note that `iface-pinning` applies independently per section, allowing different interface-pinning policy for DC and IOC connections.

To `[Global]`:

| Option | Default | Description |
|--------|---------|-------------|
| `zeroconf-ip-family` | ipv4+ipv6 | Address family selector for mDNS-discovered DCs (`ipv4`, `ipv6`, or `ipv4+ipv6`). Per spec, a service publisher must advertise all IP addresses of the interface, so receiving both IPv4 and IPv6 for the same DC is common. This option selects which to use, preventing duplicate connections to the same DC. Has no effect on manual `controller=` entries or NBFT entries. |
| `discovery-retention-time` | 72hours | How long to retain a dynamically-discovered DC after its discovery source becomes unavailable and its connection fails. Applies to mDNS-discovered DCs; also applies to referral DCs and FC kickstart DCs (see §11. DC Retention Policy for the full design). Values: `infinity` (retain forever), `0` (remove immediately on source loss), or a time span — a unit-less integer in seconds, or a string such as `72hours`, `3days 5hours`. |

These options live in the **`[Discovery Controller Defaults]`** section of `discoverd.conf` (§6.1). They apply to auto-discovered (mDNS) DCs, which have no endpoint section of their own to carry inline parameters; a manually configured `[Discovery Controller]` section in `connections.d/` overrides them per endpoint, and a `controller =` line overrides them per path (§6.2.2).

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

These options live in the **`[I/O Controller Defaults]`** section of `discoverd.conf` (§6.1). They apply to DLP-discovered IOCs, which have no endpoint section of their own; a manually configured `[Subsystem]` section in `connections.d/` overrides them per endpoint, and a `controller =` line overrides them per path (§6.2.2).

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

## 11. Future Release: DC Retention Policy

Discovery Controllers fall into two categories with fundamentally different lifetime semantics.

**Statically configured DCs** — those declared in `[Discovery Controller]` sections in `connections.d/`, and those derived from NBFT — represent explicit administrator or firmware intent. If a statically configured DC is unreachable, discoverd retries indefinitely. The admin put it there on purpose; a maintenance window, firmware update, or fabric reconfiguration should not silently evict a configured target. The correct way to stop reconnecting to a static DC is to remove it from the configuration. NBFT-derived DCs are similarly permanent: the NBFT is written by firmware and does not change at runtime.

**Dynamically discovered DCs** — those found via mDNS advertisements, referral entries in a DLP, or FC kickstart responses — are ephemeral by nature. They were not declared by an administrator; they were found. When their discovery source goes silent, the absence is a meaningful signal that the topology has changed. Retrying indefinitely toward a DC that has been gone for days accumulates phantom cache state and keeps otherwise-idle IOC reconnect timers running.

`discovery-retention-time` specifies how long discovery-derived configuration is retained after the discovery source becomes unavailable. Expiration removes the retained discovery information but does not disconnect existing controllers. Controllers that subsequently disconnect are not reconnected unless rediscovered through an active discovery source. They fizzle out naturally over time as their keep-alive sessions expire.

The default is 72 hours — long enough to survive transient outages and maintenance windows without operator intervention, short enough to prevent indefinite accumulation of phantom entries.

Values: `infinity` (retain forever), `0` (remove immediately on source loss), or a time span — a unit-less integer in seconds, or a string such as `72hours`, `3days 5hours`.

**Interaction with `ctrl-loss-tmo`:** The fizzle-out behavior relies on the kernel eventually removing the device once `ctrl-loss-tmo` expires, firing a `device remove` uevent that gives discoverd the opportunity to decide not to reconnect. If `ctrl-loss-tmo=-1` is set on IOC connections, the kernel retries indefinitely and never removes the device — discoverd therefore never receives the `device remove` uevent. Setting `ctrl-loss-tmo=-1` for IOCs reachable through dynamic discovery sources effectively bypasses `discovery-retention-time` for those connections; they persist indefinitely regardless of cache expiry.

### 11.1 mDNS-discovered DCs

The discovery source is the mDNS advertisement. The timer starts when the advertisement disappears from the systemd-resolved service browser, regardless of whether the DC connection is still alive at that point. A live connection is left undisturbed; the expiry is only felt when the connection later drops and is not reconnected. If the DC re-advertises while the timer is still running, the timer is cancelled and the cache entry is refreshed. This is the passive model: the DC announces its own presence, and its silence is the expiry signal.

### 11.2 Referral DCs

The discovery source is the DLPE in a parent DC's Discovery Log Page. The timer starts when the referral entry disappears from the parent DC's DLP (detected immediately when the DC's AEN triggers a DLP re-fetch), regardless of whether the referral DC's connection is still alive at that point. A live connection is left undisturbed; the expiry is only felt when the connection later drops and is not reconnected. If the referral entry reappears in a later DLP before the timer expires, the timer is cancelled. Like mDNS, this is passive: the parent DC's DLP is the authoritative signal for whether the referral is still known.

One asymmetry with mDNS: if the parent DC itself becomes unreachable, its DLP cannot be refreshed, so the disappearance of a referral entry may not be detected until the parent DC reconnects. This is acceptable — the parent DC's own connection will time out and eventually cause a cache eviction, which drags the unreachable referral DC with it.

Whether the referral disappeared because the upstream administrator intentionally removed it from the parent DC's DLP, or because the parent DC or referral DC simply became unreachable, the handling is identical. The connect-only design makes the distinction irrelevant: no live connections are touched regardless of cause, so there is no scenario where a more aggressive response would be warranted.

### 11.3 FC kickstart DCs

FC kickstart is an active mechanism: discoverd writes to `/sys/class/fc/fc_udev_device/nvme_discovery` to trigger a fabric probe; the FC HBA firmware responds with `FC_EVENT=="nvmediscovery"` uevents, one per currently reachable target. Unlike mDNS or DLP referrals, an FC DC does not announce its own presence — it only appears when discoverd explicitly asks. The NVMe Boot Specification characterizes FC as "self-discovering" — the HBA is always aware of what is reachable on the fabric; kickstart is simply asking it to report.

**The equipment replacement scenario.** Consider an FC DC that fails and is replaced. The replacement unit may have a different address and a different subsystem NQN — in that case it looks like an entirely new DC from the host's perspective. Two things must happen for the host to reconnect correctly: the old DC's TID must eventually be evicted (it is dead and will never come back), and the new DC's TID must be discovered. `discovery-retention-time` handles the first; periodic kickstart handles the second. Without periodic kickstart, the new DC would only be discovered if something else happened to trigger a kickstart — daemon restart, SIGHUP, or an unrelated FC controller drop — which may not be acceptable in an FC production environment. Environments that rely on FC and want timely detection of equipment replacement should set `fc-kickstart-interval-minutes` to a suitable interval.

**Connection loss as the primary trigger.** When an FC DC's connection drops and ctrl-loss-tmo expires, discoverd re-issues kickstart as part of its normal FC reconnect path (§5). If the DC's TID appears in the response, discoverd reconnects. If not, discoverd starts the retention timer. If the TID reappears in a subsequent kickstart response before the timer expires, the timer is cancelled and the DC is reconnected. If the timer expires without the TID reappearing, the cache entry is evicted.

**Periodic kickstart.** Relying solely on connection loss as the kickstart trigger has a gap: a DC that disappears while its connection is still alive is not detected until ctrl-loss-tmo expires. More importantly, a new replacement DC would not be found until an existing connection drops and triggers kickstart. A periodic kickstart — `fc-kickstart-interval-minutes` — closes this gap by probing the fabric on a schedule, independently of connection events.

`0` disables periodic kickstart (connection-loss-triggered kickstart still applies); this is the default, since nvme-discoverd runs on all Linux systems including those with no FC infrastructure. Any value ≥ 1 is a valid interval in minutes; a value of 1 means a replacement DC is typically discovered within a minute of the replacement being completed.

The `fc-kickstart-interval-minutes` and `discovery-retention-time` are orthogonal knobs: the kickstart interval governs how quickly topology changes are detected; the retention time governs how long to tolerate a DC's absence before evicting it. With periodic kickstart disabled (the default), the replacement scenario above depends on an unrelated connection drop to trigger kickstart, which may be acceptable in environments where FC equipment replacement is rare or easily followed by a daemon restart.

**Config addition** (to `[Global]`):

| Option | Default | Description |
|--------|---------|-------------|
| `fc-kickstart-interval-minutes` | 0 | Periodic FC kickstart interval in minutes. Discoverd re-issues kickstart on this schedule, independently of connection events, to detect topology changes such as equipment replacement. `0` disables periodic kickstart (default); connection-loss-triggered kickstart (§5) still applies. Any value ≥ 1 is valid. |

---

## 12. Legacy Autoconnect Mechanisms Replaced

nvme-cli currently ships a collection of udev rules, systemd units, a dracut config snippet, and a NetworkManager dispatcher script that together implement NVMe-oF autoconnect. These accreted over years, are difficult to reason about as a whole, and have transport- and network-manager-specific gaps. This section inventories every component, states when it fires, and describes how nvme-discoverd subsumes it. The guiding distinction is between components that *establish connections* — which discoverd replaces — and components that perform *orthogonal tuning, key provisioning, or interface naming* — which discoverd leaves in place. The disposition column reflects the static-replacement build model of §1: replaced components are simply not installed when nvme-discoverd is built.

### 12.1 Inventory

| Component | Kind | Fires when | Disposition |
|-----------|------|-----------|-------------|
| `70-nvmf-autoconnect.rules` | udev rule | DC Discovery Log Page Change AEN (`0x70f002`), DC `rediscover`, and FC `nvmediscovery` uevents | **Replaced** — discoverd's event loop handles all three (§7.1) |
| `nvmf-connect@.service` | systemd template | Instantiated per-TID by the rule above | **Replaced** — discoverd creates its own transient units (§3.2) |
| `nvmf-connect.target` | systemd target | Collective handle for the `nvmf-connect@` instances (`PartOf=`/`Requires=`) | **Replaced — no equivalent needed.** The target existed only because the daemon-less design had no central coordinator: it gave the per-TID swarm a single object to reference, stop, or restart as a group. The discoverd daemon *is* that coordinator (it owns each unit's `StartTransient`/`StopUnit`/`RestartUnit` lifecycle), so a grouping target is redundant. It would also be harmful: its `PartOf=` group-stop semantics contradict the connect-only model (§1) and the rule that transient units must survive a daemon restart (§3.2). Enumeration is available via the `nvme-discoverd-*` unit naming convention |
| `nvmefc-boot-connections.service` | systemd oneshot | Once at boot, if an FC HBA is present | **Replaced** — discoverd does the FC kickstart at startup and on every FC drop (§7.1, §11.3) |
| `nvmf-autoconnect.service` | systemd oneshot | Once at boot, if `config.json`/`discovery.conf` exists | **Replaced** — discoverd reconnects configured controllers from `connections.d/` at startup (§7.1) |
| `nvmf-connect-nbft.service` | systemd oneshot | On demand, started by the NM dispatcher on NBFT-interface up | **Replaced** — discoverd adopts/reconnects NBFT controllers from its NBFT cache (§7.1); see §12.5 |
| `80-nvmf-connect-nbft.sh` | NM dispatcher | NetworkManager interface-up for `nbft*`/HFI connections | **Replaced** — discoverd's retry loop, manager-agnostic (§12.5) |
| `70-nvmf-autoconnect.conf` | dracut conf | Build-time `install_items+=` snippet that copies `70-nvmf-autoconnect.rules` into the initramfs | **Remove outright** (pre-existing cruft). dracut has never used `70-nvmf-autoconnect.rules` and ships its own initramfs mechanism, so this snippet only copies an inert rule into the initrd. Safe to delete from nvme-cli independently of discoverd; early-boot connect is dracut's job (§7.1, §12.2) |
| `65-persistent-net-nbft.rules` | udev rule | Naming of `nbft*` interfaces | **Remove (pending @mwilck)** — pins `nbft*` interface names, but the only consumer of that name was the NM dispatcher `80-nvmf-connect-nbft.sh` (matching `nbft*`), which is itself being removed; with no consumer the naming rule has nothing to serve. Held pending @mwilck confirming nothing else relied on the `nbft*` name |
| `70-nvmf-keys.rules` | udev rule | `nvme_tcp` module load; imports TLS PSK into the keyring | **Kept** — key provisioning, orthogonal to connect |
| `71-nvmf-{hpe,netapp,vastdata}.rules` | udev rules | `nvme-subsystem`/`nvme` add; set `iopolicy` & `ctrl_loss_tmo` | **Kept** — vendor device tuning, orthogonal |
| `70-nvmf-registry.rules` (new) | udev rule | `nvme` controller remove; prunes `/run/nvme/registry/` | **Kept** — part of this work, complementary |

### 12.2 The core autoconnect rules (replaced)

`70-nvmf-autoconnect.rules` is the heart of the legacy mechanism. It has three match clauses, each of which runs `systemctl --no-block restart nvmf-connect@<TID>.service`: a DC raised a **Discovery Log Page Change** notification (AEN type Notice, information F0h, log page 70h — i.e. `NVME_AEN=="0x70f002"`), a discovery controller reconnected (`NVME_EVENT=="rediscover"`, `cntrltype=="discovery"`), and an FC discovery event (`SUBSYSTEM=="fc"`, `FC_EVENT=="nvmediscovery"`). The templated `nvmf-connect@.service` then runs `nvme connect-all --context=autoconnect` for that one TID, with the TID encoded into the unit instance name as a tab-separated, hex-escaped argument string.

Two structural weaknesses motivate discoverd. First, there is **no retry**: if `connect-all` fails because the target is momentarily unreachable, the triggering uevent is already consumed and nothing reconnects until the next fabric event happens to fire — which may be never. Second, the **TID-in-unit-name encoding** is fragile and opaque. discoverd replaces both with a long-lived event loop that owns the desired set and retries on its own schedule (§5), so a transient failure is recovered without waiting for another fabric event, and connection state lives in the registry and state files rather than in escaped systemd unit names.

**Scope — this replacement applies to the running system only.** In the initramfs (Phase 1, before `switch_root`), discoverd does not run — by design, not by impossibility. Phase 1 only needs a one-shot connect to mount the root filesystem; the ongoing AEN/rediscover-driven management that `70-nvmf-autoconnect.rules` (and discoverd) provide is a running-system concern. Early-boot connectivity is owned by dracut's nvmf module (`74nvmf`, formerly `95nvmf`), which is self-contained and portable across both systemd and non-systemd initramfs: it uses its own `initqueue`-based udev rule (`95-nvmf-initqueue.rules`) and a one-shot, prioritized connect script (`nvmf-autoconnect.sh`: FC kickstart, then `connect-all --nbft`, then `connect-all` from `discovery.conf`/`config.json`), and has never used `70-nvmf-autoconnect.rules`. (dracut also honours a third early-boot path: the manual `rd.nvmf.*` kernel-command-line arguments, parsed by its `74nvmf` `parse-nvmf-boot-connections.sh`, whose real-world adoption is uncertain. Like NBFT and the FC kickstart, it is a Phase-1/dracut concern, not discoverd's.) Running discoverd there would also be inappropriate on footprint grounds and is outright impossible in a non-systemd initrd. Removing this rule from the running-system install therefore has no effect on Phase 1; after `switch_root`, discoverd adopts whatever the initramfs connected (§7.1, §9).

Note that being root, a process *can* drive systemd (start units, even `StartTransientUnit`) in a systemd-based initrd without the D-Bus message-bus daemon — `systemctl`/`systemd-run` talk to PID 1 directly over its private socket (`/run/systemd/private`). So discoverd is kept out of Phase 1 by the design reasons above, not because the bus is absent. dracut nonetheless avoids systemd services in the initrd and uses `initqueue` instead, which is what makes its mechanism work uniformly even in a non-systemd initrd.

**`70-nvmf-autoconnect.conf` is pre-existing dead weight and should be removed from nvme-cli outright.** It is a dracut configuration snippet (`install_items+= …/70-nvmf-autoconnect.rules`) whose only effect is to copy the rule into every initramfs. But the rule alone does nothing there: its `RUN+=` lines start `nvmf-connect@<TID>.service`, so making it functional would also require copying in `nvmf-connect@.service` and `nvmf-connect.target` — which the snippet does not do, so the `systemctl` call fails with "unit not found." More fundamentally, dracut never relied on any of this: a search of the entire dracut history finds no reference to `70-nvmf-autoconnect.rules`, and dracut's nvmf module has shipped its own FC `initqueue` rule since 2020. So the snippet has only ever copied an inert rule into the initrd that dracut ignores in favour of its own mechanism. It can be deleted from nvme-cli independently of nvme-discoverd — and in practice already is downstream: Fedora's rpm build explicitly deletes `70-nvmf-autoconnect.conf` during the build.

### 12.3 FC boot kickstart (replaced)

`nvmefc-boot-connections.service` writes `add` to `/sys/class/fc/fc_udev_device/nvme_discovery` exactly once at boot, gated by `ConditionPathExists=` on that same path so it is a silent no-op on hosts without an FC HBA. discoverd performs the identical kickstart at startup — self-gated at runtime: the write returns `ENOENT` on FC-less hosts and discoverd treats that as success, the programmatic equivalent of `ConditionPathExists=`, so the startup kickstart is harmless on a plain laptop. discoverd additionally re-issues the kickstart on every FC controller drop and, optionally, on a timer (§11.3), closing the equipment-replacement gap that a one-shot boot service structurally cannot cover.

### 12.4 Config-file boot connect (replaced)

`nvmf-autoconnect.service` runs `nvme connect-all --context=autoconnect` once at boot when `config.json` or the legacy `discovery.conf` exists, ordered `After=network-online.target`. discoverd reconnects the same statically configured controllers from `discoverd.conf` at startup and then keeps retrying them — static entries retry indefinitely (§11), unlike the one-shot service which gets a single attempt. discoverd does not consume the legacy `discovery.conf` (§2).

### 12.5 NBFT late-connect and the network-manager problem

This is the most tangled piece of the legacy set, and the immediate reason for inventorying the whole collection.

The normal NBFT boot path does not involve any of these units: NBFT-listed controllers are connected inside the initramfs by dracut's `95nvmf` module, before `switch_root`. The only case left for the real root is an NBFT interface that **could not** be brought up during initramfs and comes up later. `nvmf-connect-nbft.service` exists to cover that late case: it runs `nvme connect-all --nbft`, gated by `ConditionPathExists=` on the NBFT ACPI table.

But that unit has **no `[Install]` section** — it is never enabled, and systemd never starts it on its own. Its `After=network-online.target` is therefore inert ordering that only takes effect if something else pulls the unit in. What pulls it in is the NetworkManager dispatcher script `80-nvmf-connect-nbft.sh`: on interface-up, if the interface name matches `nbft*` or NetworkManager's `CONNECTION_ID` begins with `"NBFT connection HFI"`, it runs `systemctl --no-block start nvmf-connect-nbft.service`.

This has two problems:

1. **NetworkManager-specific.** The `dispatcher.d` callout mechanism belongs to NetworkManager; the legacy late-NBFT path supports NetworkManager and nothing else. This is not a fringe gap. **systemd-networkd is the most common alternative to NetworkManager** and is the default or preferred network stack on a large class of server, cloud, container-host, and immutable/minimal images — precisely the headless deployments where NVMe-oF boot and late-interface connect matter most. (It is also relevant to the SUSE sl16.2 target, which may be networkd-based.) systemd-networkd has **no** dispatcher / per-link up-script mechanism — confirmed against the systemd source tree, and a deliberate design choice, not an omission. The other managers — ifupdown, netplan-over-networkd, connman, or no manager at all — likewise never invoke the script. On every one of these the late NBFT connect simply, silently, never happens.
2. **Fragile matching.** Even under NetworkManager it depends on interface naming (`nbft*`, preserved by `65-persistent-net-nbft.rules`) or an exact connection-id prefix string.

**How discoverd is better — and what it actually needs.** discoverd already maintains a desired set and a retry loop (§5) that the legacy mechanism lacks entirely. Every NBFT-listed controller is in that desired set (from discoverd's NBFT cache, §7.1). A controller that could not be connected because its interface was not yet up is just a desired-set member whose connect currently fails; the retry loop reconnects it once the interface appears — with no interface matching, no name pattern, and no network-manager hook. This is manager-agnostic by construction: it behaves identically under NetworkManager, systemd-networkd, or no manager.

Kernel link-up monitoring is therefore an **optimization, not a correctness requirement**. If lower latency than the retry interval is wanted, discoverd can subscribe to link-up events (netlink / `sd_device`) and use them to "kick" the retry immediately instead of waiting for the next tick. Crucially, such an event carries no semantics discoverd must interpret: it does **not** need to match the interface against the NBFT table, because the retry loop already knows the desired set. The design is one connect path with two triggers — the periodic timer and an optional event-kick — both idempotent. The initial release can ship retry-only and later add the event-kick as a one-line trigger into the same retry entry point.

The link-up→fully-configured delay is in fact the reason the **periodic timer is the primary mechanism, not the event**. A link-up event says only that the *link* is up, not that the interface is *usable* — DHCP leasing, IPv6 route setup, and the like land afterward — so an event-driven connect would race ahead of readiness and fail. The timer does not care *why* the interface was not ready last tick; it simply retries until it is. So the event-kick can only ever be a best-effort accelerator, never a trigger to depend on. This matches the field experience that the old `After=network-online.target` approach "never really worked that way" under NetworkManager. The one genuine benefit the legacy NM-dispatcher hook had — logging and a clear service status for the connect attempt — is retained and improved here: every connection is its own transient unit, so each has a real `systemctl status` and journal trail.

As stated in §3.8, discoverd deliberately does **not** order itself `After=network-online.target` — the recovery mechanism is the periodic retry, not any systemd readiness state. The udev-vs-netlink question for the event source is tracked in §13 Open Questions item 1.

### 12.6 Components kept (orthogonal)

These are not connection mechanisms and discoverd leaves them installed:

- `70-nvmf-keys.rules` imports TLS pre-shared keys into the kernel keyring when `nvme_tcp` loads — key provisioning that any connect path depends on.
- `71-nvmf-{hpe,netapp,vastdata}.rules` set per-model `iopolicy` and `ctrl_loss_tmo` — device tuning applied after a namespace appears, independent of who established the connection.

(`65-persistent-net-nbft.rules` was previously listed here as orthogonal naming, but is now slated for removal — its only consumer, the NM dispatcher, is itself being removed; see §12.1, pending @mwilck's confirmation.)

The new `70-nvmf-registry.rules` (part of this work) prunes the ownership registry on controller removal and is likewise complementary, not a connect mechanism.

---

## 13. Open Questions

1. **Kernel uevents vs udev events** — Reading kernel uevents directly avoids the udevd dependency but requires custom filtering and large receive buffers. udev event monitoring is more comfortable but adds latency. Not yet resolved. Note: if udev monitoring is chosen, `nvme-discoverd.service` must add `After=systemd-udevd.service` to ensure udevd is ready before the daemon starts listening for events.

2. **Shutdown ordering vs. mounted filesystems** — Transient connection units carry only `After=network.target`. This does not guarantee they stop after filesystems mounted from those controllers are unmounted. The standard systemd pattern is `Before=remote-fs-pre.target` on the connection units: at shutdown (ordering reverses), units stop after `remote-fs-pre.target`; `_netdev` mount units have `After=remote-fs-pre.target` and therefore stop before it, ensuring unmount before disconnect. Needs verification and testing before adding to the unit templates.

3. **NBFT / root-backing controller at shutdown** — a controller backing the root filesystem must **not** be disconnected at shutdown: driving `nvme disconnect` into a still-mounted root can hang or lose data. The decision is therefore to **omit `ExecStop=` on root-backing (NBFT) units**, so no teardown is driven at shutdown and the kernel holds the connection alive until the block device is finally closed (this matches the current legacy behaviour, where NBFT is not disconnected at shutdown). Supporting field observations (@tbzatek): the kernel already keeps a disconnected controller's connection active until its block-device node is closed; and XFS has been seen to return from `umount` successfully while a final flush lands afterward, so tearing the device down right after umount lost writes — i.e. even a careful unmount-then-disconnect can race. The kernel/FS behaviour itself is out of discoverd's hands; this still needs verification on real hardware together with item 2.

4. **Systemd unit management: migrate to varlink** — discoverd currently uses `org.freedesktop.systemd1.Manager` D-Bus for all unit lifecycle operations. systemd v261 (in development) adds `io.systemd.Unit.StartTransient` over varlink with streaming job-completion notifications, but `StopUnit`, `RestartUnit`, and `ResetFailedUnit` have no varlink equivalent yet. D-Bus therefore remains the supported primary path for the foreseeable future; there is no plan to drop it until the full unit-lifecycle API is both available over varlink *and* broadly shipped in targeted baselines (realistically years out — see §3.9). The legacy autoconnect components are a separate, build-gated concern that need not migrate in lockstep.

5. **Does discoverd carry NBFT at all?** — The legacy NBFT *components* (`nvmf-connect-nbft.service`, the NetworkManager dispatcher, the `nbft*` naming rule) are being removed regardless (§12). What is open is whether discoverd should also stop parsing the NBFT table itself and rely purely on dracut-for-boot plus generic adoption of already-connected controllers. The real question is *what is discoverd's source of truth for the boot connections' desired set*: the authoritative NBFT table — which survives a down-state, so it covers both a late-coming interface and reconnect after a drop past `ctrl-loss-tmo` — versus best-effort generic adoption from sysfs, which only covers connections caught live and loses anything that is down during the adoption window. The reconnect-after-drop case is the strong argument for keeping a *minimal* NBFT awareness even as every legacy NBFT component is deleted: for a root device, "reconnected only if we happened to catch it live" is a weak guarantee. To be settled with lab data and @mwilck's read on NBFT's real-world reach.

---

## 14. Glossary

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
