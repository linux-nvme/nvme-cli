# nvme-discoverd

A persistent daemon that connects the host's NVMe-oF controllers and keeps them connected: NBFT boot controllers, everything listed in the shared fabrics configuration, and whatever those Discovery Controllers' Discovery Log Pages (and FC kickstart) turn up along the way.

> The code is the source of truth. This document summarizes behavior and intent; see `nvme-discoverd(8)` for the full CLI/config reference and `src/*.h` for module-level contracts.

## Why it exists

The host's alternative today is a udev-rule-triggered swarm of systemd units (`70-nvmf-autoconnect.rules`, `nvmf-connect@.service`, and friends — still built when the `nvmf-autoconnect` meson option is enabled). That mechanism has no retry: if a connect attempt fails because the target is momentarily unreachable, nothing happens until the next fabric event happens to fire, which may be never. nvme-discoverd is a real daemon with its own retry loop, so a transient failure recovers on its own.

**nvme-discoverd and the legacy autoconnect units currently ship side by side, both enabled by default.** This is a beta-stabilization posture, not the end state — switching a host from one to the other is a deliberate `systemctl` operation for the administrator, not something either mechanism decides for itself. Once nvme-discoverd is proven out, the `nvme-discoverd`/`nvmf-autoconnect` meson option defaults are expected to flip so a given build ships one or the other.

## Design

- **Single-threaded.** One `sd_event` loop, no threads. Every connect goes through a systemd transient unit running `nvme connect`, never a direct `/dev/nvme-fabrics` write — that ioctl blocks in D state until the kernel completes or times out the connection, and nvme-discoverd cannot afford to block its event loop on it.
- **Connect-only.** nvme-discoverd never disconnects a live controller because of a discovery change (that's TP8010 fabric-zoning territory, out of scope here). The only disconnects it causes are `ExecStop=` on its own transient units, at shutdown or on request.
- **Retry with backoff and a give-up horizon.** A failed (re)connect retries with exponential backoff, capped at 5 minutes. A Discovery Controller found only through a referral or FC kickstart — never one from NBFT or the fabrics config, which represent explicit intent and always retry forever — gives up after 72 hours of unbroken failure and is dropped from tracking.
- **Cooperative, not exclusive.** Every connection is registered in the ownership registry (`--owner discoverd`, or `--owner nbft` for an NBFT-sourced controller) and checked against the system-wide exclusion list before connecting or reconnecting — see `libnvme/design/REGISTRY.md` and `EXCLUSIONS.md`.

## Source layout

| File | Role |
|---|---|
| `main.c` | Startup, signal handling, the desired-connection orchestration, retry/give-up |
| `tid.c` | Transport-identity helpers: unit-name hashing, TID equality |
| `cache.c` | The desired-connection set: NBFT, fabrics-config, and per-DC Discovery Log Page tracking |
| `units.c` | Transient systemd units over D-Bus (`StartTransient`/`Restart`/`Stop`/`ResetFailed`) |
| `events.c` | udev monitoring: device add/remove/change, sysfs TID parsing |
| `dlp.c` | Discovery Log Page fetch and parsing |
| `fc.c` | FC kickstart |
| `config.c` | The daemon's own three knobs (`discoverd.conf`) — not the connections it manages, see below |
| `state.c` | Runtime state under `$RUNDIR/nvme/discoverd/`, linking a kernel device to the unit that owns it |
| `log.c` | Journal logging wrapper |

## Configuration

nvme-discoverd reads two independent files:

- **`discoverd.conf`** — the daemon's own knobs (`nbft`, `debug-level`, `fc-kickstart-interval-minutes`). Entirely optional; a missing file or key just keeps its default.
- **The shared NVMe-oF fabrics configuration** (`nvme-fabrics.conf(5)`) — which Discovery Controllers and subsystems to connect, host identity, per-connection parameters. This is the same file `nvme connect-all`, `nvme discover`, and `nvme-stas` read; nvme-discoverd has no private connection format of its own.

Both are reloaded on `SIGHUP`. Nothing already connected is ever disconnected by a reload.

## Out of scope (for now)

mDNS/DNS-SD discovery (TP8009), TP8010 fabric zoning, and disconnecting anything nvme-discoverd didn't itself decide to stop. These are nvme-stas's territory today; revisiting them is a future release, not this one.
