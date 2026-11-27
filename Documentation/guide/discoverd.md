<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# nvme-discoverd

nvme-discoverd is a systemd daemon. It is built from the nvme-cli source tree.
It keeps a host's NVMe-oF fabric connections up. It connects the Discovery
Controllers it is told about. Those come from static configuration, NBFT,
Fibre Channel discovery, or (since 3.2, opt-in) mDNS. Once a Discovery
Controller is connected, discoverd reads its Discovery Log Page (DLP). It then
discovers and connects the I/O Controllers and any referred Discovery
Controllers that DLP lists. It retries automatically when a connection fails
or drops. It has no role on a host with only local (PCIe) NVMe. It is needed
only for NVMe over Fabrics. It is currently a **technology preview**. It
requires the `fabrics` build option and libsystemd 253 or later.

Since nvme-cli 3.2, nvme-discoverd is built by default when
libsystemd 253 or later is available. In 3.0 and 3.1, it is disabled by
default. Build with `-Dnvme-discoverd=enabled` to try it there. The daemon
only runs when you enable it:

```bash
systemctl enable --now nvme-discoverd.service
```

## Why does it exist?

nvme-cli already autoconnects NVMe-oF targets. It uses a collection of udev
rules and one-shot systemd services (see [How to set up NVMe-oF
autoconnect](autoconnect.md)). That mechanism accreted over
several years, one rule at a time. It has two structural gaps. A persistent
daemon can close both. A set of udev rules cannot.

- **No retry.** Each rule fires once per event. Events are a Discovery Log
  Page Change AEN, a rediscover, or an FC discovery uevent. Each one starts
  `nvme connect-all` for that one target. If the target is momentarily
  unreachable, that attempt fails. Nothing tries again until the next
  unrelated event happens to fire. That may be never.
- **The late-NBFT path only works under NetworkManager.** A host may boot from
  a network-attached namespace. One of its interfaces may come up after the
  initramfs stage. The retry for that case depends on a NetworkManager
  dispatcher script. systemd-networkd has no equivalent hook. It is common on
  servers and minimal images. On those hosts the late connection silently
  never happens.

nvme-discoverd is a long-lived process instead of a chain of one-shot rules.
So it can just keep trying. It owns a "desired set" of connections. The set
comes from static config, the NBFT table, and Discovery Log Pages already
read. It retries anything in that set that isn't currently connected. It does
this on its own schedule. It does not wait for any particular event to fire.
That retry loop is manager-agnostic by construction. It doesn't care whether
NetworkManager, systemd-networkd, or nothing at all is running. So it also
fixes the late-NBFT gap above as a side effect. No interface-name matching is
involved.

## How is it different from nvme-stas?

nvme-discoverd is **connect-only**. Once it connects something, it never
disconnects it in response to DLP changes. There is no logic that decides a
subsystem dropped out of the Discovery Log Page and should be torn down. The
only disconnects it causes are a `systemctl stop` and cleanup of a controller
the kernel already removed. `systemctl stop` covers shutdown and a manual
stop. This is a deliberate simplification. It avoids the whole class of
connect/disconnect ordering bugs. The cost is that it does not implement
TP8010 Fabric Zoning. That is where a Centralized Discovery Controller tells
the host a subsystem should be disconnected.

Since nvme-cli 3.2, nvme-discoverd releases a controller it no longer wants.
Examples are a controller removed from the configuration or from the DLP of a
DC, or one that the exclusion list now matches. nvme-discoverd clears the owner
in the registry and leaves the connection up.

[nvme-stas](https://github.com/linux-nvme/nvme-stas) is a separate project. It
does implement that stateful reconciliation. It also implements TP8009
zeroconf (mDNS) discovery. It does this through its own daemons, stafd and
stacd. nvme-discoverd and nvme-stas can both run on the same host. They
coordinate through the NVMe-oF ownership registry and the system-wide
exclusion list. Neither one touches a connection the other one owns.

## mDNS discovery (TP8009)

Since nvme-cli 3.2, nvme-discoverd can find Discovery Controllers
through mDNS. This is opt-in. It needs:

- nvme-discoverd built with the `mdns` meson option. This option needs
  libsystemd 258 or later. It is built by default when this version is
  available.
- systemd-resolved 258 or later at runtime, with mDNS enabled
  (`MulticastDNS=yes`).
- `zeroconf = true` in `nvme-discoverd.conf`:

```ini
[Discovery]
zeroconf = true
```

nvme-discoverd re-reads this setting on `SIGHUP`.

## Configuration

nvme-discoverd reads its own settings from `/etc/nvme/nvme-discoverd.conf`.
This file is optional. Without it, every setting keeps its default. Since
nvme-cli 3.2, `meson install` does not install this file. It installs a
commented `nvme-discoverd.conf.sample` instead. Copy it to
`nvme-discoverd.conf` to change a setting:

```ini
[Global]
nbft = true
debug-level = info

[Discovery]
epcsd-poll-interval-minutes = 15
fc-kickstart-interval-minutes = 0
dc-giveup-timeout = 72hours
zeroconf = false
```

In 3.0 and 3.1, `epcsd-poll-interval-minutes`, `fc-kickstart-interval-minutes`
and `dc-giveup-timeout` are in `[Global]`. Since 3.2, nvme-discoverd ignores
them in `[Global]` and logs an "unknown key" warning. Move them to
`[Discovery]` when you update. See [`nvme-discoverd(8)`](man:nvme-discoverd) for the meaning of each
key.

The connections themselves come from `nvme-fabrics.conf`. See [How to
configure NVMe-oF connections](fabrics-config.md).

## File systems on NVMe-oF namespaces

Mount a file system on an NVMe-oF namespace with the `_netdev` option in
`/etc/fstab`. Since nvme-cli 3.2, nvme-discoverd disconnects a controller at
shutdown only after the `_netdev` file systems are unmounted. Without
`_netdev`, the controller can be disconnected while the file system is still
mounted.

## Working with the legacy autoconnect

Since nvme-cli 3.2, the legacy udev/systemd autoconnect is built only when
nvme-discoverd is not built. `-Dnvmf-autoconnect=enabled` installs both.

If both are installed, the legacy udev rules are active at once.
nvme-discoverd runs only when you enable `nvme-discoverd.service`. While
nvme-discoverd is active, `nvmf-autoconnect.service` and the FC kickstart skip
their connect step. So the two do not race.

nvme-discoverd and the autoconnect units start after `tlshd.service`. Without
tlshd, a TLS connection fails at once. This ordering does not start tlshd. You
must enable tlshd yourself if you use TLS.

## Current limits

- No TP8010 Fabric Zoning. nvme-discoverd never disconnects a controller
  because of a discovery change. See [How is it different from
  nvme-stas?](#how-is-it-different-from-nvme-stas)
- In nvme-cli 3.0 and 3.1, nvme-discoverd is not built by default, and the
  legacy autoconnect does not skip its connect step while nvme-discoverd runs.
  Both react to the same events. Do not rely on both at once.

The legacy udev/systemd autoconnect mechanism will eventually be deprecated
and removed. Then nvme-discoverd (or a successor covering the same job)
becomes the only way to autoconnect NVMe-oF targets on Linux. No date is set
for that.

## See also

- [How to set up NVMe-oF autoconnect](autoconnect.md)
- [NVMe-oF Persistent Discovery Controllers
  (PDC)](pdc.md)
- [Booting from NVMe-oF with NBFT](nbft-boot.md)
- [NVMe-oF ownership registry and exclusion
  list](registry-exclusions.md)
- [nvme-stas](https://github.com/linux-nvme/nvme-stas)
- [nvme-discoverd's own
  README](https://github.com/linux-nvme/nvme-cli/blob/master/discoverd/README.md),
  for source layout and design detail beyond this page
