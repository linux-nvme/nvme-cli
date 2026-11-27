<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to set up NVMe-oF autoconnect

nvme-cli ships udev rules, systemd units, and a dracut module that connect
NVMe-oF subsystems automatically. You do not have to run `nvme connect` by hand.
This page describes how the pieces fit together.

nvme-cli has two independent autoconnect mechanisms:

- **udev/systemd autoconnect** (this page). Build option `nvmf-autoconnect`.
- **[nvme-discoverd](discoverd.md)**, a newer daemon. It is a technology
  preview and is not covered here.

Which one is built depends on the release:

| Release | udev/systemd autoconnect | nvme-discoverd |
|---|---|---|
| 3.0, 3.1 | Built by default. | Not built by default. |
| 3.2 | Built only when nvme-discoverd is not built. | Built by default when libsystemd 253 or later is available. |

`-Dnvmf-autoconnect=enabled` installs both. Do not rely on both at once in 3.0
and 3.1, because they overlap. Since 3.2, `nvmf-autoconnect.service` and the FC
kickstart skip their connect step while nvme-discoverd is active.

Since 3.2, `nvmf-autoconnect.service`, `nvmf-connect@.service` and
`nvmf-connect-nbft.service` start after `tlshd.service`. Without tlshd, a TLS
connection fails at once. This ordering does not start tlshd. Enable tlshd
yourself if you use TLS.

## What gets installed

| File | Type | Role |
|---|---|---|
| `nvmf-autoconnect.service` | systemd | Runs `nvme connect-all` once at boot. |
| `nvmf-connect@.service` | systemd | Reconnects one target after a udev event. |
| `nvmf-connect.target` | systemd | Groups all running `nvmf-connect@` instances. |
| `nvmefc-boot-connections.service` | systemd | Triggers Fibre Channel discovery at boot. |
| `nvmf-connect-nbft.service` | systemd | Connects the subsystems listed in the NBFT. |
| `70-nvmf-autoconnect.rules` | udev | Triggers `nvmf-connect@.service` on discovery events. |
| `65-persistent-net-nbft.rules` | udev | Keeps NBFT network interface names stable. |
| `80-nvmf-connect-nbft.sh` | NetworkManager dispatcher | Starts NBFT connect when a late interface comes up. |
| `70-nvmf-autoconnect.conf` | dracut | Adds the udev rule above to the initramfs. Installed only with the udev/systemd autoconnect. |

## Autoconnect at boot

`nvmf-autoconnect.service` runs once, after the network is up:

```
ExecStart=/usr/sbin/nvme connect-all --owner=autoconnect
```

It only starts if one of these exists: `/etc/nvme/config.json`,
`/etc/nvme/discovery.conf`, `/etc/nvme/nvme-fabrics.conf`, or a non-empty
`/etc/nvme/nvme-fabrics.conf.d/`. See
[How to configure NVMe-oF connections](fabrics-config.md) for
that file.

## Reconnecting on a Discovery Controller event

A Discovery Controller can tell the host its discovery log page changed, or the
kernel can report a Fibre Channel discovery event. `70-nvmf-autoconnect.rules`
watches for both and starts one `nvmf-connect@.service` instance per event, with
the transport, address, and interface baked into the instance name. Each
instance runs:

```
nvme connect-all --owner=autoconnect --quiet <args from the event>
```

This only fires for a Discovery Controller the host kept connected in the
first place. See
[NVMe-oF Persistent Discovery Controllers (PDC)](pdc.md)
for how a DC connection is kept open and how it ends up raising this event.

## Fibre Channel boot

`nvmefc-boot-connections.service` runs once at boot, if
`/sys/class/fc/fc_udev_device/nvme_discovery` exists. It writes to that file to
ask the kernel's FC transport to start discovery. The discovery result then
triggers `70-nvmf-autoconnect.rules` above, which does the actual connecting.

## NBFT: booting from a network-attached namespace

An NVMe-oF Boot Firmware Table (NBFT) is an ACPI table firmware writes to
describe the subsystem a system should boot from over the network. Three pieces
work together to use it:

- **`nvmf-connect-nbft.service`** runs `nvme connect-all --nbft`. It starts at
  boot if `/sys/firmware/acpi/tables/NBFT` (or `NBFT1`) exists.
- **`65-persistent-net-nbft.rules`** keeps a network interface named `nbft0`,
  `nbft1`, etc. from being renamed by other udev rules. NBFT interfaces are
  named this way so they can be recognized.
- **`80-nvmf-connect-nbft.sh`**, a NetworkManager dispatcher script, starts
  `nvmf-connect-nbft.service` again if an `nbft*` interface (or a connection
  named `NBFT connection HFI...`) comes up later. This covers an interface that
  could not come up during the initramfs stage.

`nvme connect-all --nbft` reads the NBFT itself; no config file is needed. Use
`--nbft-path=<path>` to point at a specific table instead of the default, and
`--no-nbft` to skip NBFT even if a table is present.

The dracut module (`70-nvmf-autoconnect.conf`) copies the udev rule above into
the initramfs, so NBFT connections can be made before the real root filesystem
is mounted. This matters for boot-from-SAN: the root filesystem itself may be on
the namespace being connected.

**Switching to nvme-discoverd:** a build with nvme-discoverd (the default since
3.2) does not install `70-nvmf-autoconnect.conf` or the udev rule. Package
updates remove them, but a host that had an earlier source install (`meson
install`) keeps the old files in `/usr/lib/dracut/dracut.conf.d/` and
`/usr/lib/udev/rules.d/`. dracut then still puts the legacy rule into the
initramfs. Remove both files and rebuild the initramfs.

## Connection ownership

Every connection these mechanisms make is tagged with `--owner=autoconnect` in
the NVMe ownership registry (`nvme connect-all --nbft` defaults to owner `pre-os`
instead, unless `--owner` is given explicitly; nvme-cli 3.0 to 3.2 call it `nbft`). In nvme-cli 3.0, `nvme
disconnect-all` with no arguments only disconnects controllers with no recorded
owner. It leaves these autoconnected controllers alone. See
[Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md) for
that behavior change.

## Vendor tuning rules

Three more udev rules ship regardless of which autoconnect mechanism, if any, is
in use. They set the native NVMe multipath I/O policy and disable the
controller-loss timeout for specific storage arrays:

- `71-nvmf-hpe.rules`: HPE Alletra Storage MP
- `71-nvmf-netapp.rules`: NetApp ONTAP and NetApp E-Series
- `71-nvmf-vastdata.rules`: VAST Data

For example, `71-nvmf-netapp.rules` sets `iopolicy=queue-depth` on an ONTAP
subsystem and `ctrl_loss_tmo=-1` (never give up on a lost controller) on its TCP
controllers. Adjust or copy these rules if you need similar tuning for another
array.

## TLS keys

A fourth udev rule, `70-nvmf-keys.rules`, loads TLS keys into the kernel keyring
when the `nvme_tcp` module loads. It is covered in
[How to set up TLS for NVMe-TCP](tls.md).
