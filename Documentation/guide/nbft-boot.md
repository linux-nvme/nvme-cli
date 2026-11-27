<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Booting from NVMe-oF with NBFT

A host can boot from a namespace on an NVMe/TCP target. The UEFI firmware
connects to the target and loads the boot loader from it. The firmware then
describes the connection in an ACPI table, the NVMe Boot Firmware Table
(NBFT). The operating system reads the NBFT and connects the same
controllers again. The NBFT is defined in the NVM Express Boot Specification.

This page describes what nvme-cli does with the NBFT. The firmware setup
depends on the vendor of the host.

## Show the NBFT

The kernel provides the table as `/sys/firmware/acpi/tables/NBFT` (and
`NBFT1`, ... if there are several). `nvme nbft show` decodes it:

```
# nvme nbft show

/sys/firmware/acpi/tables/NBFT:

NBFT Subsystems:

Idx|NQN                                                    |Trsp|Address      |SvcId|HFIs
---+-------------------------------------------------------+----+-------------+-----+----
1  |nqn.1988-11.com.dell:powerstore:00:88b402df2d762AA7AF94|tcp |172.18.240.60|4420 |1
2  |nqn.1988-11.com.dell:powerstore:00:88b402df2d762AA7AF94|tcp |172.18.240.60|4420 |1

NBFT HFIs:

Idx|Trsp|PCI Addr  |MAC Addr         |DHCP|IP Addr     |Mask|Gateway |DNS
---+----+----------+-----------------+----+------------+----+--------+--------
1  |tcp |0:6a:0.0  |00:62:0b:cb:eb:70|no  |172.18.240.1|24  |0.0.0.0 |0.0.0.0
```

- **Subsystems** are the NVMe-oF subsystems to connect.
- **HFIs** (host fabric interfaces) are the network interfaces of the host,
  with their address settings.
- `--discovery` also shows the Discovery Controllers. `-o json` prints all
  details, including the host NQN.
- `--nbft-path=<dir>` reads the tables from another directory, for example a
  copy for a bug report.

## Connect the NBFT controllers

`nvme connect-all --nbft` connects the subsystems of the NBFT:

```bash
nvme connect-all --nbft
```

It connects through the network interface of the HFI. It records the owner
`pre-os` in the [ownership
registry](registry-exclusions.md). Because of this,
`nvme disconnect-all` and `nvme disconnect` do not disconnect the boot volume
(they need `--owner=pre-os` or `--force`). `--owner=NAME` records another
owner. nvme-cli 3.0 to 3.2 record the owner as `nbft`; it is the old name of
`pre-os` and means the same.

## The pre-OS and the OS environment

Since nvme-cli 3.3 the controllers of a host that boots from NVMe-oF follow one
rule: **the context that connects a controller owns it, and ownership is never
handed over.**

- The **pre-OS environment** is everything before the real root: the firmware
  (which writes the NBFT) and the initramfs. Every controller it connects gets
  the owner `pre-os`, NBFT or not, root file system or not.
- The **OS environment** is the real root, with systemd and nvme-discoverd. It
  keeps the pre-OS connections up, reconnects them when they are lost, but
  never owns or disconnects them, also not at shutdown.

The design is in
[`libnvme/design/PRE-OS.md`](https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/PRE-OS.md).

### In the initramfs

The initramfs must connect the boot namespace before it can mount the root
file system. The initramfs generator does this, for example the `nvmf` module
of dracut. It is not part of nvme-cli.

With nvme-cli 3.3, in the initramfs (`/etc/initrd-release` exists), `nvme`:

- connects with the owner `pre-os` when it is asked to (`connect-all --nbft`
  does so by default, dracut passes `--owner=pre-os` for every other connect,
  see below);
- uses `ctrl_loss_tmo=-1` for pre-OS connections unless one is given, so the
  root is never given up; vendor defaults (`vendor.d`) do not override it;
- records every requested connection, also a failed one, in
  `/run/nvme/pre-os.conf.d/` for the OS environment. NBFT paths are not
  recorded (the NBFT is still there). **Credentials are never recorded**
  (DH-HMAC-CHAP secrets, inline TLS keys): load them into the kernel keyring,
  in the OS with [nvme-keysd](keysd.md).

dracut has to pass `--owner=pre-os` to the connects that are not from the NBFT
(Fibre Channel, `rd.nvmf.discover=`, `nvme-fabrics.conf`); it checks
`nvme connect-all --help` for `pre-os`. dracut then also disconnects the pre-OS
controllers in the shutdown initramfs, after the root is unmounted, so the
target sees a clean disconnect. This is
[dracut-ng/dracut#2825](https://github.com/dracut-ng/dracut/pull/2825), which
is not merged yet; the fixes dracut needs for nvme-cli 3 at all are
[dracut-ng/dracut#2820](https://github.com/dracut-ng/dracut/pull/2820).

### After the switch to the root file system

Some HFIs come up only after the initramfs, for example a second path for
multipath. Then the host must connect the NBFT controllers again later. How
this works depends on the nvme-cli version and build:

- **nvme-discoverd** (built by default since nvme-cli 3.2): it reads the NBFT
  at start and connects its controllers. Since 3.3 it also takes the entries
  of `/run/nvme/pre-os.conf.d/` and what a pre-OS discovery controller lists.
  It connects them with the owner `pre-os` and the parameters the pre-OS
  environment used, never disconnects their I/O controllers and does not
  apply the exclusion list to them. `pre-os = true` in the `[Global]` section
  of `nvme-discoverd.conf` controls this (`nbft` is its old name). It is the
  default. It retries a failed connection, for example when an HFI comes up
  late. It works with any network management. See
  [nvme-discoverd](discoverd.md).
- **Legacy autoconnect** (built when nvme-discoverd is not built): the
  NetworkManager dispatcher script `80-nvmf-connect-nbft.sh` starts
  `nvmf-connect-nbft.service` when an NBFT interface comes up. The service
  runs `nvme connect-all --nbft`. There is no such hook for
  systemd-networkd. On a host without NetworkManager, a late HFI is not
  connected.

### Which initramfs works with which OS

| Initramfs | Owner it records | In the OS (nvme-cli 3.3, nvme-discoverd) |
|---|---|---|
| nvme-cli 2.x | none | NBFT paths are still pre-OS (from the NBFT); other paths are adopted by nvme-discoverd |
| nvme-cli 3.0 to 3.2 | `nbft` for `connect-all --nbft` | same as `pre-os` |
| nvme-cli 3.3, dracut without `--owner=pre-os` | `pre-os` for the NBFT only | Fibre Channel and configured paths have no owner: nvme-discoverd adopts them and disconnects them at shutdown, as before |
| nvme-cli 3.3, dracut with `--owner=pre-os` | `pre-os` for all | all kept, none disconnected |

Update dracut and rebuild the initramfs together with nvme-cli.

## Network interface names

How the network interfaces of the HFIs are named depends on the model:

| | Legacy (dracut without `--owner=pre-os`) | Pre-OS model |
|---|---|---|
| Interface name | renamed to `nbft0`, `nbft1`, ... by the initramfs | kept as the kernel named it; nvme finds the HFI by its MAC address |
| NetworkManager | profiles "NBFT connection HFI ..." | nm-initrd-generator reads the NBFT itself (NetworkManager 1.60 or later for libnvme 3, [NetworkManager!2597](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/merge_requests/2597)) |
| systemd-networkd | `ip=` by the `nbftN` name | dracut writes a `.network` file that matches the MAC address (and a `.netdev` for a VLAN) |
| network-legacy (dracut) | `nbftN` | still `nbftN` |

The udev rule `65-persistent-net-nbft.rules` keeps the `nbftN` names after
the switch to the root file system, so that udev does not rename them.
nvme-cli installs this rule with every NVMe-oF build.

## Take an NBFT path out of service

The NBFT is in the firmware. You cannot edit it on the host. To stop the
host from connecting an NBFT controller, add it to the [exclusion
list](registry-exclusions.md#exclusion-list):

```bash
nvme exclusion add --entry="nqn=<subsystem NQN>;traddr=<address>"
```

`nvme connect-all --nbft` and nvme-discoverd then skip it.

## See also

- [nvme-discoverd](discoverd.md)
- [How to set up NVMe-oF autoconnect](autoconnect.md)
- [NVM Express Boot Specification](https://nvmexpress.org/specifications/)
- [`nvme-connect-all(1)`](man:nvme-connect-all), [`nvme-discoverd(8)`](man:nvme-discoverd)
