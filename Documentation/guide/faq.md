<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Frequently asked questions

See also [Troubleshooting](troubleshooting.md).

## Why do device names change after a hotplug or a reboot?

### Question

A controller is hot-unplugged or the host reboots. Why does a block device
such as `/dev/nvme3n1` still appear in `nvme list` after the controller
`nvme3` is gone? Why do the controller numbers in `nvme list` and `nvme
list-subsys` change?

### Answer

This is the expected behavior of the Linux NVMe driver.

1. **Controller numbers are not persistent.** The kernel does not keep the
   instance numbers of controllers (`nvme0`, `nvme1`, ...) or the names of
   block devices (`/dev/nvmeXnY`) across a reboot or a hotplug (PCIe hotplug,
   DLPAR). A controller that comes back gets the next free number. For
   example, `nvme3` becomes `nvme4`.

2. **Multipath namespaces belong to the subsystem, not to a controller.** With
   native NVMe multipath, the block devices in `nvme list` (`/dev/nvmeSnN`)
   and the generic character devices (`/dev/ngSnN`) are multipath namespace
   heads. Their number is the number of the subsystem (`nvme-subsysS`), not of
   a controller:
   - `/dev/nvme3n1` belongs to `nvme-subsys3`.
   - `/dev/nvme2n1` belongs to `nvme-subsys2`.

   A subsystem can have several controllers (paths). If one controller goes
   away, for example `nvme3`, the other controllers stay, for example `nvme1`.
   While at least one path to `nvme-subsys3` is live, the subsystem and its
   namespace heads stay, and their device nodes do not disappear.

### Best practices

- Do not use the names `/dev/nvmeX` or `/dev/nvmeXnY` in scripts, automation
  or tests.
- Run `nvme list -v` or `nvme list-subsys -v` to see the subsystems, the
  controllers and the namespaces together.
- Use persistent names to find and mount devices:
  - the links in `/dev/disk/by-id/`, for example `nvme-eui.*` and `nvme-nvme.*`
  - the subsystem NQN (`nvme-subsysX - NQN=...`)
