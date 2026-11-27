<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Privilege Separation

nvme-cli 3.2 has two features that limit what a bug in nvme-cli can do:

- **Privilege separation.** When root runs nvme-cli for a user, for example
  with `sudo`, a small helper process keeps root. nvme-cli itself drops its
  privileges to that user.
- **The decoder sandbox.** The code that decodes the data of a device runs in
  a child process. This process can do little more than allocate memory and
  write to stdout and stderr.

Both are **technology previews**. Both are disabled by default. They are work
in progress and may change. They may also be removed again if they turn out
not to be useful or too complicated. The design was discussed in [issue
#3879](https://github.com/linux-nvme/nvme-cli/issues/3879). The full design
is in [Design of privilege separation and the decoder sandbox](privsep-design.md).

## Why does it exist?

nvme-cli usually runs as root, because opening `/dev/nvme*` needs root. It
does two kinds of work:

- It talks to the kernel. It issues passthru ioctls and writes to
  `/dev/nvme-fabrics`. This needs root.
- It decodes the data that the device returns, and prints it as text or
  JSON. All vendor plugins do this too. This does not need root.

The second part is much larger. A device or a fabrics target controls this
data. A device that returns crafted or broken data can trigger a bug in a
decoder. Most bugs that fuzzing found in nvme-cli were in these decoders.
Without these features, such a bug runs with full root privileges.

## Privilege separation

Build with `-Dprivsep=enabled`. It works on Linux only.

nvme-cli drops its privileges when all of these are true:

- It runs as root.
- `SUDO_UID` is set (by `sudo`), or `NVME_PRIVSEP_UID` is set. The value is
  the user ID to drop to. `SUDO_GID` or `NVME_PRIVSEP_GID` sets the group ID.
- The command needs a device.

Root without `SUDO_UID` or `NVME_PRIVSEP_UID` keeps its privileges. Because
of this, scripts and services that run as root work as before.

Before it drops its privileges, nvme-cli starts `nvme-privsep-helper`. The
helper keeps root. It issues the NVMe commands for nvme-cli and returns the
raw result. It never decodes data from the device. The helper exists only
while the nvme-cli command runs. It is not a daemon.

If nvme-cli cannot start the helper or cannot drop its privileges, it exits
with an error. It does not continue as root.

After the drop, nvme-cli reads `nvme-cli.conf` as the target user. So this
file must be readable by all users.

Some commands still run as root:

- Commands without a device, for example the fabrics commands (`connect`,
  `discover`, ...), the `keys` commands and the registry commands.
- Device commands that need root for other reasons, for example to read PCI
  config space or the kernel log.
- NVMe-MI devices (`mctp:<net>,<eid>`).

Privilege separation does not limit what you can do with the device. A user
who may run `sudo nvme` can still run `sanitize`, `format`, `security-send`
or firmware commands. The user only loses root outside of the NVMe devices.

A setuid nvme-cli is not supported.

## The decoder sandbox

Build with `-Dsandbox=enabled`. It works on Linux and FreeBSD.

The printers that decode device data run in a forked child process. On
Linux, a seccomp filter restricts this process. On FreeBSD, Capsicum does.
The child cannot open files, and it cannot use the helper of privilege
separation. A crash in a decoder ends only the child. nvme-cli then prints
this error and exits:

```
the decoder of the device data crashed or misbehaved in the sandbox
```

The sandbox works with and without privilege separation. It also protects
plain root and the commands that keep root.

Control it with the `NVME_SANDBOX` environment variable:

```bash
# Turn the sandbox off, for example in a debugger:
NVME_SANDBOX=0 nvme id-ctrl /dev/nvme0

# Turn the sandbox on in a build without -Dsandbox=enabled:
NVME_SANDBOX=1 nvme id-ctrl /dev/nvme0
```

The output does not change, also with `-o json`. A printed object costs
less than 1 ms more.

## What changes for plugin authors

Nothing, for most plugins. All passthru commands go through
`libnvme_exec_admin_passthru()` and `libnvme_exec_io_passthru()`. With
privilege separation, these functions send the command to the helper.

Do not call `ioctl()` directly on the file descriptor from
`libnvme_transport_handle_get_fd()`. With privilege separation, this function
returns `LIBNVME_INVALID_FD`. Use the libnvme API instead.

In nvme-cli 3.2, the last two plugins with raw ioctls were changed:

- `plugins/sed`: uses the new libnvme sed module (`libnvme-sed.h`) for level 0
  discovery and Opal operations.
- `plugins/scaleflux`: uses libnvme calls instead of block device ioctls. The
  ScaleFlux proprietary ioctls are removed. Because of this, the clean card
  feature is gone, and CSD 2000 drives with the proprietary driver are no
  longer supported.

Decode device data through the `nvme_show_*()` functions. Only these run in
the sandbox. A plugin that decodes inside the command code is not covered.

## Current limits

- Both features are disabled by default.
- Commands without a device and the commands that need root for other
  reasons do not drop their privileges.
- The sandbox does not cover the code that fetches the data before it is
  printed, for example a log page that is read in parts.
- The sandbox does not cover vendor plugins that decode the data inside the
  command instead of through `nvme_show_*()`.
- Some printers stay in the main process. Examples are `list`,
  `list-subsys`, `show-topology` and `top`.

## See also

- [Design of privilege separation and the decoder sandbox](privsep-design.md)
- [Issue #3879: Privilege Separation](https://github.com/linux-nvme/nvme-cli/issues/3879)
- [Building nvme-cli](building.md)
