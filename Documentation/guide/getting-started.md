<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Getting started

nvme-cli is the command line tool to manage NVMe devices. It runs on Linux,
Windows (since nvme-cli 3.0) and FreeBSD (since nvme-cli 3.2).

## Install

### Distribution package

Most distributions ship nvme-cli. The package name is usually `nvme-cli`:

```bash
dnf install nvme-cli        # Fedora, RHEL, CentOS Stream
apt install nvme-cli        # Debian, Ubuntu
zypper install nvme-cli     # openSUSE, SLES
pacman -S nvme-cli          # Arch Linux
```

Check the version:

```
$ nvme version
nvme version 3.2 (git 3.2)
libnvme version 3.2 (git 3.2)
```

A distribution may ship an older version. This guide describes nvme-cli 3.x.
If you use 2.x, see [Migrating from 2.x to 3.0](migrating-2-to-3.md).

### Pre-built binaries

The [releases page](https://github.com/linux-nvme/nvme-cli/releases) has a
static Linux binary (x86_64) and a Windows binary for each release since
3.2. The `nightly` pre-release has a static Linux binary of the latest
`master`. These binaries are useful to test a new version without an
installation. See [Building from
Source](building.md#pre-built-static-binaries).

### Build from source

See [Building from Source](building.md).

## First commands

Most commands need root.

List the NVMe devices:

```
# nvme list
Node                  Generic               SN                   Model     Namespace  Usage                      Format           FW Rev
--------------------- --------------------- -------------------- --------- ---------- -------------------------- ---------------- --------
/dev/nvme0n1          /dev/ng0n1            35efdb862d80bcb0fa47 Linux     0x1        268.44  MB / 268.44  MB      4 KiB +  0 B   6.19.10+
```

- `/dev/nvme0` is the controller.
- `/dev/nvme0n1` is namespace 1 of the controller, a block device.
- `/dev/ng0n1` is the generic character device of the same namespace.

Show the Identify Controller data and the SMART log:

```bash
nvme id ctrl /dev/nvme0
nvme log smart /dev/nvme0
```

Show the subsystems and their controllers:

```bash
nvme list-subsys
```

### Command names in nvme-cli 3.x

nvme-cli 3.0 grouped many commands. The old names still work, but they print a
warning:

| nvme-cli 3.x | nvme-cli 2.x |
|---|---|
| `nvme id ctrl` | `nvme id-ctrl` |
| `nvme id ns` | `nvme id-ns` |
| `nvme log smart` | `nvme smart-log` |
| `nvme log error` | `nvme error-log` |
| `nvme ns create` | `nvme create-ns` |
| `nvme fw download` | `nvme fw-download` |

```
WARNING: 'smart-log' is deprecated and will be removed in the next major version, use 'nvme log smart' instead
```

See [Migrating from 2.x to 3.0](migrating-2-to-3.md) for the full list.

### Get help

```bash
nvme help                   # all commands
nvme log --help             # the commands of a group
nvme log smart --help       # the options of a command
man nvme-log-smart          # the man page, if installed
```

Since nvme-cli 3.2, `nvme help <command>` finds the command like `nvme
<command>` does, and opens its man page.

## Windows and FreeBSD

nvme-cli has fewer features on Windows and FreeBSD than on Linux:

| Feature | Linux | Windows | FreeBSD |
|---|---|---|---|
| PCIe devices | yes | yes | yes, through `nvme(4)` |
| NVMe-oF (fabrics) | yes | no | no |
| NVMe-MI | yes | no | no |
| nvme-discoverd | yes | no | no |
| `nvme top` | yes | no | no |

On Windows, a namespace is a physical drive, for example
`\\.\PhysicalDrive1`. Run `nvme list` to see the names.

## Next steps

- [How to connect to a target](connect.md), for NVMe over
  Fabrics
- [Using nvme-cli in scripts](scripting.md)
- [How to securely erase an NVMe device](secure-erase.md)
- [Troubleshooting](troubleshooting.md) and the [FAQ](faq.md)
