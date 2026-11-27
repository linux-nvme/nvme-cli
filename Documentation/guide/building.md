<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Building nvme-cli

nvme-cli uses meson as its build system. This page covers the common build and
the dependency packages of some distributions. The full reference is
[`Documentation/BUILDING.md`](https://github.com/linux-nvme/nvme-cli/blob/master/Documentation/BUILDING.md)
in the source tree. It covers the install paths, debug and sanitizer builds,
the selection of plugins, the Windows build and distribution packaging.

## Quick start

```shell
$ meson setup .build
$ meson compile -C .build
# meson install -C .build
```

Since nvme-cli 3.x, libnvme is part of the nvme-cli source tree. You do not need
to build or install it separately first, unlike in nvme-cli 2.x.

Since nvme-cli 3.2, nvme-cli also builds and runs on FreeBSD. PCIe devices
work through the nvme(4) driver. NVMe-oF, NVMe-MI, nvme-discoverd and `nvme
top` are not available there yet.

By default this installs under `/usr/local`. To install into the paths a Linux
distribution normally uses instead:

```shell
$ meson setup .build --prefix /usr --sysconfdir /etc
```

## Dependencies

A minimal build needs a C compiler (gcc or clang), ninja, and meson. A few
optional libraries unlock extra features. Each is auto-detected by default; pass
`-D<option>=enabled` or `-D<option>=disabled` to force it:

| Library | Feature it unlocks |
|---|---|
| `json-c` | `config.json` parsing, all vendor plugins, JSON output. Without it, plugins are disabled. |
| `openssl` | TLS over NVMe-TCP, host authentication |
| `keyutils` | Key management for NVMe-oF authentication |
| `libdbus` | NVMe-MI endpoint discovery (disabled by default) |
| `liburing` | Get-log-page via io_uring (disabled by default) |
| `python` | Python bindings for libnvme |
| `libarchive` | Log archives of the WDC, SanDisk, Micron, Samsung and Solidigm plugins (since 3.2). Without it, these subcommands fail with an error. |

For the full option list, including meson's own built-in options, run:

```shell
$ meson configure .build
```

## Building specific plugins

By default every vendor plugin is built. To build only some of them:

```shell
$ meson setup .build -Dplugins=intel,wdc,ocp
```

## Minimal static build with muon

Older distributions may ship a meson version too old for nvme-cli.
[muon](https://git.sr.ht/~lattis/muon) is an implementation of the meson build
system in C99, with far fewer dependencies than meson itself. `scripts/build.sh`
drives it for you:

```shell
$ scripts/build.sh -m muon
```

This needs only:

- make
- gcc
- git

and produces a static binary. It downloads and builds `muon` and
[samurai](https://github.com/michaelforney/samurai) (its `ninja` replacement) as
part of the build.

For some older distributions, additional packages need to be installed first;
see the sections below.

## Pre-built static binaries

You do not have to build nvme-cli yourself to test it. Static x86_64
binaries are available on the
[releases page](https://github.com/linux-nvme/nvme-cli/releases):

- `nightly`: a pre-release with a static Linux build of the latest master
  commit. It is updated on every push to master.
  Direct link:
  [nvme-cli-latest-x86_64](https://github.com/linux-nvme/nvme-cli/releases/download/nightly/nvme-cli-latest-x86_64).
- Since v3.2: each release has a static Linux binary and a Windows binary
  attached.

## Per-distribution setup

### Fedora

```shell
# dnf install json-c-devel openssl-devel keyutils-libs-devel dbus-devel python3-devel
```

### CentOS Stream 9

```shell
$ dnf config-manager --set-enabled powertools
$ dnf search glibc
$ dnf provides */libc.a
$ dnf install glibc-static
```

### Ubuntu 24.04

Dependencies if using meson directly:

```shell
$ sudo apt install gcc make git
$ sudo pip3 install meson
$ sudo apt-get install python3 python3-pip python3-setuptools python3-wheel ninja-build
$ sudo apt install cmake swig libjson-c-dev libssl-dev libkeyutils-dev pkg-config
```

### SUSE Linux Enterprise 15 Service Pack 7

```shell
# zypper install git meson gcc libjson-c-devel keyutils-devel openssl-devel
```

### EOL distributions

These are unsupported for the muon minimal build, but are included here for
reference:

**CentOS 8**

```shell
$ dnf config-manager --set-enabled powertools
$ dnf search glibc
$ dnf provides */libc.a
$ dnf install glibc-static
```

**CentOS 7**

```shell
$ yum install glibc-static
```
