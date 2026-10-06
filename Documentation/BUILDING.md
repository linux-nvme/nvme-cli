<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Building nvme-cli and libnvme

nvme-cli uses meson as its build system. There is more than one way to configure and
build the project to accommodate environments with an older version of meson.

A minimal build requires:
- gcc (or clang)
- ninja
- meson 1.0.0 or later

If you build on a relatively modern system, either use meson directly or the
Makefile wrapper.

Older distros may ship an outdated version of meson. In this case, it's possible
to build the project using [samurai](https://github.com/michaelforney/samurai)
and [muon](https://github.com/annacrombie/muon). Both build tools have only a
minimal dependency on the build environment. To ease this step, there is a build
script which helps to setup a build environment.

## nvme-cli dependencies (3.x and later)

Starting with nvme-cli 3.x, the libnvme library is fully integrated into the
nvme-cli source tree. There is no longer any dependency on an external libnvme
repository or package. All required libnvme and libnvme-mi code is included and
built as part of nvme-cli.

| Library | Dependency | Notes |
|---------|------------|-------|
| libnvme, libnvme-mi | integrated | No external dependency, included in nvme-cli |
| json-c | optional | Recommended; without it, all plugins are disabled and json-c output format is disabled |
| libkmod | optional | Without it, nvme-cli won't be able to load the nvme-fabrics module when needed |

## Optional feature dependencies

The following optional libraries unlock additional features. Each can be
explicitly enabled (`-Doption=enabled`) or disabled (`-Doption=disabled`);
the default is `auto` (use if found) unless noted otherwise.

| Option | Default | Minimum version | Feature unlocked |
|--------|---------|-----------------|-----------------|
| `json-c` | `auto` | 0.13 | `/etc/nvme/config.json` parsing; all vendor plugins; JSON output format |
| `openssl` | `auto` | 3.0 | TLS over NVMe-TCP; host authentication. LibreSSL works if it provides `openssl/core_names.h` |
| `keyutils` | `auto` | 1.5 | Key management for NVMe-oF authentication |
| `libkmod` | `auto` | 5 | Loading the nvme-fabrics module when needed |
| `libdbus` | `disabled` | | End-point discovery for NVMe-MI |
| `liburing` | `disabled` | 2.2 | Asynchronous admin and I/O passthrough commands through io_uring |
| `libarchive` | `auto` | | Archiving vendor plugin log captures (WDC, SanDisk, Micron, Samsung, Solidigm) as `.tar`/`.tar.gz`/`.zip`, without spawning an external `tar`/`zip` process. Without it, those capture subcommands fail with a clear error instead |
| `python` | `auto` | 3.6 | Python bindings for libnvme |
| `nvme-discoverd` | `auto` | libsystemd 253 | The nvme-discoverd daemon; see [Daemons and systemd](#daemons-and-systemd) |
| `mdns` | `auto` | libsystemd 258 | mDNS discovery in nvme-discoverd; see [Daemons and systemd](#daemons-and-systemd) |
| `nvme-keysd` | `disabled` | libsystemd 257, OpenSSL, libkeyutils | The nvme-keysd daemon; see [Daemons and systemd](#daemons-and-systemd) |

nvme-cli calls `printbuf_memappend()` in a serializer installed with
`json_object_set_serializer()` (`src/nvme-json.c`). json-c's `printbuf.h`
allows this use, but json-c exports the function under its private symbol
version, `JSONC_PRIVATE`. json-c therefore does not promise that its ABI
stays stable.

Example: explicitly disable Python bindings:

```shell
$ meson setup .build -Dpython=disabled
```

Options specific to nvme-cli are defined in [`meson_options.txt`](../meson_options.txt).
To see the full list of available options, including meson built-ins:

```shell
$ meson configure .build
```

## Daemons and systemd

The daemons need systemd both at build time (libsystemd) and at run time
(the service manager and other systemd services). The minimum version is
the same for both.

| Feature | Minimum systemd version | Reason |
|---------|-------------------------|--------|
| nvme-discoverd | 253 | `Type=notify-reload` |
| mDNS in nvme-discoverd | 258 | The `BrowseServices` method of systemd-resolved |
| nvme-keysd | 257 | The `io.systemd.Credentials.Decrypt` Varlink method |

At startup, nvme-discoverd checks that systemd-resolved provides
`BrowseServices`. If it does not, the daemon logs a warning and runs
without mDNS.

## Kernel requirement

libnvme depends on the `/sys/class/nvme-subsystem` interface which was
introduced in Linux kernel v4.15. nvme-cli requires kernel v4.15 or later.

## Build with meson

### Configuring

No special configuration is required for libnvme, as it is now part of the
nvme-cli source tree. Simply run:

```shell
$ meson setup .build
```

With meson's `--wrap-mode` argument it's possible to control if additional
dependencies should be resolved. The options are:

```
--wrap-mode {default,nofallback,nodownload,forcefallback,nopromote}
```

Note for nvme-cli the 'default' is set to nofallback.

### Installation paths

By default, meson installs everything under `/usr/local` (executables in
`/usr/local/bin`, libraries in `/usr/local/lib`, configuration in
`/usr/local/etc`, etc.). This is controlled by two meson built-in options
whose defaults are set in `meson.build`:

| Option | Default |
|--------|---------|
| `--prefix` | `/usr/local` |
| `--sysconfdir` | `etc` (relative to prefix → `/usr/local/etc`) |

To install into the standard system locations that a Linux distribution would
use (`/usr/bin`, `/usr/lib`, `/etc`, …), pass these options at configure time:

```shell
$ meson setup .build --prefix /usr --sysconfdir /etc
```

Optionally add `--buildtype release` to disable debug symbols and enable
optimizations for a production install:

```shell
$ meson setup .build --prefix /usr --sysconfdir /etc --buildtype release
```

### Building

```shell
$ meson compile -C .build
```

### Running unit tests

```shell
$ meson test -C .build
```

### Installing

```shell
# meson install -C .build
```

To install only some groups of files, see [Install tags](#install-tags).

To build a static library instead of a shared one:

```shell
$ meson setup --default-library=static .build
```

### Debug and sanitizer builds

To configure a build for debugging (optimizations off, debug symbols on):

```shell
$ meson setup .build --buildtype=debug
```

To enable address sanitizer (detects memory errors at runtime):

```shell
$ meson setup .build -Db_sanitize=address
```

When using the sanitizer, `libasan.so` must be preloaded if you encounter
linking issues:

```shell
$ meson setup .build -Db_sanitize=address && \
  LD_PRELOAD=/lib64/libasan.so.6 ninja -C .build test
```

The undefined behavior sanitizer is also supported: `-Db_sanitize=undefined`.
To enable both: `-Db_sanitize=address,undefined`.

## Build with build.sh wrapper

The `scripts/build.sh` is used for the CI build but can also be used for
configuring and building the project.

Running `scripts/build.sh` without any argument builds the project in the
default configuration (meson, gcc and defaults)

It's possible to change the compiler to clang

```shell
scripts/build.sh -c clang
```

or enable all the fallbacks

```shell
scripts/build.sh fallback
```

## Minimal static build with muon

`scripts/build.sh -m muon` will download and build `samurai` and `muon` instead
of using `meson` to build the project. This reduces the dependency on the build
environment to:
- gcc
- make
- git

Furthermore, this configuration will produce a static binary.

## Build with Makefile wrapper

There is a Makefile wrapper for meson for backwards compatibility

```shell
$ make
# make install
```

Note: In previous versions, libnvme needed to be installed by hand.
This is no longer required in nvme-cli 3.x and later.

RPM build support via Makefile that uses meson

```shell
$ make rpm
```

Static binary (no dependency) build support via Makefile that uses meson

```shell
$ make static
```

If you are not sure how to use it, find the top-level documentation with:

```shell
$ man nvme
```

Or find a short summary with:

```shell
$ nvme help
```

## Building with specific plugins

By default, all vendor plugins are built. To build only specific plugins, use the `plugins` option:

```shell
$ meson setup .build -Dplugins=intel,wdc,ocp
$ meson compile -C .build
```

Or with the Makefile wrapper:

```shell
$ make PLUGINS="intel,wdc,ocp"
```

When `PLUGINS` is not used, the value defaults to `all`, which selects all plugins:

```shell
$ make PLUGINS="all"
```

To build without any vendor plugins:

```shell
$ make PLUGINS=""
```

## Building on Windows

nvme-cli can be built on Windows using the [msys2](https://www.msys2.org/)
UCRT64 environment. After installing MSYS2 (`winget install MSYS2.MSYS2`), the
`win-ucrt64-setup.sh` script can be run within the UCRT64 environment to install
the required build system and nvme-cli dependencies.

## Distro packaging

nvme-cli is available on many popular distributions (Alpine, Arch, Debian, Fedora,
FreeBSD, Gentoo, Ubuntu, Nix(OS), openSUSE, ...) and the usual package name is
nvme-cli.

### Install tags

Every installed file has a meson install tag. A distribution can build
everything once and then install each group of files into its own package
with `meson install --tags`.

| Tag | Files |
|-----|-------|
| `runtime` | `nvme`, the libnvme shared library, shell completions |
| `devel` | libnvme headers, `libnvme3.so` link, pkg-config file |
| `python-runtime` | libnvme Python bindings |
| `man` | man pages |
| `doc` | HTML and reST documentation |
| `nvmf` | NVMe-oF files needed with the legacy autoconnect and with nvme-discoverd: registry and vendor udev rules, NBFT interface naming rule, `nvme-fabrics.conf.sample` |
| `nvmf-autoconnect` | legacy NVMe-oF autoconnect: udev rules, systemd units, dracut config, NetworkManager dispatcher script |
| `nvme-discoverd` | nvme-discoverd: binary, systemd unit, config file |
| `nvme-keysd` | nvme-keysd: binary, systemd unit, config file, credential directory |

A file can have only one tag. Some NVMe-oF files are needed with the
legacy autoconnect and with nvme-discoverd. They have their own tag
(`nvmf`), and both packages list it.

Example: one build, separate packages.

```shell
$ meson setup .build --prefix /usr --sysconfdir /etc --buildtype release \
      -Dnvme-discoverd=enabled -Dnvme-keysd=enabled -Ddocs=man
$ meson compile -C .build
$ meson install -C .build --destdir pkg/nvme-cli \
      --tags runtime,man,nvmf,nvme-discoverd
$ meson install -C .build --destdir pkg/nvme-keysd --tags nvme-keysd
$ meson install -C .build --destdir pkg/libnvme-dev --tags devel
$ meson install -C .build --destdir pkg/python3-libnvme --tags python-runtime
```

The legacy autoconnect files are built only with
`-Dnvmf-autoconnect=enabled` when nvme-discoverd is also built. A package
that uses the legacy autoconnect instead of nvme-discoverd uses
`--tags runtime,man,nvmf,nvmf-autoconnect`.

Without `--tags`, `meson install` installs all files. The
`nvme-cli - install-tags` test fails if an installed file has no tag.
Meson tags executables `runtime` by itself. So the test does not catch a
new executable that belongs to another group. Set its `install_tag`.

### OpenEmbedded/Yocto

An [nvme-cli recipe](https://layers.openembedded.org/layerindex/recipe/88631/)
is available as part of the `meta-openembedded` layer collection.

### Buildroot

`nvme-cli` is available as a [buildroot](https://buildroot.org) package. The
package is named `nvme`.
