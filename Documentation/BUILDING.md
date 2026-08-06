<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Building nvme-cli and libnvme

nvme-cli uses meson as its build system. There is more than one way to configure and
build the project to accommodate environments with an older version of meson.

A minimal build requires:
- gcc (or clang)
- ninja
- meson

If you build on a relatively modern system, either use meson directly or the
Makefile wrapper.

Older distros may ship an outdated version of meson. In this case, it's possible
to build the project using [samurai](https://github.com/michaelforney/samurai)
and [muon](https://github.com/annacrombie/muon). Both build tools have only a
minimal dependency on the build environment. To ease this step, there is a build
script which helps to setup a build environment.

## Building on Windows

nvme-cli can be built on Windows using the [msys2](https://www.msys2.org/)
UCRT64 environment. After installing MSYS2 (`winget install MSYS2.MSYS2`), the
`win-ucrt64-setup.sh` script can be run within the UCRT64 environment to install
the required build system and nvme-cli dependencies.

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

| Option | Default | Feature unlocked |
|--------|---------|-----------------|
| `json-c` | `auto` | `/etc/nvme/config.json` parsing; all vendor plugins; JSON output format |
| `openssl` | `auto` | TLS over NVMe-TCP; host authentication |
| `keyutils` | `auto` | Key management for NVMe-oF authentication |
| `libdbus` | `disabled` | End-point discovery for NVMe-MI |
| `liburing` | `disabled` | Get-log-page via io_uring passthrough |
| `python` | `auto` | Python bindings for libnvme |

Example: explicitly disable Python bindings:

```shell
$ meson setup .build -Dpython=disabled
```

Options specific to nvme-cli are defined in [`meson_options.txt`](../meson_options.txt).
To see the full list of available options, including meson built-ins:

```shell
$ meson configure .build
```

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

### Building

```shell
$ meson compile -C .build
```

### Installing

```shell
# meson install -C .build
```

To build a static library instead of a shared one:

```shell
$ meson setup --default-library=static .build
```

### Running unit tests

```shell
$ meson test -C .build
```

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

## Distro packaging

nvme-cli is available on many popular distributions (Alpine, Arch, Debian, Fedora,
FreeBSD, Gentoo, Ubuntu, Nix(OS), openSUSE, ...) and the usual package name is
nvme-cli.

### OpenEmbedded/Yocto

An [nvme-cli recipe](https://layers.openembedded.org/layerindex/recipe/88631/)
is available as part of the `meta-openembedded` layer collection.

### Buildroot

`nvme-cli` is available as a [buildroot](https://buildroot.org) package. The
package is named `nvme`.

## Kernel requirement

libnvme depends on the `/sys/class/nvme-subsystem` interface which was
introduced in Linux kernel v4.15. nvme-cli requires kernel v4.15 or later.
