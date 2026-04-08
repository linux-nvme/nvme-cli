<!-- SPDX-License-Identifier: GPL-2.0-only -->
# nvme-cli and libnvme

NVM-Express user space tooling for Linux.

For more information on the NVM Express standard, see https://nvmexpress.org.

Subscribe to linux-nvme@lists.infradead.org for Linux NVMe discussions and
development. The list is archived at
https://lists.infradead.org/mailman/listinfo/linux-nvme

[![Coverity Scan Build Status](https://scan.coverity.com/projects/24883/badge.svg)](https://scan.coverity.com/projects/linux-nvme-nvme-cli)
[![codecov](https://codecov.io/gh/linux-nvme/nvme-cli/branch/master/graph/badge.svg)](https://codecov.io/gh/linux-nvme/nvme-cli)
![MesonBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/build.yml/badge.svg)

nvme-cli:
![GitHub](https://img.shields.io/github/license/linux-nvme/nvme-cli)
[![Docs](https://img.shields.io/readthedocs/nvme-cli)](https://nvme-cli.readthedocs.io/en/latest/)

libnvme:
![GitHub](https://img.shields.io/github/license/linux-nvme/libnvme)
[![Docs](https://img.shields.io/readthedocs/libnvme)](https://libnvme.readthedocs.io/en/latest/)
![PyBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/libnvme-release-python.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/libnvme)](https://pypi.org/project/libnvme/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/libnvme)](https://pypi.org/project/libnvme/)

## Build from source

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

### nvme-cli dependencies (3.x and later):

Starting with nvme-cli 3.x, the libnvme library is fully integrated into the
nvme-cli source tree. There is no longer any dependency on an external libnvme
repository or package. All required libnvme and libnvme-mi code is included and
built as part of nvme-cli.

| Library | Dependency | Notes |
|---------|------------|-------|
| libnvme, libnvme-mi | integrated | No external dependency, included in nvme-cli |
| json-c | optional | Recommended; without it, all plugins are disabled and json-c output format is disabled |
| libkmod | optional | Without it, nvme-cli won't be able to load the nvme-fabrics module when needed |

### Optional feature dependencies

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

Options specific to nvme-cli are defined in [`meson_options.txt`](meson_options.txt). 
To see the full list of available options, including meson built-ins:

```shell
$ meson configure .build
```

### Build with meson

#### Configuring

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

#### Building

```shell
$ meson compile -C .build
```

#### Installing

```shell
# meson install -C .build
```

To build a static library instead of a shared one:

```shell
$ meson setup --default-library=static .build
```

#### Running unit tests

```shell
$ meson test -C .build
```

#### Installation paths

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

#### Debug and sanitizer builds

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

### Build with build.sh wrapper

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

### Minimal static build with muon

`scripts/build.sh -m muon` will download and build `samurai` and `muon` instead
of using `meson` to build the project. This reduces the dependency on the build
environment to:
- gcc
- make
- git

Furthermore, this configuration will produce a static binary.

### Build with Makefile wrapper

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

### Building with specific plugins

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

## Distro Support

It is available on many popular distributions (Alpine, Arch, Debian, Fedora,
FreeBSD, Gentoo, Ubuntu, Nix(OS), openSUSE, ...) and the usual package name is
nvme-cli.

### OpenEmbedded/Yocto

An [nvme-cli recipe](https://layers.openembedded.org/layerindex/recipe/88631/)
is available as part of the `meta-openembedded` layer collection.

### Buildroot

`nvme-cli` is available as a [buildroot](https://buildroot.org) package. The
package is named `nvme`.

## Dependency

libnvme depends on the `/sys/class/nvme-subsystem` interface which was
introduced in Linux kernel v4.15. nvme-cli requires kernel v4.15 or later.

## Contributing

For information on adding commands, adding plugins, API naming conventions,
commit guidelines, and the pull request workflow, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Persistent and volatile configuration

Persistent configurations can be stored in two different locations: either in
the file `/etc/nvme/discovery.conf` using the old style, or in the file
`/etc/nvme/config.json` using the new style.

On the other hand, volatile configurations, such as those obtained from
third-party tools like `nvme-stats` or `blktests`, can be stored in the
`/run/nvme` directory. When using the `nvme-cli` tool, all these configurations
are combined into a single configuration that is used as input.

The volatile configuration is particularly useful for coordinating access to the
global resources among various components. For example, when executing
`blktests` for the FC transport, the `nvme-cli` udev rules can be triggered. To
prevent interference with a test, `blktests` can create a JSON configuration
file in `/run/nvme` to inform `nvme-cli` that it should not perform any actions
triggered from the udev context. This behavior can be controlled using the
`--context` argument.

For example, a `blktests` volatile configuration could look like:

```json
[
  {
    "hostnqn": "nqn.2014-08.org.nvmexpress:uuid:242d4a24-2484-4a80-8234-d0169409c5e8",
    "hostid": "242d4a24-2484-4a80-8234-d0169409c5e8",
    "subsystems": [
      {
	"application": "blktests",
        "nqn": "blktests-subsystem-1",
        "ports": [
          {
            "transport": "fc",
	    "traddr": "nn-0x10001100aa000001:pn-0x20001100aa000001",
	    "host_traddr": "nn-0x10001100aa000002:pn-0x20001100aa000002"
          }
        ]
      }
    ]
  }
]
```

Note when updating the volatile configuration during runtime, it should be done
in an atomic way. For example, create a temporary file without the `.json` file
extension in `/run/nvme` and write the contents to this file. When finished, use
`rename` to add the `.json` file name extension. This ensures nvme-cli only
sees the complete file.

## Testing and CI

For pre-built binaries, CI build reproduction, and container-based debugging,
see [TESTING.md](TESTING.md).
