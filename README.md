# libnvme

![MesonBuild](https://github.com/linux-nvme/libnvme/actions/workflows/meson.yml/badge.svg)
![PyBuild](https://github.com/linux-nvme/libnvme/actions/workflows/python-publish.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/libnvme)](https://pypi.org/project/libnvme/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/libnvme)](https://pypi.org/project/libnvme/)
![GitHub](https://img.shields.io/github/license/linux-nvme/libnvme)
[![codecov](https://codecov.io/gh/linux-nvme/libnvme/branch/master/graph/badge.svg)](https://codecov.io/gh/linux-nvme/libnvme)
[![Read the Docs](https://img.shields.io/readthedocs/libnvme)](https://libnvme.readthedocs.io/en/latest/)

This is the libnvme development C library. libnvme provides type
definitions for NVMe specification structures, enumerations, and bit
fields, helper functions to construct, dispatch, and decode commands
and payloads, and utilities to connect, scan, and manage nvme devices
on a Linux system.

The public specification is the authority to resolve any protocol
discrepancies with this library. For more info on NVM Express, please
see:

  https://nvmexpress.org

Subscribe to linux-nvme@lists.infradead.org for linux-nvme related
discussions and development for both kernel and userspace. The list is
archived here:

  https://lists.infradead.org/mailman/listinfo/linux-nvme

# License

Except where otherwise stated, all software contained within this repo
is currently licensed LGPL-2.1-or-later, see COPYING for more
information.

Keith Busch 2020-02-06

------

# Dependency

libnvme depends on minimum Linux kernel version v4.15, which
introduced the /sys/class/nvme-subsystem.

# Build from source
## Prerequisite

A minimal build depends on a set of build tools

  - gcc
  - ninja
  - meson

Not all feature will be present with such configuration, e.g.
the fabrics part of the library wont support authentication or
TLS over the nvme-tcp transport.

To enable the optional features install following libraries

`/etc/nvme/config.json`` support:
  - json-c (recommend)

Authentication and TLS over nvme-tcp:
  - openssl
  - keyutils

End point discovery for MI
  - libdbus

Python bindings
  - Python 3 interpreter
  - Python 3 development libraries

## Minimal on embedded builds

The reference implemention of the Meson specification is in Python 3. Installing
or porting this dependency is not really feasible for embedded project. Though
there are two project which implement the Ninja and the Meson API in pure C99

  - samurai: https://github.com/michaelforney/samurai.git
  - muon: https://git.sr.ht/~lattis/muon

See the CI [build](.github/workflows/build.yml) for an example how to use it.

## To compile libnvme

To `configure` the project:

```
meson setup .build
```

Which will default to build a shared library. To configure for static libraries call

```
meson setup --default-library=static .build
```

One nice feature of meson is that it doesn't mix build artifacts
(e.g. `*.o`, `*.so`, etc.) with source code. In the above example,
"`.build`" is the name of the directory where the build configuration
as well as all the build artifacts will be saved. This directory can
be named anything as long as it's not an existing source directory. To
completely "clean" all the build artifacts, one need only delete the
`.build` directory.

To compile:

```
meson compile -C .build
```

## To install libnvme

To install `libnvme`:

```
meson install -C .build
```

## To run unit tests

To run unit tests:

```
meson test -C .build
```

## To purge everything

To completely clean all build artifacts, including the build configuration.

```
rm -rf .build
```

## Supported build options

A few build options can be specified on the command line when invoking meson.

| Option      | Values [default]          | Description                                                  |
| ----------- | ------------------------- | ------------------------------------------------------------ |
| version-tag | none                      | Overwrite the git version string in the binary               |
| htmldir     | none                      | Installation directory for the HTML documentation            |
| rstdir      | none                      | Installation directory for the RST documentation             |
| docs        | [false], html, man, rst, all | Install documentation                                     |
| docs-build  | [false], true             | Enable build documentation                                   |
| python | [auto], enabled, disabled | Whether to build the Python bindings. When set to `auto`, the default, meson will check for the presence of the  tools and libraries (e.g. `swig`) required to build the Python bindings. If found, meson will configure the project to build the Python bindings. If a tool or library is missing, then the Python bindings won't be built. Setting this to `enabled`, forces the Python bindings to be built. When set to `disabled`, meson will configure the project to not build the Python bindings.<br />Example: `meson setup .build -Dpython=disabled` |
| openssl     | [auto], enabled, disabled | Enables OpenSSL dependent features (e.g. TLS over TCP), adds build dependency on OpenSSL |
| libdbus     | auto, enabled, [disabled] | Enables D-Bus dependent features (libnvme-mi: End point discovery), adds build dependency on libdbus |
| json-c      | [auto], enabled, disabled | (recommended) Enables JSON-C dependend features (e.g. config.json parsing), adds build depdency on json-c |
| keyutils    | [auto], enabled, disabled | Enables keyutils dependent features (e.g. authentication), adds build dependency on keyutils |

See the full configuration options with

```bash
meson configure .build
```

### Changing the build options from the command-line (i.e. w/o modifying any files)

To configure a build for debugging purposes (i.e. optimization turned
off and debug symbols enabled):

```bash
meson setup .build --buildtype=debug
```

To enable address sanitizer (advanced debugging of memory issues):

```bash
meson setup .build -Db_sanitize=address
```

This option adds `-fsanitize=address` to the gcc options. Note that when using the sanitize feature, the library `libasan.so` must be available and must be the very first library loaded when running an executable. Ensuring that `libasan.so` gets loaded first can be achieved with the `LD_PRELOAD` environment variable as follows: 

```
meson setup .build -Db_sanitize=address && LD_PRELOAD=/lib64/libasan.so.6 ninja -C .build test
```
