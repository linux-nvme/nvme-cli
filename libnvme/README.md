<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# libnvme

![PyBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/libnvme-release-python.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/libnvme)](https://pypi.org/project/libnvme/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/libnvme)](https://pypi.org/project/libnvme/)
[![codecov](https://codecov.io/gh/linux-nvme/nvme-cli/branch/master/graph/badge.svg)](https://codecov.io/gh/linux-nvme/nvme-cli)
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

The CI build helper script `scripts/build.sh` is able to setup and build this
project in a minimal setup using samurai and muon and thus only depending on:
- gcc
- make
- git

`scripts/build.sh -m muon`

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
| liburing    | auto, enabled, [disabled] | Enables liburing dependent features (e.g. get log page by uring cmd), adds build depdency on liburing, very questionable feature. Don't enable it |

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

This option adds `-fsanitize=address` to the gcc options. The tests can then be run normally (`meson test -C .build`).

Note that when using the sanitize feature, the library `libasan.so` must be available and must be the very first library loaded when running an executable. If experiencing linking issues, you can ensure that `libasan.so` gets loaded first with the `LD_PRELOAD` environment variable as follows:

```
meson setup .build -Db_sanitize=address && LD_PRELOAD=/lib64/libasan.so.6 ninja -C .build test
```

It's also possible to enable the undefined behavior sanitizer with `-Db_sanitize=undefined`. To enable both, use `-Db_sanitize=address,undefined`.

## Accessor generation

Some public structs in libnvme use auto-generated setter/getter accessor
functions to provide ABI stability. Callers never access struct members
directly; they use the generated accessors instead. The generated files are
committed to the source tree and are **not** regenerated during a normal build.

Two sets of accessors are maintained — one for common NVMe structs and one for
NVMe-oF-specific structs. The split exists so that non-fabrics (e.g. embedded
or PCIe-only) builds can exclude all fabrics code entirely.

| Meson target | Input header | Generated files |
|---|---|---|
| `update-common-accessors` | `src/nvme/private.h` | `src/nvme/accessors.{h,c}`, `src/accessors.ld` |
| `update-fabrics-accessors` | `src/nvme/private-fabrics.h` | `src/nvme/nvmf-accessors.{h,c}`, `src/nvmf-accessors.ld` |

### When to regenerate

Regeneration is needed whenever a `/*!generate-accessors*/` struct in
`private.h` or `private-fabrics.h` has a member added, removed, or renamed.

### How to regenerate

To regenerate both sets at once:

```bash
meson compile -C .build update-accessors
```

Or regenerate only one set:

```bash
meson compile -C .build update-common-accessors
meson compile -C .build update-fabrics-accessors
```

The script atomically updates the `.h` and `.c` files when their content
changes. Commit the updated files afterward:

```bash
git add libnvme/src/nvme/accessors.h libnvme/src/nvme/accessors.c
git add libnvme/src/nvme/nvmf-accessors.h libnvme/src/nvme/nvmf-accessors.c
git commit -m "libnvme: regenerate accessors following <struct> changes"
```

### Maintaining the .ld version-script files

The `.ld` files (`src/accessors.ld` and `src/nvmf-accessors.ld`) are GNU
linker version scripts that control which accessor symbols are exported from
the shared library and under which ABI version label they were introduced
(e.g. `LIBNVME_ACCESSORS_3`, `LIBNVMF_ACCESSORS_3`).

These files are **not** updated automatically, because each new symbol must be
placed in the correct version section by the maintainer. Adding a symbol to an
already-published version section would break binary compatibility for
existing users of the library.

When the generator detects that the symbol list has drifted, it prints a
report like the following:

```
WARNING: accessors.ld needs manual attention.

  Symbols to ADD (new version section, e.g. LIBNVME_ACCESSORS_X_Y):
    libnvme_ctrl_get_new_field
    libnvme_ctrl_set_new_field
```

New symbols must be added to a **new** version section that chains the
previous one. For example, if the current latest section is
`LIBNVME_ACCESSORS_3`, add:

```
LIBNVME_ACCESSORS_4 {
    global:
        libnvme_ctrl_get_new_field;
        libnvme_ctrl_set_new_field;
} LIBNVME_ACCESSORS_3;
```

Then commit the updated `.ld` file together with the regenerated source files.
