# libnvme

This is the libnvme development C library. libnvme provides type
defintions for NVMe specification structures, enumerations, and bit
fields, helper functions to construct, dispatch, and decode commands
and payloads, and utilities to connect, scan, and manage nvme devices
on a Linux system.

The public specification is the authority to resolve any protocol
discrepencies with this library. For more info on NVM Express, please
see:

  http://nvmexpress.org

Subscribe to linux-nvme@lists.infradead.org for linux-nvme related
discussions and development for both kernel and userspace. The list is
archived here:

  http://lists.infradead.org/mailman/listinfo/linux-nvme

# License

Except where otherwise stated, all software contained within this repo
is currently licensed LGPL, see COPYING for more information.

Keith Busch 2020-02-06

------

# Building with meson

## What is the meson build system?

Here's an excerpt from the meson web site: *Meson is **an open source
build system** meant to be both extremely fast, and, even more
importantly, as user friendly as possible. The main design point of
Meson is that every moment a developer spends writing or debugging
build definitions is a second wasted.*

Several well-known projects such as `systemd` and `Gnome` use meson as
their build system. A summary of projects using meson can be found
[here](https://mesonbuild.com/Users.html). For more info on meson,
please consult the following sites:

**Wiki page**: https://en.wikipedia.org/wiki/Meson_(software)

**meson documentation**: https://mesonbuild.com/

**meson repo**: https://github.com/mesonbuild/meson

## Prerequisite

First, install meson.

**Debian / Ubuntu**:

```bash
sudo apt-get install meson
```

**Fedora / Red Hat**:

```bash
sudo dnf install meson
```

## To compile libnvme

Using meson is similar to projects that use a `configure` script before running `make`.

To `configure` the project:

```
meson .build
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
cd .build
ninja
```

Or:

```
ninja -C .build
```

## To install libnvme

To install `libnvme`:

```
cd .build
meson install
```

## To run unit tests

To run unit tests:

```
cd .build
meson test
```

## To clean after a build

To perform the equivalent of a `make clean` without deleting the build configuration.

```
cd .build
ninja -t clean
```

Or:

```
ninja -C .build -t clean
```

## To purge everything

To completely clean all build artifacts, including the build configuration.

```
rm -rf .build
```

## Supported build options

A few build options can be specified on the command line when invoking meson.

| Option | Values [default]    | Description                                                  |
| ------ | ------------------- | ------------------------------------------------------------ |
| man    | true, [false]       | Instruct meson to configure the project to build the `libnvme` documentation. <br />Example: `meson .build -Dman=true` |
| python | [auto], true, false | Whether to build the Python bindings. When set to `auto`, the default, meson will check for the presence of the  tools and libraries (e.g. `swig`) required to build the Python bindings. If found, meson will configure the project to build the Python bindings. If a tool or library is missing, then the Python bindings won't be built. Setting this to `true`, forces the Python bindings to be built. When set to `false`, meson will configure the project to not build the Python bindings.<br />Example: `meson .build -Dpython=false` |

### Changing the build options from the command-line (i.e. w/o modifying any files)

To configure a build for debugging purposes (i.e. optimization turned
off and debug symbols enabled):

```bash
meson .build -Dbuildtype=debug
```

To enable address sanitizer (advanced debugging of memory issues):

```bash
meson .build -Db_sanitize=address
```

This option adds `-fsanitize=address` to the gcc options. Note that when using the sanitize feature, the library `libasan.so` must be available and must be the very first library loaded when running an executable. Ensuring that `libasan.so` gets loaded first can be achieved with the `LD_PRELOAD` environment variable as follows: 

```
meson .build -Db_sanitize=address && LD_PRELOAD=/lib64/libasan.so.6 ninja -C .build test 
```

To list configuration options that are available and possible values:

```bash
meson configure .build
```

