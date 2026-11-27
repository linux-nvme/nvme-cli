<!-- SPDX-License-Identifier: GPL-2.0-only -->
# nvme-cli and libnvme

`nvme-cli` is the command line tool for managing NVMe devices. It is
built on the `libnvme` library. Together they support local NVMe drives,
NVMe-oF fabrics (TCP, RDMA, FC), and many vendor-specific plugins.

For more information on the NVM Express standard, see https://nvmexpress.org.

The project is developed on GitHub at
https://github.com/linux-nvme/nvme-cli.

Subscribe to linux-nvme@lists.infradead.org for Linux NVMe discussions and
development. The list is archived at
https://lists.infradead.org/mailman/listinfo/linux-nvme

| | Shared | nvme-cli | libnvme |
|---|---|---|---|
| Build | [![MesonBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/build.yml/badge.svg)](https://github.com/linux-nvme/nvme-cli/actions/workflows/build.yml) |  | [![PyBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/release-python.yml/badge.svg)](https://github.com/linux-nvme/nvme-cli/actions/workflows/release-python.yml) |
| Static analysis | [![Coverity Scan Build Status](https://scan.coverity.com/projects/24883/badge.svg)](https://scan.coverity.com/projects/linux-nvme-nvme-cli) [![clang-analyzer](https://img.shields.io/badge/clang--analyzer-report-blue)](https://linux-nvme.github.io/nvme-cli/analyzer/) |  |  |
| Nightly tests | [![Nightly](https://github.com/linux-nvme/nvme-cli/actions/workflows/nightly-tests.yml/badge.svg)](https://linux-nvme.github.io/nvme-cli/) |  |  |
| Test coverage | [![codecov](https://codecov.io/gh/linux-nvme/nvme-cli/branch/master/graph/badge.svg)](https://codecov.io/gh/linux-nvme/nvme-cli) |  |  |
| Docs |  | [![nvme-cli Docs](https://img.shields.io/readthedocs/nvme-cli?label=docs)](https://nvme-cli.readthedocs.io/en/stable/) | [![libnvme Docs](https://img.shields.io/readthedocs/libnvme?label=docs)](https://libnvme.readthedocs.io/en/stable/) |
| Package |  |  | [![PyPI](https://img.shields.io/pypi/v/libnvme3)](https://pypi.org/project/libnvme3/) [![PyPI - Wheel](https://img.shields.io/pypi/wheel/libnvme3)](https://pypi.org/project/libnvme3/) |
| License |  | [![nvme-cli License](https://img.shields.io/github/license/linux-nvme/nvme-cli?label=license)](https://github.com/linux-nvme/nvme-cli/blob/master/COPYING) | [![libnvme License](https://img.shields.io/github/license/linux-nvme/libnvme?label=license)](https://github.com/linux-nvme/libnvme/blob/master/COPYING) |

## Quick start

```shell
$ meson setup .build
$ meson compile -C .build
# meson install -C .build
```

It is also packaged by most Linux distributions (Alpine, Arch, Debian,
Fedora, FreeBSD, Gentoo, Ubuntu, Nix(OS), openSUSE, ...) as `nvme-cli`.

Once installed, find the top-level documentation with `man nvme`, or a short
summary with `nvme help`.

## Documentation

The guide at https://nvme-cli.readthedocs.io is the entry point to the
documentation: building, connecting to NVMe-oF targets, security,
troubleshooting, contributing, and the man pages of all commands. Its
sources are in [Documentation/guide](Documentation/guide).

Report security vulnerabilities as [SECURITY.md](SECURITY.md) describes.
[CONTRIBUTING.md](CONTRIBUTING.md) explains how to contribute, including the
AI-assisted development resources in the companion repository
[nvme-cli-ai](https://github.com/linux-nvme/nvme-cli-ai).
