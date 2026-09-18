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
| Build | [![MesonBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/build.yml/badge.svg)](https://github.com/linux-nvme/nvme-cli/actions/workflows/build.yml) |  | [![PyBuild](https://github.com/linux-nvme/nvme-cli/actions/workflows/libnvme-release-python.yml/badge.svg)](https://github.com/linux-nvme/nvme-cli/actions/workflows/libnvme-release-python.yml) |
| Static analysis | [![Coverity Scan Build Status](https://scan.coverity.com/projects/24883/badge.svg)](https://scan.coverity.com/projects/linux-nvme-nvme-cli) [![clang-analyzer](https://img.shields.io/badge/clang--analyzer-report-blue)](https://monom.org/linux-nvme/clang-analyze/current/) |  |  |
| Test coverage | [![codecov](https://codecov.io/gh/linux-nvme/nvme-cli/branch/master/graph/badge.svg)](https://codecov.io/gh/linux-nvme/nvme-cli) |  |  |
| Docs |  | [![nvme-cli Docs](https://img.shields.io/readthedocs/nvme-cli?label=docs)](https://nvme-cli.readthedocs.io/en/latest/) | [![libnvme Docs](https://img.shields.io/readthedocs/libnvme?label=docs)](https://libnvme.readthedocs.io/en/latest/) |
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

| Topic | Where |
|---|---|
| Building from source: dependencies, alternative build systems, packaging, plugin selection | [BUILDING.md](Documentation/BUILDING.md) |
| Configuring host identity, NVMe-oF connections, and multi-orchestrator coordination | [CONFIGURATION.md](Documentation/CONFIGURATION.md) |
| Pre-built binaries, reproducing CI builds, memory/sanitizer testing | [TESTING.md](Documentation/TESTING.md) |
| libnvme coverage against NVMe specifications, chapter by chapter | [SPEC-COVERAGE.md](Documentation/SPEC-COVERAGE.md) |
| Command/plugin man pages | `man nvme`, or browse [Documentation](Documentation/) |
| Contributing: adding commands/plugins, API naming, commit & PR workflow | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Reporting security vulnerabilities | [SECURITY.md](SECURITY.md) |
| Release history | [NEWS.md](NEWS.md) |

AI-assisted development resources live in the companion repository
[nvme-cli-ai](https://github.com/linux-nvme/nvme-cli-ai); see
[CONTRIBUTING.md](CONTRIBUTING.md) for how they fit into the workflow.
