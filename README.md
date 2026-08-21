<!-- SPDX-License-Identifier: GPL-2.0-only -->
# nvme-cli and libnvme

NVM-Express user space tooling for Linux: the `nvme` command line tool and
the `libnvme` library it's built on, including NVMe-oF fabrics support and
vendor plugins.

For more information on the NVM Express standard, see https://nvmexpress.org.

Subscribe to linux-nvme@lists.infradead.org for Linux NVMe discussions and
development. The list is archived at
https://lists.infradead.org/mailman/listinfo/linux-nvme

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

## Reports

- **Static analysis**
  - [[clang-analyzer]](https://monom.org/linux-nvme/clang-analyze/current/)
  - [![Coverity Scan Build Status](https://scan.coverity.com/projects/24883/badge.svg)](https://scan.coverity.com/projects/linux-nvme-nvme-cli)
- **Test coverage**
  - [![codecov](https://codecov.io/gh/linux-nvme/nvme-cli/branch/master/graph/badge.svg)](https://codecov.io/gh/linux-nvme/nvme-cli)

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
| Building from source: dependencies, alternative build systems, packaging, plugin selection | [Documentation/BUILDING.md](Documentation/BUILDING.md) |
| Configuring host identity, NVMe-oF connections, and multi-orchestrator coordination | [Documentation/CONFIGURATION.md](Documentation/CONFIGURATION.md) |
| Pre-built binaries, reproducing CI builds, memory/sanitizer testing | [Documentation/TESTING.md](Documentation/TESTING.md) |
| libnvme coverage against NVMe specifications, chapter by chapter | [Documentation/SPEC-COVERAGE.md](Documentation/SPEC-COVERAGE.md) |
| Command/plugin man pages | `man nvme`, or browse [Documentation/](Documentation/) |
| Contributing: adding commands/plugins, API naming, commit & PR workflow | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Reporting security vulnerabilities | [SECURITY.md](SECURITY.md) |
| Release history | [NEWS.md](NEWS.md) |

AI-assisted development resources live in the companion repository
[nvme-cli-ai](https://github.com/linux-nvme/nvme-cli-ai); see
[CONTRIBUTING.md](CONTRIBUTING.md) for how they fit into the workflow.
