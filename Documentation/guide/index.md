<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# nvme-cli

nvme-cli is the command line tool for managing NVMe devices: local PCIe
drives and NVMe over Fabrics (TCP, RDMA, FC) targets. It is built on the
libnvme library, which is part of the same source tree.

This guide explains how to build, configure and use nvme-cli. The
[man pages](man:nvme) describe every command and option. The
[libnvme documentation](https://libnvme.readthedocs.io/) describes the
library API.

The project is developed at <https://github.com/linux-nvme/nvme-cli>.
Discussions take place on the linux-nvme mailing list,
linux-nvme@lists.infradead.org, archived at
<https://lore.kernel.org/linux-nvme/>.

```{toctree}
:caption: Getting started
:maxdepth: 1

getting-started
building
global-options
scripting
```

```{toctree}
:caption: Connecting to NVMe-oF targets
:maxdepth: 1

connect
fibre-channel
fabrics-config
host-traddr-host-iface
inband-auth
tls
autoconnect
pdc
multipath-ana
discoverd
registry-exclusions
nbft-boot
```

```{toctree}
:caption: Security and encryption
:maxdepth: 1

keys-plugin
secure-erase
tcg-opal
keysd
privsep
Reporting security issues <https://github.com/linux-nvme/nvme-cli/blob/master/SECURITY.md>
```

```{toctree}
:caption: Monitoring
:maxdepth: 1

prometheus-exporter
mcp
```

```{toctree}
:caption: Reference
:maxdepth: 1

commands
breaking-changes
migrating-2-to-3
ocp
troubleshooting
faq
Release notes <https://github.com/linux-nvme/nvme-cli/blob/master/NEWS.md>
```

```{toctree}
:caption: Contributing
:maxdepth: 1

Contribution guidelines <https://github.com/linux-nvme/nvme-cli/blob/master/CONTRIBUTING.md>
testing
spec-coverage
ini-parameter
privsep-design
Tests and fuzz coverage with Claude Code <https://github.com/linux-nvme/nvme-cli-ai/blob/main/docs/tests-and-fuzz-coverage.md>
```

```{toctree}
:caption: libnvme design
:maxdepth: 1

Configuration file format <https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/CONFIG.md>
Ownership registry <https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/REGISTRY.md>
Exclusion list <https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/EXCLUSIONS.md>
Pre-OS hand-over <https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/PRE-OS.md>
Transport ID (TID) <https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/TID.md>
Integrating libnvme into an application <https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/INTEGRATION.md>
```
