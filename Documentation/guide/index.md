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

breaking-changes
migrating-2-to-3
ocp
troubleshooting
faq
```

```{toctree}
:caption: Contributing
:maxdepth: 1

ini-parameter
```
