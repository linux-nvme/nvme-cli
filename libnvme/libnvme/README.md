<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Python bindings for libnvme

We use [SWIG](http://www.swig.org/) to generate Python bindings for libnvme.

## Classes

Five classes are exposed, matching the NVMe topology:

| Class | Description |
|---|---|
| `nvme.GlobalCtx` | Root context. Manages the NVMe device tree and logging. Create one instance per process. |
| `nvme.Host` | Represents the local host: NQN, host ID, optional symbolic name (symname). |
| `nvme.Subsystem` | An NVMe subsystem discovered under a host. |
| `nvme.Ctrl` | An NVMe controller (physical or fabrics). Constructed from a configuration dict. |
| `nvme.Namespace` | A namespace under a controller. |

All five classes support the context manager protocol (`with` statement) for automatic cleanup.

Topology can be traversed with iterators: `ctx.hosts()`, `host.subsystems()`,
`subsystem.controllers()`, `ctrl.namespaces()`.

### Ctrl configuration dict

`nvme.Ctrl(ctx, cfg)` accepts a flat dict. Common keys:

| Key | Description |
|---|---|
| `subsysnqn` | Subsystem NQN (required) |
| `transport` | Transport type: `pcie`, `tcp`, `rdma`, `fc`, `loop`, `apple-nvme` (required) |
| `traddr` | Target address |
| `trsvcid` | Target service ID (port) |
| `host_iface` | Local network interface to use |
| `hostnqn` | Override the host NQN |
| `hostid` | Override the host ID |
| `hdr_digest` | Enable header digests (`bool`) |
| `data_digest` | Enable data digests (`bool`) |
| `persistent` | Keep the connection alive after the object is released (`bool`) |

### Key Ctrl methods and properties

| Name | Type | Description |
|---|---|---|
| `connected` | property | `True` if the controller is currently connected |
| `registration_supported` | property | `True` if the target supports explicit host registration |
| `name` | property | Kernel device name (e.g. `nvme0`), or `None` if not connected |
| `transport`, `traddr`, `trsvcid` | properties | Connection parameters |
| `connect(host)` | method | Establish the kernel connection |
| `disconnect()` | method | Tear down the connection |
| `discover()` | method | Retrieve the discovery log page (discovery controllers only) |
| `get_supported_log_pages()` | method | Fetch the Supported Log Pages log |
| `rescan()` | method | Rescan the controller and refresh its namespace list |
| `registration_control(tas)` | method | Register / deregister / update with the DIM service |

## Exceptions

All libnvme errors are reported through a small exception hierarchy:

```
NvmeError                  base class — carries .errno (int) and .message (str)
├── ConnectError            raised by ctrl.connect()
├── DisconnectError         raised by ctrl.disconnect()
├── DiscoverError           raised by ctrl.discover()
└── NotConnectedError       raised when an operation requires a connected controller
                            (.errno is always 0)
```

Import them directly from the `nvme` module:

```python
from libnvme import nvme

try:
    ctrl.connect(host)
except nvme.ConnectError as e:
    print(f"errno={e.errno}, message={e.message}")
except nvme.NotConnectedError:
    print("not connected")
```

`NvmeError` is also raised by `get_supported_log_pages()` and
`registration_control()` on failure.

## How to use

```python
#!/usr/bin/env python3
import sys
import pprint
from libnvme import nvme

def disc_supp_str(dlp_supp_opts):
    bitmap = {
        nvme.NVMF_LOG_DISC_LID_EXTDLPES: "EXTDLPES",
        nvme.NVMF_LOG_DISC_LID_PLEOS:    "PLEOS",
        nvme.NVMF_LOG_DISC_LID_ALLSUBES: "ALLSUBES",
    }
    return [txt for msk, txt in bitmap.items() if dlp_supp_opts & msk]

ctx = nvme.GlobalCtx()
ctx.log_level('debug')  # Optional: extra debug info

host = nvme.Host(ctx)

ctrl = nvme.Ctrl(ctx, {
    'subsysnqn':  '...',    # e.g. nvme.NVME_DISC_SUBSYS_NAME
    'transport':  '...',    # One of: 'tcp', 'rdma', 'fc', 'loop'
    'traddr':     '...',    # e.g. '192.168.10.10'
    'trsvcid':    '...',    # e.g. '8009', '4420'
    'host_iface': '...',    # e.g. 'eth1', 'ens256'
    'hdr_digest': True,     # Enable header digests
    'data_digest': False,   # Disable data digests
})

try:
    ctrl.connect(host)
    print(f"connected to {ctrl.name} subsys {ctrl.subsystem.name}")
except nvme.ConnectError as e:
    sys.exit(f'Failed to connect: {e}')

try:
    slp = ctrl.get_supported_log_pages()
    dlp_supp_opts = slp[nvme.NVME_LOG_LID_DISCOVERY] >> 16
except (nvme.NvmeError, IndexError, TypeError):
    dlp_supp_opts = 0

print(f"LID {nvme.NVME_LOG_LID_DISCOVERY:02x}h (Discovery), supports: {disc_supp_str(dlp_supp_opts)}")

try:
    lsp = nvme.NVMF_LOG_DISC_LSP_PLEO if dlp_supp_opts & nvme.NVMF_LOG_DISC_LID_PLEOS else 0
    log_pages = ctrl.discover(lsp=lsp)
    print(pprint.pformat(log_pages))
except nvme.DiscoverError as e:
    sys.exit(f'Failed to retrieve log pages: {e}')

try:
    ctrl.disconnect()
except nvme.DisconnectError as e:
    sys.exit(f'Failed to disconnect: {e}')
```

## Installation

The package is available from most Linux distribution repositories and on PyPI.

**From your distribution (recommended):**

```bash
# Debian / Ubuntu
apt-get install python3-libnvme

# Fedora
dnf install python3-libnvme

# openSUSE
zypper install python3-libnvme
```

**From PyPI:**

```bash
pip install libnvme
```

> **Note:** The PyPI package is a source distribution — it builds libnvme and
> the Python bindings directly on your machine. Build dependencies (a C
> compiler, Meson, Ninja, SWIG, and the libnvme C dependencies) must be
> present. If any are missing, `pip install` will fail. Installing from your
> distribution package manager is generally easier and avoids this requirement.

See [PUBLISHING.md](PUBLISHING.md) for instructions on testing and publishing new releases.
