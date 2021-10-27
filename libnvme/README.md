# Python bindings for libnvme

We use [SWIG](http://www.swig.org/) to generate Python bindings for libnvme.

## How to use

```python
#!/usr/bin/env python3
import sys
import pprint
from libnvme import nvme

root = nvme.root()      # This is a singleton
root.log_level('debug') # Optional: extra debug info

host = nvme.host(root)      # This "may be" a singleton. 
sybsysnqn  = [string]       # e.g. 'nqn.2014-08.org.nvmexpress.discovery', nvme.NVME_DISC_SUBSYS_NAME, ...
transport  = [string]       # One of: 'tcp, 'rdma', 'fc', 'loop'.
traddr     = [IPv4 or IPv6] # e.g. '192.168.10.10', 'fd2e:853b:3cad:e135:506a:65ee:29f2:1b18', ...
trsvcid    = [string]		# e.g. '8009', '4420', ...
host_iface = [interface]    # e.g. 'eth1', ens256', ...
ctrl = nvme.ctrl(subsysnqn=subsysnqn, transport=transport, traddr=traddr, trsvcid=trsvcid, host_iface=host_iface)

try:
    cfg = {
        'hdr_digest': True,   # Enable header digests
        'data_digest': False, # Disable data digests       
    }
    ctrl.connect(host, cfg)
    print(f"connected to {ctrl.name} subsys {ctrl.subsystem.name}")
except Exception as e:
    sys.exit(f'Failed to connect: {e}')

try:
    log_pages = ctrl.discover()
    print(pprint.pformat(log_pages))
except Exception as e:
    sys.exit(f'Failed to retrieve log pages: {e}')

try:
    ctrl.disconnect()
except Exception as e:
    sys.exit(f'Failed to disconnect: {e}')

```

