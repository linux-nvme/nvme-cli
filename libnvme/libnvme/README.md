# Python bindings for libnvme

We use [SWIG](http://www.swig.org/) to generate Python bindings for libnvme.

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

root = nvme.root()      # This is a singleton
root.log_level('debug') # Optional: extra debug info

host = nvme.host(root)      # This "may be" a singleton. 
subsysnqn  = [string]       # e.g. nvme.NVME_DISC_SUBSYS_NAME, ...
transport  = [string]       # One of: 'tcp', 'rdma', 'fc', 'loop'.
traddr     = [IPv4 or IPv6] # e.g. '192.168.10.10', 'fd2e:853b:3cad:e135:506a:65ee:29f2:1b18', ...
trsvcid    = [string]		# e.g. '8009', '4420', ...
host_iface = [interface]    # e.g. 'eth1', ens256', ...
ctrl = nvme.ctrl(root, subsysnqn=subsysnqn, transport=transport, traddr=traddr, trsvcid=trsvcid, host_iface=host_iface)

try:
    cfg = {
        'hdr_digest': True,   # Enable header digests
        'data_digest': False, # Disable data digests       
    }
    ctrl.connect(host, cfg)
    print(f"connected to {ctrl.name} subsys {ctrl.subsystem.name}")
except Exception as e:
    sys.exit(f'Failed to connect: {e}')

supported_log_pages = ctrl.supported_log_pages()
try:
    # Get the supported options for the Get Discovery Log Page command
    dlp_supp_opts = supported_log_pages[nvme.NVME_LOG_LID_DISCOVER] >> 16
except (TypeError, IndexError):
    dlp_supp_opts = 0

print(f"LID {nvme.NVME_LOG_LID_DISCOVER:02x}h (Discovery), supports: {disc_supp_str(dlp_supp_opts)}")
try:
    lsp = nvme.NVMF_LOG_DISC_LSP_PLEO if dlp_supp_opts & nvme.NVMF_LOG_DISC_LID_PLEOS else 0
    log_pages = ctrl.discover(lsp=lsp)
    print(pprint.pformat(log_pages))
except Exception as e:
    sys.exit(f'Failed to retrieve log pages: {e}')

try:
    ctrl.disconnect()
except Exception as e:
    sys.exit(f'Failed to disconnect: {e}')

ctrl = None
host = None
root = None
```

