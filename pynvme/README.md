# Python bindings for libnvme

We use [SWIG](http://www.swig.org/) to generate Python bindings for libnvme.

## How to use

```python
import sys
from libnvme import nvme

root = nvme.root()     # This is a singleton
host = nvme.host(root) # This "may be" a singleton. 
ctrl = nvme.ctrl(subsysnqn=<nqn>, transport=<trtype>, traddr=<traddr>, trsvcid=<trsvcid>, host_traddr=<traddr or None>, host_iface=<iface or None>)

try:
    ctrl.connect(host)
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

