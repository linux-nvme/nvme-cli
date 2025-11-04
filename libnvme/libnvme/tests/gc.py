#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import gc
import sys
import pprint
from libnvme import nvme

root = nvme.root()
root.log_level('debug')
print(f'root: {root}')

host = nvme.host(root)
print(f'host: {host}')

ctrls = []
for i in range(10):
    ctrl = nvme.ctrl(
        root,
        subsysnqn=nvme.NVME_DISC_SUBSYS_NAME,
        transport='loop',
    )
    ctrls.append(ctrl)
    print(f'ctrl {i}: {ctrl}')

for s in host.subsystems():
    print(f'subsystem: {s}')
    for ns in s.namespaces():
        print(f'ns: {ns}')

# Deleting objects in the following order would create a segmentation
# fault if it weren't for the %pythonappend in nvme.i. This test is to
# make sure garbage collection is not impacted by object deletion order.
root = None
host = None

gc.collect()  # Force garbage collection before controller/subsystem objects get deleted

ctrls = None
subsystem= None
ns = None
