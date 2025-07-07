#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import gc
import sys
import pprint
from libnvme import nvme

ctx = nvme.global_ctx()
ctx.log_level('debug')
print(f'ctx: {ctx}')

host = nvme.host(ctx)
print(f'host: {host}')

ctrls = []
for i in range(10):
    ctrl = nvme.ctrl(
        ctx,
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
ctx = None
host = None

gc.collect()  # Force garbage collection before controller/subsystem objects get deleted

ctrls = None
subsystem= None
ns = None
