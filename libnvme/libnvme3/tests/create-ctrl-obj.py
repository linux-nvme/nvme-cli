#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later


from libnvme3 import nvme

ctx = nvme.GlobalCtx()
ctx.log_level('debug')
(hostnqn, hostid) = nvme.host_get_ids(ctx)
ctx.hostnqn = hostnqn
ctx.hostid = hostid

ctrl = nvme.Ctrl(ctx, {
    'subsysnqn': nvme.NVME_DISC_SUBSYS_NAME,
    'transport': 'loop',
    'traddr': '127.0.0.1',
    'trsvcid': '8009',
})
