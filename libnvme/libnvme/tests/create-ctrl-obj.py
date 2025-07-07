#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import sys
import pprint
from libnvme import nvme

ctx = nvme.global_ctx()      
ctx.log_level('debug') 

host = nvme.host(ctx)  
subsysnqn = nvme.NVME_DISC_SUBSYS_NAME
transport = 'loop'
traddr    = '127.0.0.1'
trsvcid   = '8009'
ctrl = nvme.ctrl(ctx, subsysnqn=subsysnqn, transport=transport, traddr=traddr, trsvcid=trsvcid)
