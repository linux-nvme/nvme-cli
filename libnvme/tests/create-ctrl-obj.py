#!/usr/bin/env python3
import sys
import pprint
from libnvme import nvme

root = nvme.root()      
root.log_level('debug') 

host = nvme.host(root)  
subsysnqn = nvme.NVME_DISC_SUBSYS_NAME
transport = 'loop'
traddr    = '127.0.0.1'
trsvcid   = '8009'
ctrl = nvme.ctrl(subsysnqn=subsysnqn, transport=transport, traddr=traddr, trsvcid=trsvcid)
