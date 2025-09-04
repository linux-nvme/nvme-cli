#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
'''
Example script for nvme discovery
'''

import sys
import pprint
from libnvme import nvme

def disc_supp_str(dlp_supp_opts):
    d = {
        nvme.NVMF_LOG_DISC_LID_EXTDLPES: "Extended Discovery Log Page Entry Supported (EXTDLPES)",
        nvme.NVMF_LOG_DISC_LID_PLEOS:    "Port Local Entries Only Supported (PLEOS)",
        nvme.NVMF_LOG_DISC_LID_ALLSUBES: "All NVM Subsystem Entries Supported (ALLSUBES)",
    }
    return [txt for msk, txt in d.items() if dlp_supp_opts & msk]

root = nvme.root()
host = nvme.host(root)

subsysnqn = nvme.NVME_DISC_SUBSYS_NAME
transport = 'tcp'
traddr = '127.0.0.1'
trsvcid = '4420'

ctrl = nvme.ctrl(root, subsysnqn=subsysnqn, transport=transport, traddr=traddr, trsvcid=trsvcid)

try:
    ctrl.connect(host)
except Exception as e:
    sys.exit(f'Failed to connect: {e}')

print(f'{ctrl.name} connected to subsys {ctrl.subsystem}')

slp = ctrl.supported_log_pages()

try:
    dlp_supp_opts = slp[nvme.NVME_LOG_LID_DISCOVER] >> 16
except (TypeError, IndexError):
    dlp_supp_opts = 0

print(f"LID {nvme.NVME_LOG_LID_DISCOVER}h (Discovery), supports: {disc_supp_str(dlp_supp_opts)}")

try:
    lsp = nvme.NVMF_LOG_DISC_LSP_PLEO if dlp_supp_opts & nvme.NVMF_LOG_DISC_LID_PLEOS else 0
    disc_log = ctrl.discover(lsp=lsp)
except Exception as e:
    print(f'Failed to discover: {e}')
    disc_log = []

for dlpe in disc_log:
    print(f'log entry {dlpe["portid"]}: {dlpe["subtype"]} {dlpe["subnqn"]}')

try:
    ctrl.disconnect()
except Exception as e:
    sys.exit(f'Failed to disconnect: {e}')

for s in host.subsystems():
    for c in s.controllers():
        print(f'{s}: {c.name}')
