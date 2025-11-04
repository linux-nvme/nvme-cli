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

def discover(host, ctrl, iteration):
    # Only 8 levels of indirection are supported
    if iteration > 8:
        return

    try:
        ctrl.connect(host)
    except Exception as e:
        print(f'Failed to connect: {e}')
        return

    print(f'{ctrl.name} connected to {ctrl.subsystem}')

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
        return

    for dlpe in disc_log:
        if dlpe['subtype'] == 'nvme':
            print(f'{iteration}: {dlpe["subtype"]} {dlpe["subnqn"]}')
            continue
        if dlpe['subtype'] == 'discovery' and dlpe['subnqn'] == nvme.NVME_DISC_SUBSYS_NAME:
            continue
        print(f'{iteration}: {dlpe["subtype"]} {dlpe["subnqn"]}')
        with nvme.ctrl(root, subsysnqn=dlpe['subnqn'], transport=dlpe['trtype'], traddr=dlpe['traddr'], trsvcid=dlpe['trsvcid']) as new_ctrl:
            discover(host, new_ctrl, iteration + 1)

root = nvme.root()
host = nvme.host(root)

subsysnqn = nvme.NVME_DISC_SUBSYS_NAME
transport = 'tcp'
traddr = '127.0.0.1'
trsvcid = '4420'

with nvme.ctrl(root, subsysnqn=subsysnqn, transport=transport, traddr=traddr, trsvcid=trsvcid) as ctrl:
    discover(host, ctrl, 0)

for s in host.subsystems():
    for c in s.controllers():
        print(f'{s}: {c.name}')
