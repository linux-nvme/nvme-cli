#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
'''
Example script for nvme discovery

Copyright (c) 2021 Hannes Reinecke, SUSE Software Solutions
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
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

r = nvme.root()
h = nvme.host(r)
c = nvme.ctrl(r, nvme.NVME_DISC_SUBSYS_NAME, 'loop')
try:
    c.connect(h)
except Exception as e:
    sys.exit(f'Failed to connect: {e}')

print("connected to %s subsys %s" % (c.name, c.subsystem.name))

slp = c.supported_log_pages()

try:
    dlp_supp_opts = slp[nvme.NVME_LOG_LID_DISCOVER] >> 16
except (TypeError, IndexError):
    dlp_supp_opts = 0

print(f"LID {nvme.NVME_LOG_LID_DISCOVER}h (Discovery), supports: {disc_supp_str(dlp_supp_opts)}")

try:
    lsp = nvme.NVMF_LOG_DISC_LSP_PLEO if dlp_supp_opts & nvme.NVMF_LOG_DISC_LID_PLEOS else 0
    d = c.discover(lsp=lsp)
    print(pprint.pformat(d))
except Exception as e:
    sys.exit(f'Failed to discover: {e}')

try:
c.disconnect()
except Exception as e:
    sys.exit(f'Failed to disconnect: {e}')

c = None
h = None
r = None
