#!/usr/bin/python3
'''
SPDX-License-Identifier: LGPL-3.1-or-later

This file is part of libnvme.
Copyright (c) 2021 SUSE Software Solutions AG

Authors: Hannes Reinecke <hare@suse.de>

Scans the NVMe subsystem and prints out all found hosts,
subsystems, and controllers
'''

import libnvme

r = libnvme.nvme_root()
for h in r.hosts():
    print (h)
    for s in h.subsystems():
        print (s)
        for c in s.controllers():
            print (c)

