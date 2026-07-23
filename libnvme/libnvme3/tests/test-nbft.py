#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import os
import unittest
from libnvme3 import nvme
from argparse import ArgumentParser


class Testclass(unittest.TestCase):
    def setUp(self):
        self.expected_nbft = {
            "discovery": [
                {
                    "hfi_index": 0,
                    "nqn": "nqn.2014-08.org.nvmexpress.discovery",
                    "uri": "nvme+tcp://100.71.103.50:8009/",
                }
            ],
            "hfi": [
                {
                    "dhcp_iaid": 0,
                    "dhcp_duid": b"",
                    "dhcp_duid_len": 0,
                    "dhcp_server_ipaddr": "100.71.245.254",
                    "flags": 0x07,
                    "gateway_ipaddr": "100.71.245.254",
                    "ip_origin": 82,
                    "ipaddr": "100.71.245.232",
                    "mac_addr": "b0:26:28:e8:7c:0e",
                    "pcidev": "0:40:0.0",
                    "pcie_seg_num": 0,
                    "primary_dns_ipaddr": "100.64.0.5",
                    "route_metric": 500,
                    "secondary_dns_ipaddr": "100.64.0.6",
                    "subnet_mask_prefix": 24,
                    "trtype": "tcp",
                    "vlan": 0,
                }
            ],
            "host": {
                "flags": 0x07,
                "id": "44454c4c-3400-1036-8038-b2c04f313233",
                "nqn": "nqn.1988-11.com.dell:PowerEdge.R760.1234567",
            },
            "subsystem": [
                {
                    "asqsz": 0,
                    "cipeec": 0,
                    "controller_id": 5,
                    "cto": 0,
                    "flags": 0x0051,
                    "hfi_indexes": [0],
                    "naed": 0,
                    "nceec": 0,
                    "nid": "c82404ed9c15f53b8ccf0968002e0fca",
                    "nid_type": "nguid",
                    "nsid": 148,
                    "subsys_nqn": "nqn.1988-11.com.dell:powerstore:00:2a64abf1c5b81F6C4549",
                    "subsys_port_id": 0,
                    "traddr": "100.71.103.48",
                    "trflags": 0x0000,
                    "trsvcid": "4420",
                    "trtype": "tcp",
                },
                {
                    "asqsz": 0,
                    "cipeec": 0,
                    "controller_id": 4166,
                    "cto": 0,
                    "flags": 0x0051,
                    "hfi_indexes": [0],
                    "naed": 0,
                    "nceec": 0,
                    "nid": "c82404ed9c15f53b8ccf0968002e0fca",
                    "nid_type": "nguid",
                    "nsid": 148,
                    "subsys_nqn": "nqn.1988-11.com.dell:powerstore:00:2a64abf1c5b81F6C4549",
                    "subsys_port_id": 0,
                    "traddr": "100.71.103.49",
                    "trflags": 0x0000,
                    "trsvcid": "4420",
                    "trtype": "tcp",
                },
            ],
        }

    def test_read_nbft_file(self):
        """Make sure we get expected data when reading from binary NBFT file"""
        ctx = nvme.GlobalCtx()
        ctx.log_level('debug')
        actual_nbft = nvme.nbft_get(ctx, args.filename)
        self.assertEqual(actual_nbft, self.expected_nbft)


if __name__ == "__main__":
    import sys

    parser = ArgumentParser(description="Test NBFT")
    parser.add_argument("--filename", default=None, help="NBFT binary file to read")
    parser.add_argument("unittest_args", nargs="*")  # Grab everything else
    args = parser.parse_args()
    sys.argv[1:] = args.unittest_args

    unittest.main()
