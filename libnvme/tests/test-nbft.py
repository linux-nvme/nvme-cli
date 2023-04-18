#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import os
import unittest
from libnvme import nvme
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
                    "dhcp_override": True,
                    "dhcp_server_ipaddr": "100.71.245.254",
                    "gateway_ipaddr": "100.71.245.254",
                    "ip_origin": 82,
                    "ipaddr": "100.71.245.232",
                    "mac_addr": "b0:26:28:e8:7c:0e",
                    "pcidev": "0:40:0.0",
                    "primary_dns_ipaddr": "100.64.0.5",
                    "route_metric": 500,
                    "secondary_dns_ipaddr": "100.64.0.6",
                    "subnet_mask_prefix": 24,
                    "this_hfi_is_default_route": 1,
                    "trtype": "tcp",
                    "vlan": 0,
                }
            ],
            "host": {
                "host_id_configured": True,
                "host_nqn_configured": True,
                "id": "44454c4c-3400-1036-8038-b2c04f313233",
                "nqn": "nqn.1988-11.com.dell:PowerEdge.R760.1234567",
                "primary_admin_host_flag": "not indicated",
            },
            "subsystem": [
                {
                    "asqsz": 0,
                    "controller_id": 5,
                    "data_digest_required": False,
                    "hfi_indexes": [0],
                    "nid": "c82404ed9c15f53b8ccf0968002e0fca",
                    "nid_type": "nguid",
                    "nsid": 148,
                    "pdu_header_digest_required": False,
                    "subsys_nqn": "nqn.1988-11.com.dell:powerstore:00:2a64abf1c5b81F6C4549",
                    "subsys_port_id": 0,
                    "traddr": "100.71.103.48",
                    "trsvcid": "4420",
                    "trtype": "tcp",
                },
                {
                    "asqsz": 0,
                    "controller_id": 4166,
                    "data_digest_required": False,
                    "hfi_indexes": [0],
                    "nid": "c82404ed9c15f53b8ccf0968002e0fca",
                    "nid_type": "nguid",
                    "nsid": 148,
                    "pdu_header_digest_required": False,
                    "subsys_nqn": "nqn.1988-11.com.dell:powerstore:00:2a64abf1c5b81F6C4549",
                    "subsys_port_id": 0,
                    "traddr": "100.71.103.49",
                    "trsvcid": "4420",
                    "trtype": "tcp",
                },
            ],
        }

    def test_read_nbft_file(self):
        """Make sure we get expected data when reading from binary NBFT file"""
        actual_nbft = nvme.nbft_get(args.filename)
        self.assertEqual(actual_nbft, self.expected_nbft)


if __name__ == "__main__":
    import sys

    parser = ArgumentParser(description="Test NBFT")
    parser.add_argument("--filename", default=None, help="NBFT binary file to read")
    parser.add_argument("unittest_args", nargs="*")  # Grab everything else
    args = parser.parse_args()
    sys.argv[1:] = args.unittest_args

    unittest.main()
