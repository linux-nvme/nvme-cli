# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C4h Device Capabilities log page.

This is the reference the device-capability-log tests build pages from
and decode against. It is transcribed from the OCP Datacenter NVMe SSD
specification's DCLP field table, deliberately *not* from
`struct ocp_device_capabilities_log_page`, so a disagreement between the
two shows up as a test failure.

DCLP-13 (FIPS 140 Validation) is defined from log page version 2
(OCP 2.7).
"""

from __future__ import annotations

import struct
from typing import Dict

LID = 0xC4
LOG_PAGE_SIZE = 4096

PCIE_EXP_PORT = 0
OOB_MANAGEMENT_SUPPORT = 2
WZ_CMD_SUPPORT = 4
SANITIZE_CMD_SUPPORT = 6
DSM_CMD_SUPPORT = 8
WU_CMD_SUPPORT = 10
FUSED_OPERATION_SUPPORT = 12
MIN_VALID_DSSD_PWR_STATE = 14
DSSD_PWR_STATE_DESC = 16
DSSD_PWR_STATE_DESC_LEN = 128
FIPS_140_VALIDATION = 144
RESERVED = 146
LOG_PAGE_VERSION = 4078
LOG_PAGE_GUID = 4080

FIPS_140_MIN_VERSION = 2

# dev_cap_req_guid in plugins/ocp/ocp-nvme.c, on the wire.
GUID_BYTES = bytes.fromhex('9742050dd1e1c9985d49584b913c05b7')

# Fixed fields ahead of the power state descriptors, as (offset, value),
# each a distinct le16 so a field read from the wrong offset shows.
FIXED_FIELDS = {
    PCIE_EXP_PORT: 0x0102,
    OOB_MANAGEMENT_SUPPORT: 0x8007,
    WZ_CMD_SUPPORT: 0x801F,
    SANITIZE_CMD_SUPPORT: 0x801E,
    DSM_CMD_SUPPORT: 0x8003,
    WU_CMD_SUPPORT: 0x800F,
    FUSED_OPERATION_SUPPORT: 0x8001,
    MIN_VALID_DSSD_PWR_STATE: 0x0003,
}


def pack(version: int = 2, fips: int = 0, guid: bytes = GUID_BYTES) -> bytes:
    """A C4h page reporting log page @version, with the DCLP-13 word
    @fips."""
    page = bytearray(LOG_PAGE_SIZE)
    for offset, value in FIXED_FIELDS.items():
        struct.pack_into('<H', page, offset, value)
    page[DSSD_PWR_STATE_DESC + 1:DSSD_PWR_STATE_DESC + 4] = b'\x11\x22\x33'
    struct.pack_into('<H', page, FIPS_140_VALIDATION, fips)
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    return bytes(page)


def parse_stdout(text: str) -> Dict[str, str]:
    """Label to value for every "label : value" line of the text report,
    labels and values stripped of their alignment."""
    fields = {}
    for line in text.splitlines():
        label, sep, value = line.partition(':')
        if sep:
            fields[label.strip()] = value.strip()
    return fields
