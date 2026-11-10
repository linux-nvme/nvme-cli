# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C1h Error Recovery log page.

This is the reference the error-recovery-log tests build pages from. It
is transcribed from the OCP Datacenter NVMe SSD specification's EREC
table (2.7 section 4.8.7.2), deliberately *not* from
`struct ocp_error_recovery_log_page`, so a disagreement between the two
shows up as a test failure.

The layout is the same in log page version 0003h of OCP 2.5, 2.6 and 2.7;
2.7 renames the Panic fields Error (Error Reset Wait Time, Error ID,
Error / Assert Count, Previous Error IDs).
"""

from __future__ import annotations

import struct
from typing import Dict, Mapping, Optional, Sequence, Tuple

LID = 0xC1
LOG_PAGE_SIZE = 512
LOG_PAGE_VERSION = 494
LOG_PAGE_GUID = 496
VERSION = 3

# EREC-12, 5A1983BA3DFD4DABAE3430FE2131D944h, on the wire.
GUID_BYTES = bytes.fromhex('5A1983BA3DFD4DABAE3430FE2131D944')[::-1]

ERROR_RESET_WAIT_TIME = 'Error Reset Wait Time'
ERROR_RESET_ACTION = 'Error Reset Action'
DEVICE_RECOVERY_ACTION_1 = 'Device Recovery Action 1'
ERROR_ID = 'Error ID'
DEVICE_CAPABILITIES = 'Device Capabilities'
VS_RECOVERY_OPCODE = 'Vendor Specific Recovery Opcode'
VS_COMMAND_CDW12 = 'Vendor Specific Command CDW12'
VS_COMMAND_CDW13 = 'Vendor Specific Command CDW13'
VS_COMMAND_TIMEOUT = 'Vendor Specific Command Timeout'
DEVICE_RECOVERY_ACTION_2 = 'Device Recovery Action 2'
DEVICE_RECOVERY_ACTION_2_TIMEOUT = 'Device Recovery Action 2 Timeout'
ERROR_ASSERT_COUNT = 'Error / Assert Count'

# Offset and struct format of each field (EREC-1..9, 13..16).
FIELDS: Dict[str, Tuple[int, str]] = {
    ERROR_RESET_WAIT_TIME: (0, '<H'),
    ERROR_RESET_ACTION: (2, '<B'),
    DEVICE_RECOVERY_ACTION_1: (3, '<B'),
    ERROR_ID: (4, '<Q'),
    DEVICE_CAPABILITIES: (12, '<I'),
    VS_RECOVERY_OPCODE: (16, '<B'),
    VS_COMMAND_CDW12: (20, '<I'),
    VS_COMMAND_CDW13: (24, '<I'),
    VS_COMMAND_TIMEOUT: (28, '<B'),
    DEVICE_RECOVERY_ACTION_2: (29, '<B'),
    DEVICE_RECOVERY_ACTION_2_TIMEOUT: (30, '<B'),
    ERROR_ASSERT_COUNT: (31, '<B'),
}

# EREC-17: Error IDs N-1 to N-4, eight bytes each.
PREVIOUS_ERROR_IDS = 32
PREVIOUS_ERROR_ID_COUNT = 4

# A distinct non-zero value for every field.
DEFAULT_VALUES: Mapping[str, int] = {
    ERROR_RESET_WAIT_TIME: 0x0102,
    ERROR_RESET_ACTION: 0x21,   # NVMe Controller Reset, Hot Reset
    DEVICE_RECOVERY_ACTION_1: 0x04,  # Vendor Specific Command Required
    ERROR_ID: 0x13141516,
    DEVICE_CAPABILITIES: 0x00000003,
    VS_RECOVERY_OPCODE: 0xC5,
    VS_COMMAND_CDW12: 0x21222324,
    VS_COMMAND_CDW13: 0x31323334,
    VS_COMMAND_TIMEOUT: 0x1C,
    DEVICE_RECOVERY_ACTION_2: 0x02,
    DEVICE_RECOVERY_ACTION_2_TIMEOUT: 0x1E,
    ERROR_ASSERT_COUNT: 0x1F,
}
DEFAULT_PREVIOUS_IDS = (0x4142434445464748, 0x5152535455565758,
                        0x6162636465666768, 0x7172737475767778)


def pack(values: Optional[Mapping[str, int]] = None,
         previous_ids: Sequence[int] = DEFAULT_PREVIOUS_IDS,
         version: int = VERSION, guid: bytes = GUID_BYTES
         ) -> Tuple[bytes, Dict[str, int]]:
    """A C1h page with every field set from @values over
    DEFAULT_VALUES. Returns the page and the field values in it."""
    if len(previous_ids) > PREVIOUS_ERROR_ID_COUNT:
        raise ValueError('the page holds 4 previous error IDs')
    merged = dict(DEFAULT_VALUES)
    merged.update(values or {})
    page = bytearray(LOG_PAGE_SIZE)
    for name, (offset, fmt) in FIELDS.items():
        struct.pack_into(fmt, page, offset, merged[name])
    for i, error_id in enumerate(previous_ids):
        struct.pack_into('<Q', page, PREVIOUS_ERROR_IDS + i * 8, error_id)
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    return bytes(page), merged
