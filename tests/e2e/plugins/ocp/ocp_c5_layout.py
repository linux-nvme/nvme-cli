# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C5h Unsupported Requirements log page.

This is the reference the unsupported-reqs-log tests build pages from.
It is transcribed from the OCP Datacenter NVMe SSD specification's URLP
table (2.7 section 4.8.12, unchanged in log page version 0001h since
2.5), deliberately *not* from `struct unsupported_requirement_log`, so a
disagreement between the two shows up as a test failure.
"""

from __future__ import annotations

import struct
from typing import Optional, Sequence

LID = 0xC5
LOG_PAGE_SIZE = 4096

UNSUPPORTED_COUNT = 0
LIST = 16
ENTRY_SIZE = 16
MAX_ENTRIES = 253
LOG_PAGE_VERSION = 4078
LOG_PAGE_GUID = 4080
VERSION = 1

# URLP-6, C7BB98B7D0324863BB2C23990E9C722Fh, on the wire.
GUID_BYTES = bytes.fromhex('C7BB98B7D0324863BB2C23990E9C722F')[::-1]


def pack(requirement_ids: Sequence[bytes] = (),
         count: Optional[int] = None, version: int = VERSION,
         guid: bytes = GUID_BYTES) -> bytes:
    """A C5h page listing @requirement_ids, each zero padded to 16
    bytes (URLP-3). The Unsupported Count is their number unless @count
    gives the value to write."""
    if len(requirement_ids) > MAX_ENTRIES:
        raise ValueError('the list holds 253 entries')
    page = bytearray(LOG_PAGE_SIZE)
    struct.pack_into('<H', page, UNSUPPORTED_COUNT,
                     len(requirement_ids) if count is None else count)
    for i, req_id in enumerate(requirement_ids):
        if len(req_id) > ENTRY_SIZE:
            raise ValueError(f'{req_id!r} is longer than 16 bytes')
        offset = LIST + i * ENTRY_SIZE
        page[offset:offset + ENTRY_SIZE] = req_id.ljust(ENTRY_SIZE, b'\0')
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    return bytes(page)
