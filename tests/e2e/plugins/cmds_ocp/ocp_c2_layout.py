# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C2h Firmware Activation History log page.

This is the reference the fw-activate-history tests build pages from. It
is transcribed from the OCP Datacenter NVMe SSD specification 2.0
(section 4.8.7, FAHL-1..7 and FAHE-1..13), deliberately *not* from
`struct fw_activation_history`, so a disagreement between the two shows
up as a test failure. From 2.5 on the page, and the Clear Firmware
Update History feature (FID C1h) which empties it, are obsolete (2.7
sections 4.8.4 and 4.15.2): activations are Persistent Event Log
Firmware Commit events instead (STD-LOG-10).

The entries are a circular buffer of the last 20 activations: the 21st
goes into entry 0 (FWHST-LOG-1), and Valid Firmware Activation History
Entries stops at 20 (FAHL-3).
"""

from __future__ import annotations

import struct
from typing import Iterable, NamedTuple

LID = 0xC2
LOG_PAGE_SIZE = 4096

LOG_ID = 0
VALID_ENTRIES = 4
ENTRIES = 8
ENTRY_SIZE = 64
MAX_ENTRIES = 20
LOG_PAGE_VERSION = 4078
LOG_PAGE_GUID = 4080
VERSION = 1

# Entry fields (FAHE-1..12). The Timestamp is the NVMe Timestamp
# (Feature Identifier 0Eh) format: milliseconds in bytes 5:0, the
# attributes in byte 6.
ENTRY_VERSION = 0
ENTRY_LENGTH = 1
ENTRY_ACTIVATION_COUNT = 4
ENTRY_TIMESTAMP = 6
ENTRY_POWER_CYCLE_COUNT = 22
ENTRY_PREVIOUS_FW = 30
ENTRY_NEW_FW = 38
ENTRY_SLOT = 46
ENTRY_COMMIT_ACTION = 47
ENTRY_RESULT = 48
FW_LEN = 8
ENTRY_FORMAT_VERSION = 0x01
ENTRY_LENGTH_BYTES = 0x40

# FAHL-7, D11CF3AC8AB24DE2A3F6DAB4769A796Dh, on the wire.
GUID_BYTES = bytes.fromhex('D11CF3AC8AB24DE2A3F6DAB4769A796D')[::-1]


class Entry(NamedTuple):
    version: int = ENTRY_FORMAT_VERSION
    length: int = ENTRY_LENGTH_BYTES
    activation_count: int = 0
    timestamp_ms: int = 0
    timestamp_attr: int = 0
    power_cycle_count: int = 0
    previous_fw: bytes = b''
    new_fw: bytes = b''
    slot: int = 0
    commit_action: int = 0
    result: int = 0


def pack_entry(e: Entry) -> bytes:
    data = bytearray(ENTRY_SIZE)
    data[ENTRY_VERSION] = e.version
    data[ENTRY_LENGTH] = e.length
    struct.pack_into('<H', data, ENTRY_ACTIVATION_COUNT, e.activation_count)
    data[ENTRY_TIMESTAMP:ENTRY_TIMESTAMP + 6] = e.timestamp_ms.to_bytes(
        6, 'little')
    data[ENTRY_TIMESTAMP + 6] = e.timestamp_attr
    struct.pack_into('<Q', data, ENTRY_POWER_CYCLE_COUNT,
                     e.power_cycle_count)
    data[ENTRY_PREVIOUS_FW:ENTRY_PREVIOUS_FW + FW_LEN] = e.previous_fw.ljust(
        FW_LEN, b'\0')
    data[ENTRY_NEW_FW:ENTRY_NEW_FW + FW_LEN] = e.new_fw.ljust(FW_LEN, b'\0')
    data[ENTRY_SLOT] = e.slot
    data[ENTRY_COMMIT_ACTION] = e.commit_action
    struct.pack_into('<H', data, ENTRY_RESULT, e.result)
    return bytes(data)


def pack(entries: Iterable[Entry] = (), valid: int | None = None,
         version: int = VERSION, guid: bytes = GUID_BYTES,
         start: int = 0) -> bytes:
    """A C2h page holding @entries, oldest first, from entry @start on,
    wrapping round to entry 0 as the circular buffer does. Valid Entries
    is their number unless @valid gives the value to write."""
    entries = list(entries)
    if len(entries) > MAX_ENTRIES:
        raise ValueError('the page holds 20 entries')
    page = bytearray(LOG_PAGE_SIZE)
    page[LOG_ID] = LID
    struct.pack_into('<I', page, VALID_ENTRIES,
                     len(entries) if valid is None else valid)
    for i, e in enumerate(entries):
        offset = ENTRIES + (start + i) % MAX_ENTRIES * ENTRY_SIZE
        page[offset:offset + ENTRY_SIZE] = pack_entry(e)
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    return bytes(page)
