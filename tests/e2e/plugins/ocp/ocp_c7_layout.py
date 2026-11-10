# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C7h TCG Configuration log page.

This is the reference the tcg-configuration-log tests build pages from.
It is transcribed from the OCP Datacenter NVMe SSD specification's TCGL
tables, deliberately *not* from `struct tcg_configuration_log`, so a
disagreement between the two shows up as a test failure.

Each published log page version has a layout of its own:

  * 0001h (OCP 2.5): one-byte counters TCGL-3..13 at bytes 4..14, the
    four-byte TCGL-15..19 at 19:16..35:32.
  * 0002h (OCP 2.6): adds TCGL-23, Number of Namespace Provisioned
    Locking Objects Extended, at 37:36.
  * 0003h (OCP 2.7): the counters TCGL-3..13 grow to two bytes (5:4 ..
    25:24), TCGL-14 is obsolete, TCGL-15..19 move to 29:26 .. 45:42 and
    TCGL-23 to 49:46. The table gives TCGL-23 a size of 2 but the byte
    range 49:46; FIELDS writes it as two bytes and leaves 49:48 zero.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Mapping, Optional, Tuple

LID = 0xC7
LOG_PAGE_SIZE = 512
LOG_PAGE_VERSION = 494
LOG_PAGE_GUID = 496

# TCGL-22, 54E02A9DFA5447C083E6E07EBD244006h, on the wire.
GUID_BYTES = bytes.fromhex('54E02A9DFA5447C083E6E07EBD244006')[::-1]

STATE = 'State'
LOCKING_SP_ACTIVATION = 'Locking SP Activation Count'
TPER_REVERT = 'Tper Revert Count'
LOCKING_SP_REVERT = 'Locking SP Revert Count'
LOCKING_OBJECTS = 'Number of Locking Objects'
SUM_OBJECTS = 'Number of Single User Mode Locking Objects'
RANGE_OBJECTS = 'Number of Range Provisioned Locking Objects'
NS_OBJECTS = 'Number of Namespace Provisioned Locking Objects'
READ_LOCKED = 'Number of Read Locked Locking Objects'
WRITE_LOCKED = 'Number of Write Locked Locking Objects'
READ_UNLOCKED = 'Number of Read Unlocked Locking Objects'
WRITE_UNLOCKED = 'Number of Write Unlocked Locking Objects'
SID_TRY_COUNT = 'SID Authentication Try Count'
SID_TRY_LIMIT = 'SID Authentication Try Limit'
TCG_RESET_COUNT = 'Programmatic TCG Reset Count'
RESET_LOCK_COUNT = 'Programmatic Reset Lock Count'
TCG_ERROR_COUNT = 'TCG Error Count'
NS_OBJECTS_EXT = 'Number of Namespace Provisioned Locking Objects Extended'

# TCGL-3..13 in table order, then TCGL-15..19.
COUNTERS = (LOCKING_SP_ACTIVATION, TPER_REVERT, LOCKING_SP_REVERT,
            LOCKING_OBJECTS, SUM_OBJECTS, RANGE_OBJECTS, NS_OBJECTS,
            READ_LOCKED, WRITE_LOCKED, READ_UNLOCKED, WRITE_UNLOCKED)
DWORDS = (SID_TRY_COUNT, SID_TRY_LIMIT, TCG_RESET_COUNT, RESET_LOCK_COUNT,
          TCG_ERROR_COUNT)

# TCGL-1 State bits.
STATE_C_PIN_SID_NOT_MSID = 1 << 0
STATE_C_PIN_SID_BLOCKED = 1 << 1
STATE_LOCKING_ENABLED = 1 << 2
STATE_SUM_OWNER_ADMINS = 1 << 3

Field = Tuple[int, str]  # (offset, struct format)


def _fields(counter_fmt: str, dwords_at: int,
            ext_at: Optional[int]) -> Dict[str, Field]:
    size = struct.calcsize(counter_fmt)
    fields: Dict[str, Field] = {STATE: (0, '<B')}
    for i, name in enumerate(COUNTERS):
        fields[name] = (4 + i * size, counter_fmt)
    for i, name in enumerate(DWORDS):
        fields[name] = (dwords_at + i * 4, '<I')
    if ext_at is not None:
        fields[NS_OBJECTS_EXT] = (ext_at, '<H')
    return fields


# Offset and format of every field, by log page version.
FIELDS: Mapping[int, Dict[str, Field]] = {
    1: _fields('<B', 16, None),
    2: _fields('<B', 16, 36),
    3: _fields('<H', 26, 46),
}


def default_values(version: int) -> Dict[str, int]:
    """A distinct non-zero value for every field of @version that fits
    it, so a field read from the wrong offset shows."""
    values = {STATE: STATE_C_PIN_SID_NOT_MSID | STATE_LOCKING_ENABLED}
    wide = version >= 3
    for i, name in enumerate(COUNTERS):
        values[name] = (0x0101 * (i + 1) + 0x1000 if wide
                        else 0x11 + i)
    for i, name in enumerate(DWORDS):
        values[name] = 0x01020304 * (i + 1)
    if NS_OBJECTS_EXT in FIELDS[version]:
        values[NS_OBJECTS_EXT] = 0x0A0B
    return values


def pack(version: int = 2, values: Optional[Mapping[str, int]] = None,
         guid: bytes = GUID_BYTES) -> Tuple[bytes, Dict[str, int]]:
    """A C7h page of log page @version, every field set from @values
    over default_values(). Returns the page and the values in it."""
    merged = default_values(version)
    merged.update(values or {})
    page = bytearray(LOG_PAGE_SIZE)
    for name, (offset, fmt) in FIELDS[version].items():
        struct.pack_into(fmt, page, offset, merged[name])
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    return bytes(page), {k: merged[k] for k in FIELDS[version]}


def field_names(version: int) -> List[str]:
    return list(FIELDS[version])
