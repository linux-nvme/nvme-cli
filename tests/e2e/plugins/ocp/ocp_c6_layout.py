# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C6h Hardware Component log page.

This is the reference the hardware-component-log tests build pages from.
It is transcribed from the OCP Datacenter NVMe SSD specification's
HWCLOG, COMPD and CITYPE tables (2.7 section 4.8.13), deliberately *not*
from `struct hwcomp_log`, so a disagreement between the two shows up as a
test failure.

The Hardware Component Log Size (HWCLOG-4) counts dwords in log page
version 1 (OCP 2.5) and bytes from version 2 (OCP 2.6 and 2.7). The
Date/Lot Size and Additional Information Size of a descriptor (COMPD-1,
COMPD-2) count dwords in every version. Born on Date (000Ch) is defined
from OCP 2.6.
"""

from __future__ import annotations

import struct
from typing import Iterable, NamedTuple

LID = 0xC6

# Header (HWCLOG-1..5); the descriptors start at byte 64 (HWCOMP-7).
LOG_PAGE_VERSION = 0
LOG_PAGE_GUID = 16
LOG_SIZE = 32
LOG_SIZE_LEN = 16
HEADER_SIZE = 64

# Fixed part of a Component Descriptor (COMPD-1..6), then the Date/Lot
# Code (COMPD-7) and the Additional Information (COMPD-8).
DESC_DATE_LOT_SIZE = 0
DESC_ADD_INFO_SIZE = 8
DESC_ID = 16
DESC_MFG = 20
DESC_REV = 28
DESC_MFG_CODE = 36
DESC_SIZE = 44

# HWCLOG-3, BCB6821F30CD4ED0B76B31B99F0F57DCh, on the wire.
GUID_BYTES = bytes.fromhex('BCB6821F30CD4ED0B76B31B99F0F57DC')[::-1]

# Component Identifier Table (CITYPE-1..15).
ID_RESERVED = 0x0000
ID_ASIC = 0x0001
ID_NAND = 0x0002
ID_DRAM = 0x0003
ID_PMIC = 0x0004
ID_PCB = 0x0005
ID_CAP = 0x0006
ID_RESISTOR = 0x0007
ID_CASE = 0x0008
ID_SN = 0x0009
ID_COUNTRY = 0x000A
ID_HW_REV = 0x000B
ID_BORN_ON_DATE = 0x000C
ID_VENDOR_FIRST = 0x8000
ID_VENDOR_LAST = 0xFFFF

# The description of each identifier, as the table words it.
ID_NAMES = {
    ID_ASIC: 'Controller ASIC component',
    ID_NAND: 'NAND Component',
    ID_DRAM: 'DRAM Component',
    ID_PMIC: 'PMIC Component',
    ID_PCB: 'PCB Component',
    ID_CAP: 'capacitor component',
    ID_RESISTOR: 'resistor component',
    ID_CASE: 'case component',
    ID_SN: 'Device Serial Number',
    ID_COUNTRY: 'Country of Origin',
    ID_HW_REV: 'Global Device Hardware Revision',
    ID_BORN_ON_DATE: 'Born on Date',
}
RESERVED_NAME = 'Reserved'
VENDOR_NAME = 'Vendor Unique Component'


def id_name(ident: int) -> str:
    """The description CITYPE gives @ident."""
    if ident in ID_NAMES:
        return ID_NAMES[ident]
    if ID_VENDOR_FIRST <= ident <= ID_VENDOR_LAST:
        return VENDOR_NAME
    return RESERVED_NAME


class Descriptor(NamedTuple):
    """One Component Descriptor. @date_lot and @add_info are whole
    dwords; @date_lot_dw and @add_info_dw override the sizes written,
    for descriptors that lie about them."""
    ident: int
    mfg: int = 0
    rev: int = 0
    mfg_code: int = 0
    date_lot: bytes = b''
    add_info: bytes = b''
    date_lot_dw: int | None = None
    add_info_dw: int | None = None


def pack_descriptor(d: Descriptor) -> bytes:
    if len(d.date_lot) % 4 or len(d.add_info) % 4:
        raise ValueError('descriptor fields are whole dwords')
    date_lot_dw = (len(d.date_lot) // 4 if d.date_lot_dw is None
                   else d.date_lot_dw)
    add_info_dw = (len(d.add_info) // 4 if d.add_info_dw is None
                   else d.add_info_dw)
    fixed = bytearray(DESC_SIZE)
    struct.pack_into('<Q', fixed, DESC_DATE_LOT_SIZE, date_lot_dw)
    struct.pack_into('<Q', fixed, DESC_ADD_INFO_SIZE, add_info_dw)
    struct.pack_into('<I', fixed, DESC_ID, d.ident)
    struct.pack_into('<Q', fixed, DESC_MFG, d.mfg)
    struct.pack_into('<Q', fixed, DESC_REV, d.rev)
    struct.pack_into('<Q', fixed, DESC_MFG_CODE, d.mfg_code)
    return bytes(fixed) + d.date_lot + d.add_info


def pack(descriptors: Iterable[Descriptor] = (), version: int = 2,
         guid: bytes = GUID_BYTES, size: int | None = None,
         tail: bytes = b'') -> bytes:
    """A C6h page of log page @version holding @descriptors back to
    back from byte 64, then @tail. The Hardware Component Log Size is the
    length of the page, in dwords for version 1 and bytes otherwise,
    unless @size gives the value to write."""
    body = b''.join(pack_descriptor(d) for d in descriptors) + tail
    page = bytearray(HEADER_SIZE) + body
    if size is None and version == 1:
        if len(page) % 4:
            raise ValueError('a version 1 page is whole dwords')
        size = len(page) // 4
    elif size is None:
        size = len(page)
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    page[LOG_SIZE:LOG_SIZE + LOG_SIZE_LEN] = size.to_bytes(LOG_SIZE_LEN,
                                                           'little')
    return bytes(page)
