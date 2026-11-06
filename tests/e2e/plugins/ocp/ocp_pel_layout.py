# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the Persistent Event log page and its OCP TCG Activity
Event.

This is the reference the persistent-event-log tests build logs from and
decode against. The log header and the event header are transcribed from
the NVM Express Base Specification (Persistent Event Log, Log Identifier
0Dh), the TCG Activity Event from the OCP Datacenter NVMe SSD
specification 2.7, TCG Activity Event Format (TCGCE-1 to TCGCE-24),
deliberately *not* from `struct nvme_persistent_event_log` or
`struct tcg_activity_event_data`, so a disagreement between them shows up
as a test failure.

The Action in bits 1:0 of the Log Specific Parameter selects what a read
does with the reporting context: Read Log Data (00b) needs an established
context, Establish Context and Read Log Data (01b) creates one and fails
if one exists, Release Context (10b) releases it, and Establish Context
and Read 512 Bytes of Header (11b) creates one unless one exists and
returns the log header, whose Reporting Context Exists bit tells whether
one existed. The other LSP bits are reserved.

An event is a 24 byte header, Vendor Specific Information of VSIL bytes
and the event data. The Event Header Length (EHL) does not count the
first 3 bytes of the header; the Event Length (EL) counts the Vendor
Specific Information and the event data.

A Vendor Specific event (DEh) holds Vendor Specific Event Descriptors:
the event code, the data type, the UUID Index and the data length,
followed by that many bytes of data. The TCG Activity Event is one
descriptor of 38 bytes of binary data, after 4 bytes of zero Vendor
Specific Information which align that data to 8 bytes.
"""

from __future__ import annotations

import struct
from typing import Iterable

LID = 0x0D
HEADER_SIZE = 512

ACTION_READ = 0
ACTION_EST_CTX_AND_READ = 1
ACTION_RELEASE_CTX = 2
ACTION_EST_CTX_AND_READ_HDR = 3
ACTION_MASK = 0x3

# Log header
LOG_ID = 0
TNEV = 4
TLL = 8
LOG_REVISION = 16
LHL = 18
TIMESTAMP = 20
POH = 28
POH_LEN = 16
PCC = 44
VID = 52
SSVID = 54
SN = 56
SN_LEN = 20
MN = 76
MN_LEN = 40
SUBNQN = 116
SUBNQN_LEN = 256
GEN_NUMBER = 372
RCI = 374
# Reporting Context Exists, in RCI
RCI_RCE = 1 << 18
SEB = 480
SEB_LEN = 32

# Header field name -> (struct format, offset)
HEADER_FIELDS = {
    'lid': ('B', LOG_ID),
    'tnev': ('<I', TNEV),
    'tll': ('<Q', TLL),
    'rv': ('B', LOG_REVISION),
    'lhl': ('<H', LHL),
    'ts': ('<Q', TIMESTAMP),
    'pcc': ('<Q', PCC),
    'vid': ('<H', VID),
    'ssvid': ('<H', SSVID),
    'sn': (f'{SN_LEN}s', SN),
    'mn': (f'{MN_LEN}s', MN),
    'subnqn': (f'{SUBNQN_LEN}s', SUBNQN),
    'gen_number': ('<H', GEN_NUMBER),
    'rci': ('<I', RCI),
}

# Event header
EVENT_HEADER_SIZE = 24
ETYPE = 0
ETYPE_REV = 1
EHL = 2
EHAI = 3
CNTLID = 4
ETS = 6
PELPID = 14
VSIL = 20
EL = 22
# The bytes of the header which EHL does not count.
EHL_UNCOUNTED = 3

EVENT_HEADER_FIELDS = {
    'etype': ('B', ETYPE),
    'etype_rev': ('B', ETYPE_REV),
    'ehl': ('B', EHL),
    'ehai': ('B', EHAI),
    'cntlid': ('<H', CNTLID),
    'ets': ('<Q', ETS),
    'pelpid': ('<H', PELPID),
}

# Event types
ETYPE_FW_COMMIT = 0x02
ETYPE_TIMESTAMP_CHANGE = 0x03
ETYPE_TELEMETRY_LOG_CREATE = 0x0C
ETYPE_VENDOR_SPECIFIC = 0xDE

# Vendor Specific Event Descriptor data types
VSEDT_EVENT_NAME = 1
VSEDT_ASCII_STRING = 2
VSEDT_BINARY = 3
VSEDT_SIGNED_INT = 4

# TCG Activity Event (TCGCE-*), from the start of the event
TCG_EHL = 0x15
TCG_ETYPE_REV = 0x01
TCG_VSIL = 0x04
TCG_EL = 0x30
TCG_VSEC = 0x0001
TCG_VSEDL = 0x26
TCG_EVENT_SIZE = 72

TCG_VSI = 24
TCG_VSEC_OFFSET = 28
TCG_VSEDT_OFFSET = 30
TCG_UIDX_OFFSET = 31
TCG_VSEDL_OFFSET = 32
TCG_COMMAND_COUNT = 36
TCG_INVOKING_ID = 40
TCG_METHOD_ID = 48
TCG_COM_ID = 56
TCG_PROTOCOL_ID = 58
TCG_STATUS = 59
TCG_PROCESS_TIME = 60
TCG_CONTEXT = 62
TCG_CONTEXT_LEN = 10

TCG_FIELDS = {
    'command_count': ('<I', TCG_COMMAND_COUNT),
    'invoking_id': ('<Q', TCG_INVOKING_ID),
    'method_id': ('<Q', TCG_METHOD_ID),
    'com_id': ('<H', TCG_COM_ID),
    'protocol_id': ('B', TCG_PROTOCOL_ID),
    'status': ('B', TCG_STATUS),
    'process_time': ('<H', TCG_PROCESS_TIME),
}


def _pack_fields(buf: bytearray, fields: dict, values: dict) -> None:
    for name, value in values.items():
        fmt, offset = fields[name]
        if isinstance(value, str):
            size = struct.calcsize(fmt)
            assert len(value) <= size, \
                f'{name} {value!r} is longer than {size} bytes'
            value = value.encode('ascii').ljust(size)
        struct.pack_into(fmt, buf, offset, value)


def pack_header(poh: int = 0, seb: bytes = b'', **values) -> bytes:
    """A 512 byte log header, zero but for @values (see HEADER_FIELDS),
    the 16 byte Power on Hours @poh and the Supported Events Bitmap
    @seb."""
    buf = bytearray(HEADER_SIZE)
    values.setdefault('lid', LID)
    _pack_fields(buf, HEADER_FIELDS, values)
    buf[POH:POH + POH_LEN] = poh.to_bytes(POH_LEN, 'little')
    buf[SEB:SEB + len(seb)] = seb
    return bytes(buf)


def pack_event(etype: int, data: bytes, vsi: bytes = b'',
               ehl: int = EVENT_HEADER_SIZE - EHL_UNCOUNTED,
               **values) -> bytes:
    """An event of @etype with the Vendor Specific Information @vsi and
    the event @data. The header fields are zero but for @values (see
    EVENT_HEADER_FIELDS); EL is the length of @vsi and @data."""
    buf = bytearray(EVENT_HEADER_SIZE)
    _pack_fields(buf, EVENT_HEADER_FIELDS,
                 dict(values, etype=etype, ehl=ehl))
    struct.pack_into('<HH', buf, VSIL, len(vsi), len(vsi) + len(data))
    return bytes(buf) + vsi + data


def pack_vs_desc(vsec: int, vsedt: int, data: bytes, uidx: int = 0) -> bytes:
    """A Vendor Specific Event Descriptor with its @data."""
    return struct.pack('<HBBH', vsec, vsedt, uidx, len(data)) + data


def pack_tcg_event(context: bytes = bytes(TCG_CONTEXT_LEN), uidx: int = 0,
                   vsec: int = TCG_VSEC, vsi: bytes = bytes(TCG_VSIL),
                   **values) -> bytes:
    """A 72 byte TCG Activity Event as TCGCE-1 to TCGCE-24 lay it out, with
    the TCG fields @values (see TCG_FIELDS) and the 10 byte @context.
    @vsec and @vsi are for events which are TCG-shaped, but not TCG
    Activity Events."""
    data = bytearray(TCG_VSEDL)
    base = TCG_VSEDL_OFFSET + 2
    for name, value in values.items():
        fmt, offset = TCG_FIELDS[name]
        struct.pack_into(fmt, data, offset - base, value)
    start = TCG_CONTEXT - base
    data[start:start + TCG_CONTEXT_LEN] = context
    event = pack_event(ETYPE_VENDOR_SPECIFIC,
                       pack_vs_desc(vsec, VSEDT_BINARY, bytes(data),
                                    uidx=uidx),
                       vsi=vsi, ehl=TCG_EHL, etype_rev=TCG_ETYPE_REV,
                       ehai=0x01)
    assert len(event) == TCG_EVENT_SIZE
    assert struct.unpack_from('<HH', event, VSIL) == (TCG_VSIL, TCG_EL)
    assert event[TCG_VSI:TCG_VSEC_OFFSET] == vsi
    assert struct.unpack_from('<H', event, TCG_VSEC_OFFSET)[0] == vsec
    assert event[TCG_VSEDT_OFFSET] == VSEDT_BINARY
    assert event[TCG_UIDX_OFFSET] == uidx
    assert struct.unpack_from('<H', event, TCG_VSEDL_OFFSET)[0] == TCG_VSEDL
    return event


def pack_timestamp_change(previous: int, ms_since_reset: int,
                          **values) -> bytes:
    """A Timestamp Change event: the Previous Timestamp and the
    Milliseconds Since Reset."""
    return pack_event(ETYPE_TIMESTAMP_CHANGE,
                      struct.pack('<QQ', previous, ms_since_reset), **values)


def pack_fw_commit(old_fw: bytes, new_fw: bytes, action: int, slot: int,
                   sct: int = 0, sc: int = 0, vu_rc: int = 0,
                   **values) -> bytes:
    """A Firmware Commit event: the 8 byte Old and New Firmware Revision,
    the Commit Action and Slot, the status of the Firmware Commit command
    and the Vendor Assigned Result Code."""
    return pack_event(ETYPE_FW_COMMIT,
                      struct.pack('<8s8sBBBBH', old_fw, new_fw, action, slot,
                                  sct, sc, vu_rc), **values)


def pack_log(events: Iterable[bytes] = (), **header) -> bytes:
    """A log of @events behind a header with the fields @header. TNEV and
    TLL count @events unless @header gives them."""
    events = list(events)
    body = b''.join(events)
    header.setdefault('tnev', len(events))
    header.setdefault('tll', HEADER_SIZE + len(body))
    return pack_header(**header) + body
