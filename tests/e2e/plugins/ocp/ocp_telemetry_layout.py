# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP telemetry log and the C9h Telemetry String Log.

`ocp internal-log -t host|controller` decodes a Telemetry Host- or
Controller-Initiated log (LID 07h/08h) whose Data Area 1 opens with the
OCP header -- statistics and event FIFO locations -- and resolves names
through the OCP Telemetry String Log (LID C9h). This module is the
reference the internal-log tests build fixtures from and decode against.
It is transcribed from the OCP Datacenter NVMe SSD specification's
telemetry and string log tables, deliberately *not* from the structs in
plugins/ocp/ocp-telemetry-decode.h, so a disagreement between the two
shows up as a test failure rather than being copied into the fixtures.

All start and size fields are Dword counts. Event FIFO and statistic
starts are relative to the start of the data area that holds them;
string log table starts are relative to byte 0 of the string log, and
ASCII string offsets to the start of the ASCII table.

The builders produce self-consistent images: every offset a header
field names lies inside the returned bytes. The decoder does not check
offsets against the file size, so a fixture that points past its own end
makes the test read out of bounds rather than fail cleanly.
"""

from __future__ import annotations

import struct
from typing import (Dict, Iterable, Iterator, List, Mapping, NamedTuple,
                    Optional, Sequence, Tuple, Union)

DWORD = 4
BLOCK_SIZE = 512

LID_TELEMETRY_HOST = 0x07
LID_TELEMETRY_CTRL = 0x08
LID_STRING_LOG = 0xC9

# Telemetry log header (NVMe base specification).
HEADER_SIZE = 512
HDR_LID = 0
HDR_IEEE_OUI = 5
HDR_DALB1 = 8
HDR_DALB2 = 10
HDR_DALB3 = 12
HDR_DALB4 = 16
HDR_BYTE_380 = 380
HDR_BYTE_381 = 381
HDR_BYTE_382 = 382
HDR_BYTE_383 = 383
HDR_REASON_ID = 384
REASON_ERROR_ID = 0
REASON_FILE_ID = 64
REASON_LINE_NUMBER = 72
REASON_VALID_FLAGS = 74
REASON_VU_EXTENSION = 96

# OCP header at the start of Data Area 1, offsets relative to Data Area 1.
DA1_START = HEADER_SIZE
DA1_MAJOR_VERSION = 0
DA1_MINOR_VERSION = 2
DA1_TIMESTAMP = 8
DA1_LOG_PAGE_GUID = 16
DA1_PROFILES_SUPPORTED = 32
DA1_PROFILE_SELECTED = 33
DA1_STRING_LOG_SIZE = 40
DA1_FIRMWARE_REVISION = 56
DA1_STAT_START = 96
DA1_STAT_SIZE = 104
DA2_STAT_START = 112
DA2_STAT_SIZE = 120
DA1_FIFO_DA = 160
DA1_FIFO_OFFSETS = 176
FIFO_OFFSET_ENTRY = 16
DA1_SMART = 512
DA1_SMART_EXTENDED = 1024
DA1_HEADER_SIZE = 1536
MAX_FIFOS = 16

# C9h Telemetry String Log header.
STR_VERSION = 0
STR_GUID = 16
STR_LOG_SIZE = 32
STR_SITS = 64
STR_SITSZ = 72
STR_ESTS = 80
STR_ESTSZ = 88
STR_VU_ESTS = 96
STR_VU_ESTSZ = 104
STR_ASCTS = 112
STR_ASCTSZ = 120
STR_FIFO_NAMES = 128
FIFO_NAME_LEN = 16
STR_HEADER_SIZE = 432
STR_ENTRY_SIZE = 16
MAX_ASCII_LEN = 255

# Statistic Identifier String Table entry: id, reserved, length, offset,
# reserved. Event and VU Event String Table entry: class, id, length,
# offset, reserved.
_SITS_ENTRY = '<HBBQI'
_EST_ENTRY = '<BHBQI'
_STAT_DESCRIPTOR = '<HBBHH'
_EVENT_DESCRIPTOR = '<BHB'
STAT_DESCRIPTOR_SIZE = struct.calcsize(_STAT_DESCRIPTOR)
EVENT_DESCRIPTOR_SIZE = struct.calcsize(_EVENT_DESCRIPTOR)

# Debug event classes.
CLASS_END = 0x00
CLASS_TIMESTAMP = 0x01
CLASS_PCIE = 0x02
CLASS_NVME = 0x03
CLASS_RESET = 0x04
CLASS_BOOT_SEQUENCE = 0x05
CLASS_FIRMWARE_ASSERT = 0x06
CLASS_TEMPERATURE = 0x07
CLASS_MEDIA = 0x08
CLASS_MEDIA_WEAR = 0x09
CLASS_STATISTIC_SNAPSHOT = 0x0A
CLASS_VIRTUAL_FIFO = 0x0B
CLASS_SMBUS_I2C_I3C = 0x0C
CLASS_MCTP = 0x0D
CLASS_VU_FIRST = 0x80

# Bytes of class specific data ahead of any VU Event Identifier.
CLASS_SPECIFIC_SIZE = {
    CLASS_TIMESTAMP: 8,
    CLASS_PCIE: 4,
    CLASS_NVME: 8,
    CLASS_MEDIA_WEAR: 12,
}
COMMON_CLASSES = (CLASS_RESET, CLASS_BOOT_SEQUENCE, CLASS_FIRMWARE_ASSERT,
                  CLASS_TEMPERATURE, CLASS_MEDIA)

# VU Virtual FIFO Identifier: bits 15:11 physical Event FIFO, 10:0 virtual
# FIFO within it.
VIRTUAL_FIFO_PHY_SHIFT = 11
VIRTUAL_FIFO_PHY_MAX = 0x1F
VIRTUAL_FIFO_MASK = 0x7FF

# Fixed records of the SMBUS/I2C/I3C (0Ch) and MCTP (0Dh) classes, ahead of
# their optional VU fields.
SMBUS_EVENT_SIZE = 4
MCTP_EVENT_SIZE = 8

# SMBUS/I2C/I3C Event ID whose Event Data values are defined.
SMBUS_NACK_ERROR = 0x0003

# MCTP Event Flags bit 7: MCTP Transport Header Valid.
MCTP_HEADER_VALID = 0x80

# Statistic Information (descriptor byte 2) bit 6: set only in a Context
# Statistic Descriptor.
STAT_INFO_CONTEXT_INDEX = 0x40

# Context Statistic Descriptors: Statistic Specific Data opens with a
# Context Data Size Dword count and the context fields, then the
# encapsulated Statistic Descriptors.
STAT_NAMESPACE_ID_CONTEXT = 0x6D
STAT_CONTROLLER_ID_CONTEXT = 0x6E
STAT_QUEUE_ID_CONTEXT = 0x6F
CONTEXT_DATA_DWORDS = 2

Name = Union[str, bytes]
EventStrings = Mapping[Tuple[int, int], Name]


def _pad(data: bytes) -> bytes:
    return data + bytes(-len(data) % DWORD)


def _ascii(name: Name) -> bytes:
    return name.encode('ascii') if isinstance(name, str) else bytes(name)


def hex_upper(data: bytes) -> str:
    """Render @data the way the decoder prints variable-size fields."""
    return data.hex().upper()


def event(cls: int, event_id: int = 0, data: bytes = b'',
          size_dw: Optional[int] = None) -> bytes:
    """One event: the 4-byte descriptor, then @data padded to Dwords.

    @size_dw overrides the Event Data Size the descriptor declares without
    changing how many bytes follow it."""
    data = _pad(data)
    if size_dw is None:
        size_dw = len(data) // DWORD
    return struct.pack(_EVENT_DESCRIPTOR, cls, event_id, size_dw) + data


def vu_part(vu_event_id: int, data: bytes = b'') -> bytes:
    """VU Event Identifier followed by VU data, as it trails class data."""
    return struct.pack('<H', vu_event_id) + data


def virtual_fifo_id(physical: int, virtual: int) -> int:
    if not 0 <= physical <= VIRTUAL_FIFO_PHY_MAX:
        raise ValueError(f'physical FIFO {physical} does not fit 5 bits')
    if not 0 <= virtual <= VIRTUAL_FIFO_MASK:
        raise ValueError(f'virtual FIFO {virtual} does not fit 11 bits')
    return (physical << VIRTUAL_FIFO_PHY_SHIFT) | virtual


def virtual_fifo_event(fifo_id: int, event_id: int = 0, reserved: int = 0,
                       extra: bytes = b'',
                       size_dw: Optional[int] = None) -> bytes:
    """A Virtual FIFO event (0Bh): identifier and reserved half-word, plus
    @extra bytes beyond the one Dword the class defines."""
    return event(CLASS_VIRTUAL_FIFO, event_id,
                 struct.pack('<HH', fifo_id, reserved) + extra, size_dw)


def smbus_event(event_id: int = 0, event_data: int = 0, reserved: int = 0,
                vu: bytes = b'', size_dw: Optional[int] = None) -> bytes:
    """A SMBUS/I2C/I3C event (0Ch):

      Bytes 5:4   SMBUS Debug Event Data
      Bytes 7:6   Reserved
      Bytes 9:8   VU Event Identifier  } present when Event Data Size > 1,
      Bytes 10..  VU Data              } as @vu (see vu_part())"""
    return event(CLASS_SMBUS_I2C_I3C, event_id,
                 struct.pack('<HH', event_data, reserved) + vu, size_dw)


def mctp_event(event_id: int = 0, event_data: int = 0, protocol: int = 0,
               flags: int = 0, header: bytes = bytes(4), vu: bytes = b'',
               size_dw: Optional[int] = None) -> bytes:
    """An MCTP event (0Dh):

      Bytes 5:4   MCTP Debug Event Data
      Byte  6     MCTP Transport Protocol Information
      Byte  7     MCTP Event Flags (bit 7 Transport Header Valid)
      Bytes 11:8  MCTP Transport Header, @header as captured
      Bytes 13:12 VU Event Identifier  } present when Event Data Size > 2,
      Bytes 14..  VU Data              } as @vu (see vu_part())"""
    if len(header) != 4:
        raise ValueError('the MCTP Transport Header is 4 bytes')
    return event(CLASS_MCTP, event_id,
                 struct.pack('<HBB', event_data, protocol, flags) + header
                 + vu, size_dw)


def statistic(stat_id: int, data: bytes = b'', behavior: int = 0,
              info_reserved: int = 0, nsid: int = 0, ns_valid: bool = False,
              nsid_15_0: int = 0, context_index: bool = False,
              host_hint: int = 0) -> bytes:
    """One statistic: the 8-byte descriptor, then @data padded to Dwords.

    Statistic Information holds @behavior in bits 3:0, @host_hint in
    bits 5:4, @context_index in bit 6 and @info_reserved in bit 7.
    @nsid_15_0 fills bytes 7:6, Namespace Identifier[15:0]."""
    data = _pad(data)
    info = ((behavior & 0xF) | ((host_hint & 0x3) << 4)
            | ((info_reserved & 0x1) << 7))
    if context_index:
        info |= STAT_INFO_CONTEXT_INDEX
    return struct.pack(_STAT_DESCRIPTOR, stat_id, info,
                       (nsid & 0x7F) | (0x80 if ns_valid else 0),
                       len(data) // DWORD, nsid_15_0) + data


def context_data(scope: bytes, context_data_size: int = CONTEXT_DATA_DWORDS,
                 reserved: int = 0) -> bytes:
    """Context data: Context Data Size, reserved, then the 4-byte scope."""
    if len(scope) != 4:
        raise ValueError('the context scope is 4 bytes')
    return struct.pack('<HH', context_data_size, reserved) + scope


def namespace_id_context(nsid: int,
                         context_data_size: int = CONTEXT_DATA_DWORDS
                         ) -> bytes:
    """Namespace ID Context (6Dh) data: size, reserved, 32-bit NSID."""
    return context_data(struct.pack('<I', nsid), context_data_size)


def controller_id_context(cntlid: int,
                          context_data_size: int = CONTEXT_DATA_DWORDS
                          ) -> bytes:
    """Controller ID Context (6Eh) data: size, 4 reserved bytes, CNTLID."""
    return context_data(struct.pack('<HH', 0, cntlid), context_data_size)


def queue_id_context(cntlid: int, qid: int,
                     context_data_size: int = CONTEXT_DATA_DWORDS) -> bytes:
    """Queue ID Context (6Fh) data: size, reserved, CNTLID, queue ID."""
    return context_data(struct.pack('<HH', cntlid, qid), context_data_size)


def context_statistic(stat_id: int, context: bytes,
                      encapsulated: Iterable[bytes] = (),
                      **kwargs) -> bytes:
    """A Context Statistic Descriptor: @context data, then the
    @encapsulated Statistic Descriptors. Its own Statistic Data Size spans
    both, and its namespace fields stay cleared unless @kwargs set them
    along with any other statistic() field."""
    kwargs.setdefault('context_index', True)
    return statistic(stat_id, context + b''.join(encapsulated), **kwargs)


def statistic_snapshot_event(stat: bytes, event_id: int = 0) -> bytes:
    """A Statistic Snapshot event (0Ah) carrying one statistic."""
    return event(CLASS_STATISTIC_SNAPSHOT, event_id, stat)


class Fifo(NamedTuple):
    """One event FIFO for pack_telemetry().

    @events is placed at @start_dw (Dwords into data area @da), or after
    the previous content of that area when None. The FIFO's declared
    size is @size_dw, or the events plus @pad_dw zero Dwords when None.
    A @da other than 1 or 2 still places the events in Data Area 1."""

    da: int
    events: Sequence[bytes] = ()
    start_dw: Optional[int] = None
    size_dw: Optional[int] = None
    pad_dw: int = 0


def _blocks(length: int) -> int:
    return -(-length // BLOCK_SIZE)


def _put(area: bytearray, offset: int, data: bytes) -> None:
    end = offset + len(data)
    if end > len(area):
        area.extend(bytes(end - len(area)))
    area[offset:end] = data


def pack_telemetry(lid: int = LID_TELEMETRY_HOST,
                   fifos: Optional[Mapping[int, Fifo]] = None,
                   da1_stats: Iterable[bytes] = (),
                   da2_stats: Iterable[bytes] = (),
                   da1_blocks: Optional[int] = None,
                   da2_blocks: Optional[int] = None,
                   overlay: Optional[Mapping[int, bytes]] = None) -> bytes:
    """Build a telemetry log image covering Data Areas 1 and 2.

    @fifos maps the 1-based FIFO number to its Fifo. Statistics come
    first in their data area, FIFOs follow in FIFO number order. The data
    area last blocks are sized to fit (or fixed by @da1_blocks and
    @da2_blocks, counted per area), DA3 and DA4 end where DA2 does, and
    @overlay then writes raw bytes at absolute offsets."""
    fifos = dict(fifos or {})
    overlay = dict(overlay or {})
    da1 = bytearray(DA1_HEADER_SIZE)
    da2 = bytearray()

    # Each statistic start/size pair is one le64 start and one le64 size.
    for area, stats, start_field in ((da1, da1_stats, DA1_STAT_START),
                                     (da2, da2_stats, DA2_STAT_START)):
        blob = b''.join(stats)
        if blob:
            start = len(area)
            _put(area, start, blob)
            struct.pack_into('<QQ', da1, start_field, start // DWORD,
                             len(blob) // DWORD)

    for number in sorted(fifos):
        if not 1 <= number <= MAX_FIFOS:
            raise ValueError(f'FIFO number {number} is not 1..{MAX_FIFOS}')
        fifo = fifos[number]
        area = da2 if fifo.da == 2 else da1
        body = b''.join(fifo.events)
        if len(body) % DWORD:
            raise ValueError(f'FIFO {number} events are not Dword aligned')
        start_dw = (len(area) // DWORD if fifo.start_dw is None
                    else fifo.start_dw)
        _put(area, start_dw * DWORD, body + bytes(fifo.pad_dw * DWORD))
        size_dw = (len(body) // DWORD + fifo.pad_dw if fifo.size_dw is None
                   else fifo.size_dw)
        da1[DA1_FIFO_DA + number - 1] = fifo.da
        struct.pack_into('<QQ', da1,
                         DA1_FIFO_OFFSETS + (number - 1) * FIFO_OFFSET_ENTRY,
                         start_dw, size_dw)

    blocks1 = _blocks(len(da1)) if da1_blocks is None else da1_blocks
    blocks2 = _blocks(len(da2)) if da2_blocks is None else da2_blocks
    if len(da1) > blocks1 * BLOCK_SIZE or len(da2) > blocks2 * BLOCK_SIZE:
        raise ValueError('content does not fit the requested data areas')
    da1.extend(bytes(blocks1 * BLOCK_SIZE - len(da1)))
    da2.extend(bytes(blocks2 * BLOCK_SIZE - len(da2)))

    header = bytearray(HEADER_SIZE)
    header[HDR_LID] = lid
    dalb1 = blocks1
    dalb2 = blocks1 + blocks2
    struct.pack_into('<HHH', header, HDR_DALB1, dalb1, dalb2, dalb2)
    struct.pack_into('<I', header, HDR_DALB4, dalb2)

    image = bytearray(header + da1 + da2)
    for offset, data in overlay.items():
        if offset + len(data) > len(image):
            raise ValueError(f'overlay at {offset} runs past the image')
        image[offset:offset + len(data)] = data
    return bytes(image)


def pack_string_log(fifo_names: Optional[Mapping[int, Name]] = None,
                    stat_strings: Optional[Mapping[int, Name]] = None,
                    event_strings: Optional[EventStrings] = None,
                    vu_event_strings: Optional[EventStrings] = None,
                    overlay: Optional[Mapping[int, bytes]] = None) -> bytes:
    """Build a C9h string log.

    @fifo_names maps the 1-based FIFO number to its name (at most 16
    characters). @stat_strings maps a statistic identifier, and
    @event_strings / @vu_event_strings a (debug event class, identifier)
    pair, to its ASCII string. The four tables follow the 432-byte
    header back to back, the way a controller lays them out and the
    fetch path assumes."""
    fifo_names = dict(fifo_names or {})
    header = bytearray(STR_HEADER_SIZE)
    ascii_table = bytearray()

    def add_ascii(name: Name) -> Tuple[int, int]:
        raw = _ascii(name)
        if not 1 <= len(raw) <= MAX_ASCII_LEN:
            raise ValueError(f'string {raw!r} is not 1..{MAX_ASCII_LEN} '
                             'bytes')
        offset_dw = len(ascii_table) // DWORD
        ascii_table.extend(_pad(raw))
        return len(raw) - 1, offset_dw

    sits = bytearray()
    for stat_id, name in (stat_strings or {}).items():
        length, offset_dw = add_ascii(name)
        sits += struct.pack(_SITS_ENTRY, stat_id, 0, length, offset_dw, 0)
    ests = bytearray()
    for (cls, ident), name in (event_strings or {}).items():
        length, offset_dw = add_ascii(name)
        ests += struct.pack(_EST_ENTRY, cls, ident, length, offset_dw, 0)
    vu_ests = bytearray()
    for (cls, ident), name in (vu_event_strings or {}).items():
        length, offset_dw = add_ascii(name)
        vu_ests += struct.pack(_EST_ENTRY, cls, ident, length, offset_dw, 0)

    cursor = STR_HEADER_SIZE
    for start_field, table in ((STR_SITS, sits), (STR_ESTS, ests),
                               (STR_VU_ESTS, vu_ests),
                               (STR_ASCTS, ascii_table)):
        struct.pack_into('<QQ', header, start_field, cursor // DWORD,
                         len(table) // DWORD)
        cursor += len(table)
    struct.pack_into('<Q', header, STR_LOG_SIZE, cursor // DWORD)

    for number, name in fifo_names.items():
        raw = _ascii(name)
        if not 1 <= number <= MAX_FIFOS or len(raw) > FIFO_NAME_LEN:
            raise ValueError(f'bad FIFO name {number}: {raw!r}')
        offset = STR_FIFO_NAMES + (number - 1) * FIFO_NAME_LEN
        header[offset:offset + len(raw)] = raw

    image = bytearray(header + sits + ests + vu_ests + ascii_table)
    for offset, data in (overlay or {}).items():
        if offset + len(data) > len(image):
            raise ValueError(f'overlay at {offset} runs past the image')
        image[offset:offset + len(data)] = data
    return bytes(image)


# Decoders, for checking what a real drive returned.

def _u(buf: bytes, offset: int, size: int) -> int:
    return int.from_bytes(buf[offset:offset + size], 'little')


def data_area_last_blocks(telemetry: bytes) -> Tuple[int, int, int, int]:
    return (_u(telemetry, HDR_DALB1, 2), _u(telemetry, HDR_DALB2, 2),
            _u(telemetry, HDR_DALB3, 2), _u(telemetry, HDR_DALB4, 4))


def data_area_span(telemetry: bytes, da: int) -> Tuple[int, int]:
    """(absolute start, length) of Data Area @da (1 or 2)."""
    dalb1, dalb2, _, _ = data_area_last_blocks(telemetry)
    if da == 1:
        return DA1_START, dalb1 * BLOCK_SIZE
    if da == 2:
        return DA1_START + dalb1 * BLOCK_SIZE, (dalb2 - dalb1) * BLOCK_SIZE
    raise ValueError(f'data area {da} carries no OCP event FIFOs')


class FifoEntry(NamedTuple):
    number: int
    da: int
    start_dw: int
    size_dw: int


def fifo_table(telemetry: bytes) -> List[FifoEntry]:
    """All 16 event FIFO descriptors from the Data Area 1 header."""
    entries = []
    for i in range(MAX_FIFOS):
        base = DA1_START + DA1_FIFO_OFFSETS + i * FIFO_OFFSET_ENTRY
        entries.append(FifoEntry(i + 1,
                                 telemetry[DA1_START + DA1_FIFO_DA + i],
                                 _u(telemetry, base, 8),
                                 _u(telemetry, base + 8, 8)))
    return entries


def fifo_bytes(telemetry: bytes, entry: FifoEntry) -> bytes:
    start, _ = data_area_span(telemetry, entry.da)
    offset = start + entry.start_dw * DWORD
    return telemetry[offset:offset + entry.size_dw * DWORD]


class Event(NamedTuple):
    offset: int
    cls: int
    event_id: int
    size_dw: int
    data: bytes


def iter_events(fifo: bytes) -> Iterator[Event]:
    """Walk one event FIFO up to its end or its first class 00h entry.

    A Statistic Snapshot event (0Ah) spans its descriptor plus the whole
    statistic it carries, whatever its own Event Data Size says."""
    offset = 0
    while offset + EVENT_DESCRIPTOR_SIZE <= len(fifo):
        cls, event_id, size_dw = struct.unpack_from(_EVENT_DESCRIPTOR, fifo,
                                                    offset)
        if cls == CLASS_END:
            return
        if cls == CLASS_STATISTIC_SNAPSHOT:
            stat_size_dw = _u(fifo, offset + 8, 2)
            length = EVENT_DESCRIPTOR_SIZE + STAT_DESCRIPTOR_SIZE + \
                stat_size_dw * DWORD
        else:
            length = EVENT_DESCRIPTOR_SIZE + size_dw * DWORD
        yield Event(offset, cls, event_id, size_dw,
                    fifo[offset + EVENT_DESCRIPTOR_SIZE:offset + length])
        offset += length


class Statistic(NamedTuple):
    stat_id: int
    size_dw: int
    context_index: bool
    data: bytes
    encapsulated: Tuple['Statistic', ...] = ()


def is_context_statistic(stat_id: int, context_index: bool) -> bool:
    """A Context Statistic Descriptor is flagged by Statistic Information
    bit 6; 6Dh-6Fh are one whatever the flag says."""
    return context_index or (STAT_NAMESPACE_ID_CONTEXT <= stat_id
                             <= STAT_QUEUE_ID_CONTEXT)


def _walk_statistics(area: bytes, nested: bool) -> Iterator[Statistic]:
    offset = 0
    while offset + STAT_DESCRIPTOR_SIZE <= len(area):
        stat_id, info, _, size_dw, _ = struct.unpack_from(_STAT_DESCRIPTOR,
                                                          area, offset)
        start = offset + STAT_DESCRIPTOR_SIZE
        end = start + size_dw * DWORD
        if stat_id == 0 or end > len(area):
            return
        context_index = bool(info & STAT_INFO_CONTEXT_INDEX)
        data = area[start:end]
        encapsulated: Tuple[Statistic, ...] = ()
        if (not nested and is_context_statistic(stat_id, context_index)
                and size_dw >= CONTEXT_DATA_DWORDS):
            encapsulated = tuple(_walk_statistics(
                data[CONTEXT_DATA_DWORDS * DWORD:], True))
        yield Statistic(stat_id, size_dw, context_index, data, encapsulated)
        offset = end


def iter_statistics(telemetry: bytes, da: int) -> Iterator[Statistic]:
    """Walk the statistics of Data Area @da (1 or 2) as the OCP header
    places them, up to their declared size or the first identifier 0.

    A Context Statistic Descriptor's encapsulated descriptors come out
    in its @encapsulated; they do not nest further."""
    start_field, size_field = ((DA1_STAT_START, DA1_STAT_SIZE) if da == 1
                               else (DA2_STAT_START, DA2_STAT_SIZE))
    start = (data_area_span(telemetry, da)[0]
             + _u(telemetry, DA1_START + start_field, 8) * DWORD)
    size = _u(telemetry, DA1_START + size_field, 8) * DWORD
    return _walk_statistics(telemetry[start:start + size], False)


def split_virtual_fifo_id(fifo_id: int) -> Tuple[int, int]:
    return fifo_id >> VIRTUAL_FIFO_PHY_SHIFT, fifo_id & VIRTUAL_FIFO_MASK


def string_log_length(strings: bytes) -> int:
    """Length the header's table sizes add up to past the 432-byte header."""
    sizes = sum(_u(strings, field, 8) for field in
                (STR_SITSZ, STR_ESTSZ, STR_VU_ESTSZ, STR_ASCTSZ))
    return STR_HEADER_SIZE + sizes * DWORD


def fifo_names(strings: bytes) -> Dict[int, str]:
    """FIFO number to name, each cut at its first NUL."""
    names = {}
    for i in range(MAX_FIFOS):
        offset = STR_FIFO_NAMES + i * FIFO_NAME_LEN
        raw = strings[offset:offset + FIFO_NAME_LEN].split(b'\0', 1)[0]
        names[i + 1] = raw.decode('ascii', 'replace')
    return names


class StringTables(NamedTuple):
    statistics: Dict[int, str]
    events: Dict[Tuple[int, int], str]
    vu_events: Dict[Tuple[int, int], str]


def string_tables(strings: bytes) -> StringTables:
    """Decode the three identifier tables. Where an identifier repeats,
    the first entry wins, matching a front-to-back table search."""
    ascii_start = _u(strings, STR_ASCTS, 8) * DWORD

    def text(length: int, offset_dw: int) -> str:
        start = ascii_start + offset_dw * DWORD
        raw = strings[start:start + min(length + 1, MAX_ASCII_LEN)]
        return raw.split(b'\0', 1)[0].decode('ascii', 'replace')

    def entries(start_field, size_field, fmt):
        start = _u(strings, start_field, 8) * DWORD
        count = _u(strings, size_field, 8) * DWORD // STR_ENTRY_SIZE
        for i in range(count):
            yield struct.unpack_from(fmt, strings, start + i * STR_ENTRY_SIZE)

    stats: Dict[int, str] = {}
    for stat_id, _, length, offset_dw, _ in entries(STR_SITS, STR_SITSZ,
                                                    _SITS_ENTRY):
        stats.setdefault(stat_id, text(length, offset_dw))
    events: Dict[Tuple[int, int], str] = {}
    for cls, ident, length, offset_dw, _ in entries(STR_ESTS, STR_ESTSZ,
                                                    _EST_ENTRY):
        events.setdefault((cls, ident), text(length, offset_dw))
    vu_events: Dict[Tuple[int, int], str] = {}
    for cls, ident, length, offset_dw, _ in entries(STR_VU_ESTS, STR_VU_ESTSZ,
                                                    _EST_ENTRY):
        vu_events.setdefault((cls, ident), text(length, offset_dw))
    return StringTables(stats, events, vu_events)


def _check_layout() -> None:
    """Guard the invariants the builders rely on."""
    if STAT_DESCRIPTOR_SIZE != 8 or EVENT_DESCRIPTOR_SIZE != 4:
        raise AssertionError('descriptor sizes disagree with the spec')
    for fmt in (_SITS_ENTRY, _EST_ENTRY):
        if struct.calcsize(fmt) != STR_ENTRY_SIZE:
            raise AssertionError(f'{fmt} is not a 16-byte table entry')
    if DA1_FIFO_OFFSETS + MAX_FIFOS * FIFO_OFFSET_ENTRY > DA1_SMART:
        raise AssertionError('FIFO offset table overruns the OCP header')
    if DA1_FIFO_DA + MAX_FIFOS > DA1_FIFO_OFFSETS:
        raise AssertionError('FIFO data area bytes overlap the offsets')
    if STR_FIFO_NAMES + MAX_FIFOS * FIFO_NAME_LEN > STR_HEADER_SIZE:
        raise AssertionError('FIFO names overrun the string log header')
    if STR_HEADER_SIZE % DWORD or DA1_HEADER_SIZE % DWORD:
        raise AssertionError('table starts must be Dword aligned')


_check_layout()
