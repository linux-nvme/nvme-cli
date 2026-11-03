# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C3h Latency Monitor log page.

This is the reference the latency-monitor-log tests build pages from and
decode against. It is transcribed from the OCP Datacenter NVMe SSD
specification's LMDATA field table, deliberately *not* from
`struct ssd_latency_monitor_log`, so a disagreement between the two shows
up as a test failure.

The Latency Monitor Feature Status (LMDATA-1) bits 2:0 are defined in
every version, from log page version 1 (OCP 2.0). Version 5 (OCP 2.7)
adds Host Initiated Telemetry Format Supported in bit 3. Bytes 4095:512
are reserved (LMDATA-38). The Latency Monitor Debug Telemetry Log Size
(LMDATA-37) is there from version 4 (OCP 2.5).

The Latency Stamps and Measured Latencies list bucket 0 Read at the
highest address and bucket 3 Trim at the lowest. A Latency Stamp has the
NVMe Timestamp format: the timestamp in milliseconds in bytes 5:0, the
Synch and Timestamp Origin attributes in byte 6. All-FF marks it not
valid. A Stamp Units bit cleared to 0b means its stamp counts from power
on rather than from an NVMe Timestamp (LMDATA-18, -26, -33).
"""

from __future__ import annotations

import struct

LID = 0xC3
LOG_PAGE_SIZE = 4096
# The part of the page holding fields.
DEFINED_SIZE = 512

FEATURE_STATUS = 0
ACTIVE_BUCKET_TIMER = 2
ACTIVE_BUCKET_TIMER_THRESHOLD = 4
ACTIVE_THRESHOLD_A = 6
ACTIVE_THRESHOLD_B = 7
ACTIVE_THRESHOLD_C = 8
ACTIVE_THRESHOLD_D = 9
ACTIVE_LATENCY_CONFIG = 10
ACTIVE_LATENCY_MIN_WINDOW = 12
ACTIVE_BUCKET_COUNTER = 32
ACTIVE_LATENCY_STAMP = 96
ACTIVE_MEASURED_LATENCY = 192
ACTIVE_LATENCY_STAMP_UNITS = 216
STATIC_BUCKET_COUNTER = 240
STATIC_LATENCY_STAMP = 304
STATIC_MEASURED_LATENCY = 400
STATIC_LATENCY_STAMP_UNITS = 424
DEBUG_TELEMETRY_LOG_SIZE = 436
DEBUG_TELEMETRY_LOG_SIZE_LEN = 12
DEBUG_LOG_TRIGGER_ENABLE = 448
DEBUG_LOG_MEASURED_LATENCY = 450
DEBUG_LOG_LATENCY_STAMP = 452
DEBUG_LOG_POINTER = 460
DEBUG_COUNTER_TRIGGER_SOURCE = 462
DEBUG_LOG_STAMP_UNITS = 464
LOG_PAGE_VERSION = 494
LOG_PAGE_GUID = 496

DEBUG_TELEMETRY_LOG_SIZE_VERSION = 4

BUCKETS = 4
COUNTERS = ('Read', 'Write', 'Trim')
# Bucket Counter dword offsets; the dword at 0 is reserved.
COUNTER_OFFSET = {'Read': 12, 'Write': 8, 'Trim': 4}
BUCKET_COUNTER_SIZE = 16

INVALID_STAMP = 0xFFFF_FFFF_FFFF_FFFF

# LMDATA-1 bits.
LMFE = 1 << 0
ALCALM1S = 1 << 1
AMLS = 1 << 2
HITFS = 1 << 3          # version 5

HITFS_VERSION = 5

# LMDATA-36, 85D45E58D4E643709C6C84D08CC07A92h, on the wire.
GUID_BYTES = bytes.fromhex('85D45E58D4E643709C6C84D08CC07A92')[::-1]


def pack(version: int = 5, feature_status: int = 0x07,
         guid: bytes = GUID_BYTES) -> bytes:
    """A C3h page reporting log page @version with the LMDATA-1 Feature
    Status @feature_status. The default is version 5 (LMDATA-35) with its
    default status, 07h. The Debug Log Pointer is CAh (LMDATA-31)."""
    page = bytearray(LOG_PAGE_SIZE)
    page[FEATURE_STATUS] = feature_status
    struct.pack_into('<H', page, DEBUG_LOG_POINTER, 0xCA)
    struct.pack_into('<H', page, LOG_PAGE_VERSION, version)
    page[LOG_PAGE_GUID:LOG_PAGE_GUID + len(guid)] = guid
    return bytes(page)


def _counter_index(bucket: int, counter: str) -> int:
    return 3 * bucket + COUNTERS.index(counter)


def bucket_counter(base: int, bucket: int, counter: str) -> int:
    """Offset of the 4-byte @counter of @bucket in the Bucket Counters at
    @base (LMDATA-12 to -15, -20 to -23)."""
    return base + BUCKET_COUNTER_SIZE * bucket + COUNTER_OFFSET[counter]


def latency_stamp(base: int, bucket: int, counter: str) -> int:
    """Offset of the 8-byte Latency Stamp of @counter of @bucket in the
    Latency Stamps at @base (LMDATA-16, -24)."""
    return base + 8 * (11 - _counter_index(bucket, counter))


def measured_latency(base: int, bucket: int, counter: str) -> int:
    """Offset of the 2-byte Measured Latency of @counter of @bucket in the
    Measured Latencies at @base (LMDATA-17, -25)."""
    return base + 2 * (11 - _counter_index(bucket, counter))


def stamp_unit_bit(bucket: int, counter: str) -> int:
    """The Stamp Units bit of @counter of @bucket (LMDATA-18, -26)."""
    return 1 << _counter_index(bucket, counter)


def stamp(ms: int, attributes: int = 0) -> int:
    """A Latency Stamp of @ms milliseconds with the NVMe Timestamp
    @attributes (bit 0 Synch, bits 3:1 Timestamp Origin)."""
    return (ms & 0xFFFF_FFFF_FFFF) | (attributes & 0xFF) << 48
