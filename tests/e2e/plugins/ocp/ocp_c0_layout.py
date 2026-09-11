# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
"""Byte layout of the OCP C0 SMART / Health Information Extended log page.

This is the reference the smart-add-log tests decode against, so it is
transcribed from the OCP Datacenter NVMe SSD specification's C0 (SCAO)
field table -- deliberately *not* from `struct ocp_smart_extended_log`.

The split matters when updating this file:

  * `offset`, `size`, `kind` and `min_version` come from the spec. If
    they disagree with the C struct or with the version gating in the
    printers, that is a finding to report, not a discrepancy to edit
    away here.
  * `stdout_label`, `v1_key` and `v2_key` are nvme-cli's own output
    names, which no spec dictates. Those are taken from the printers in
    plugins/ocp/ocp-print-{stdout,json}.c and are expected to track
    them.

`kind` describes how a field is encoded on the wire *and* how the
printers render it:

  u8/le16/le32/le64  little-endian unsigned integers
  u48/u56            little-endian unsigned integers of 6 and 7 bytes
                     (int48_to_long()/int56_to_long() in shared/int-util.c)
  u128hilo           128-bit counter both JSON printers split into a
                     nested {"hi", "lo"} object, and stdout prints as one
                     decimal number
  u128dec            128-bit counter printed as a single decimal number
                     everywhere (json-c emits it unquoted via
                     util_json_object_new_uint128())
  ascii              fixed-length ASCII buffer, NUL- or space-padded
  uuid               16 raw bytes rendered as a hyphenated UUID
  guid               16 raw bytes rendered as one "0x..." hex literal
"""

from __future__ import annotations

from typing import Any, Dict, NamedTuple, Optional, Sequence, Tuple

LOG_PAGE_SIZE = 512

# scao_guid in plugins/ocp/ocp-smart-extended-log.c, on the wire.
SCAO_GUID_BYTES = bytes((
    0xC5, 0xAF, 0x10, 0x28,
    0xEA, 0xBF, 0xF2, 0xA4,
    0x9C, 0x4F, 0x6F, 0x7C,
    0xC9, 0x14, 0xD5, 0xAF,
))

# ocp_uuid in plugins/ocp/ocp-utils.c: the vendor UUID whose index in the
# drive's UUID list goes into CDW14[6:0] of the Get Log Page command.
OCP_UUID = bytes((
    0xC1, 0x94, 0xD5, 0x5B, 0xE0, 0x94, 0x47, 0x94, 0xA2, 0x1D,
    0x29, 0x99, 0x8F, 0x56, 0xBE, 0x6F,
))

# Highest log page version the printers distinguish. Their switch
# statements group `default:` with `case 6`, so anything above this is
# rendered as version 6.
MAX_LOG_PAGE_VERSION = 6


class C0Field(NamedTuple):
    """One field of the C0 log page.

    @name is this module's identifier for the field, not an output name.
    @min_version is the lowest log page version at which the printers
    emit the field; 0 means unconditionally. A printer that legitimately
    omits the field carries None for its label/key.
    """

    name: str
    offset: int
    size: int
    kind: str
    min_version: int
    stdout_label: Optional[str]
    v1_key: Optional[str]
    v2_key: Optional[str]


# Spec byte-offset order. Reserved ranges are simply absent.
FIELDS: Tuple[C0Field, ...] = (
    C0Field('physical_media_units_written', 0, 16, 'u128hilo', 0,
            'Physical media units written -',
            'Physical media units written',
            'physical_media_units_written'),
    C0Field('physical_media_units_read', 16, 16, 'u128hilo', 0,
            'Physical media units read    -',
            'Physical media units read',
            'physical_media_units_read'),
    C0Field('bad_user_nand_blocks_raw', 32, 6, 'u48', 0,
            'Bad user nand blocks - Raw',
            'Bad user nand blocks - Raw',
            'bad_user_nand_blocks_raw'),
    C0Field('bad_user_nand_blocks_normalized', 38, 2, 'le16', 0,
            'Bad user nand blocks - Normalized',
            'Bad user nand blocks - Normalized',
            'bad_user_nand_blocks_normalized'),
    C0Field('bad_system_nand_blocks_raw', 40, 6, 'u48', 0,
            'Bad system nand blocks - Raw',
            'Bad system nand blocks - Raw',
            'bad_system_nand_blocks_raw'),
    C0Field('bad_system_nand_blocks_normalized', 46, 2, 'le16', 0,
            'Bad system nand blocks - Normalized',
            'Bad system nand blocks - Normalized',
            'bad_system_nand_blocks_normalized'),
    C0Field('xor_recovery_count', 48, 8, 'le64', 0,
            'XOR recovery count',
            'XOR recovery count',
            'xor_recovery_count'),
    C0Field('uncorrectable_read_error_count', 56, 8, 'le64', 0,
            'Uncorrectable read error count',
            'Uncorrectable read error count',
            'uncorrectable_read_errors'),
    C0Field('soft_ecc_error_count', 64, 8, 'le64', 0,
            'Soft ecc error count',
            'Soft ecc error count',
            'soft_ecc_error_count'),
    C0Field('end_to_end_detected_errors', 72, 4, 'le32', 0,
            'End to end detected errors',
            'End to end detected errors',
            'end_to_end_detected_errors'),
    C0Field('end_to_end_corrected_errors', 76, 4, 'le32', 0,
            'End to end corrected errors',
            'End to end corrected errors',
            'end_to_end_corrected_errors'),
    C0Field('system_data_percent_used', 80, 1, 'u8', 0,
            'System data percent used',
            'System data percent used',
            'system_data_percent_used'),
    C0Field('refresh_count', 81, 7, 'u56', 0,
            'Refresh counts',
            'Refresh counts',
            'refresh_count'),
    C0Field('max_user_data_erase_count', 88, 4, 'le32', 0,
            'Max User data erase counts',
            'Max User data erase counts',
            'max_user_data_erase_count'),
    C0Field('min_user_data_erase_count', 92, 4, 'le32', 0,
            'Min User data erase counts',
            'Min User data erase counts',
            'min_user_data_erase_count'),
    C0Field('thermal_throttling_event_count', 96, 1, 'u8', 0,
            'Number of Thermal throttling events',
            'Number of Thermal throttling events',
            'thermal_throttling_events'),
    C0Field('thermal_throttling_current_status', 97, 1, 'u8', 0,
            'Current throttling status',
            'Current throttling status',
            'current_throttling_status'),
    C0Field('dssd_errata_version', 98, 1, 'u8', 2,
            'Errata Version Field',
            'Errata Version Field',
            'errata_version_field'),
    C0Field('dssd_point_version', 99, 2, 'le16', 2,
            'Point Version Field',
            'Point Version Field',
            'point_version_field'),
    C0Field('dssd_minor_version', 101, 2, 'le16', 2,
            'Minor Version Field',
            'Minor Version Field',
            'minor_version_field'),
    C0Field('dssd_major_version', 103, 1, 'u8', 2,
            'Major Version Field',
            'Major Version Field',
            'major_version_field'),
    C0Field('pcie_correctable_error_count', 104, 8, 'le64', 0,
            'PCIe correctable error count',
            'PCIe correctable error count',
            'pcie_correctable_errors'),
    C0Field('incomplete_shutdowns', 112, 4, 'le32', 0,
            'Incomplete shutdowns',
            'Incomplete shutdowns',
            'incomplete_shutdowns'),
    C0Field('percent_free_blocks', 120, 1, 'u8', 0,
            'Percent free blocks',
            'Percent free blocks',
            'percent_free_blocks'),
    C0Field('capacitor_health', 128, 2, 'le16', 0,
            'Capacitor health',
            'Capacitor health',
            'capacitor_health'),
    C0Field('nvme_base_errata_version', 130, 1, 'u8', 2,
            'NVMe Base Errata Version',
            'NVMe Base Errata Version',
            'nvme_base_errata_version'),
    C0Field('nvme_cmdset_errata_version', 131, 1, 'u8', 4,
            'NVMe Command Set Errata Version',
            'NVMe Command Set Errata Version',
            'nvme_command_set_errata_version'),
    C0Field('nvme_over_pcie_errata_version', 132, 1, 'u8', 5,
            'NVMe Over Pcie Errata Version',
            'NVMe Over Pcie Errata Version',
            'nvme_over_pcie_errata_version'),
    C0Field('nvme_mi_errata_version', 133, 1, 'u8', 5,
            'NVMe Mi Errata Version',
            'NVMe Mi Errata Version',
            'nvme_mi_errata_version'),
    C0Field('unaligned_io', 136, 8, 'le64', 0,
            'Unaligned I/O',
            'Unaligned I/O',
            'unaligned_io'),
    C0Field('security_version_number', 144, 8, 'le64', 0,
            'Security Version Number',
            'Security Version Number',
            'security_version_number'),
    C0Field('total_nuse', 152, 8, 'le64', 0,
            'NUSE - Namespace utilization',
            'NUSE - Namespace utilization',
            'nuse_namespace_utilization'),
    C0Field('plp_start_count', 160, 16, 'u128dec', 0,
            'PLP start count',
            'PLP start count',
            'plp_start_count'),
    C0Field('endurance_estimate', 176, 16, 'u128dec', 0,
            'Endurance estimate',
            'Endurance estimate',
            'endurance_estimate'),
    C0Field('pcie_link_retraining_count', 192, 8, 'le64', 2,
            'PCIe Link Retraining Count',
            'PCIe Link Retraining Count',
            'pcie_link_retraining_count'),
    C0Field('power_state_change_count', 200, 8, 'le64', 2,
            'Power State Change Count',
            'Power State Change Count',
            'power_state_change_count'),
    # The spec appears to define this as an 8-byte ASCII revision, the
    # same form as the FR field of Identify Controller, but all three
    # printers render it as a decimal u64. Encoded here as the printers
    # behave so the decode tests describe today's output; confirming it
    # against the spec document is an open item (see the known-issues
    # report), and if ASCII is correct this becomes kind 'ascii'.
    C0Field('lowest_permitted_fw_rev', 208, 8, 'le64', 4,
            'Lowest Permitted Firmware Revision',
            'Lowest Permitted Firmware Revision',
            'lowest_permitted_firmware_revision'),
    C0Field('total_media_dies', 216, 2, 'le16', 5,
            'Total media dies',
            'Total media dies',
            'total_media_dies'),
    C0Field('total_die_failure_tolerance', 218, 2, 'le16', 5,
            'Total die failure tolerance',
            'Total die failure tolerance',
            'total_die_failure_tolerance'),
    C0Field('media_dies_offline', 220, 2, 'le16', 5,
            'Media dies offline',
            'Media dies offline',
            'media_dies_offline'),
    C0Field('max_temperature_recorded', 222, 1, 'u8', 5,
            'Max temperature recorded',
            'Max temperature recorded',
            'max_temperature_recorded'),
    C0Field('form_factor', 223, 1, 'u8', 6,
            'Form factor',
            'Form factor',
            'form_factor'),
    C0Field('nand_avg_erase_count', 224, 8, 'le64', 5,
            'Nand avg erase count',
            'Nand avg erase count',
            'nand_avg_erase_count'),
    C0Field('command_timeouts', 232, 4, 'le32', 5,
            'Command timeouts',
            'Command timeouts',
            'command_timeouts'),
    C0Field('sys_area_program_fail_count_raw', 236, 4, 'le32', 5,
            'Sys area program fail count raw',
            'Sys area program fail count raw',
            'sys_area_program_fail_count_raw'),
    C0Field('sys_area_program_fail_count_normalized', 240, 1, 'u8', 5,
            'Sys area program fail count noralized',
            'Sys area program fail count noralized',
            'sys_area_program_fail_count_noralized'),
    C0Field('sys_area_uncorr_read_count_raw', 244, 4, 'le32', 5,
            'Sys area uncorrectable read count raw',
            'Sys area uncorrectable read count raw',
            'sys_area_uncorrectable_read_count_raw'),
    C0Field('sys_area_uncorr_read_count_normalized', 248, 1, 'u8', 5,
            'Sys area uncorrectable read count noralized',
            'Sys area uncorrectable read count noralized',
            'sys_area_uncorrectable_read_count_noralized'),
    C0Field('sys_area_erase_fail_count_raw', 252, 4, 'le32', 5,
            'Sys area erase fail count raw',
            'Sys area erase fail count raw',
            'sys_area_erase_fail_count_raw'),
    C0Field('sys_area_erase_fail_count_normalized', 256, 1, 'u8', 5,
            'Sys area erase fail count noralized',
            'Sys area erase fail count noralized',
            'sys_area_erase_fail_count_noralized'),
    C0Field('max_peak_power_capability', 260, 2, 'le16', 5,
            'Max peak power capability',
            'Max peak power capability',
            'max_peak_power_capability'),
    C0Field('current_max_avg_power', 262, 2, 'le16', 5,
            'Current max avg power',
            'Current max avg power',
            'current_max_avg_power'),
    C0Field('lifetime_power_consumed', 264, 6, 'u48', 5,
            'Lifetime power consumed',
            'Lifetime power consumed',
            'lifetime_power_consumed'),
    C0Field('dssd_firmware_revision', 270, 8, 'ascii', 5,
            'Dssd firmware revision',
            'Dssd firmware revision',
            'dssd_firmware_revision'),
    C0Field('dssd_firmware_build_uuid', 278, 16, 'uuid', 5,
            'Dssd firmware build UUID',
            'Dssd firmware build UUID',
            'dssd_firmware_build_uuid'),
    C0Field('dssd_firmware_build_label', 294, 64, 'ascii', 5,
            'Dssd firmware build label',
            'Dssd firmware build label',
            'dssd_firmware_build_label'),
    C0Field('die_in_use_bad_nand_block_raw', 358, 6, 'u48', 6,
            'Die in use badnandblock-Raw',
            'Die use badnandblock raw',
            'die_in_use_bad_nand_block_raw'),
    C0Field('die_in_use_bad_nand_block_normalized', 364, 2, 'le16', 6,
            'Die in use badnandblock-Normal',
            'Die use badnandblock normal',
            'die_in_use_bad_nand_block_normalized'),
    C0Field('log_page_version', 494, 2, 'le16', 0,
            'Log page version',
            'Log page version',
            'log_page_version'),
    C0Field('log_page_guid', 496, 16, 'guid', 0,
            'Log page GUID',
            'Log page GUID',
            'log_page_guid'),
)

_BY_NAME: Dict[str, C0Field] = {f.name: f for f in FIELDS}

# Integer kinds, in bytes. u128* are handled separately: they exceed the
# range the printers treat as a plain integer.
_INT_SIZES = {'u8': 1, 'le16': 2, 'le32': 4, 'u48': 6, 'u56': 7, 'le64': 8}

# stdout renders this one field as 0x%x; everything numeric else is
# decimal. Keyed by field name rather than kind, since it is a one-off.
_STDOUT_HEX_FIELDS = frozenset({'thermal_throttling_current_status'})


def by_name(name: str) -> C0Field:
    """Return the field called @name."""
    return _BY_NAME[name]


def fields_for_version(version: int) -> Tuple[C0Field, ...]:
    """Return the fields a printer emits for a log page of @version.

    Versions above MAX_LOG_PAGE_VERSION are rendered as that version:
    both printers group `default:` with their highest case.
    """
    effective = min(version, MAX_LOG_PAGE_VERSION)
    return tuple(f for f in FIELDS if f.min_version <= effective)


def render_guid(raw: bytes) -> str:
    """Render 16 GUID bytes the way all three printers do.

    Two little-endian halves, high half first, through "%"PRIx64 -- which
    is not zero-padded, so a half whose top bytes are zero renders
    shorter than 16 digits. Reproduced faithfully: a test comparing
    against a differently-padded string would report a mismatch that the
    printers do not actually have.
    """
    lo = int.from_bytes(raw[0:8], 'little')
    hi = int.from_bytes(raw[8:16], 'little')
    return f'0x{hi:x}{lo:x}'


def render_uuid(raw: bytes) -> str:
    """Render 16 bytes as shr_uuid_to_string() does."""
    hexed = raw.hex()
    return '-'.join((hexed[0:8], hexed[8:12], hexed[12:16],
                     hexed[16:20], hexed[20:32]))


def normalize_ascii(raw: bytes) -> str:
    """Canonical form of a fixed-length ASCII field.

    Truncated at the first NUL and stripped of trailing blanks, because
    the printers disagree past that point: the JSON printers hand the
    buffer to json_object_new_string(), which stops at the first NUL,
    while stdout writes every byte with %c, NULs included. Comparisons
    across output modes therefore only have this prefix in common.
    """
    return raw.split(b'\0', 1)[0].decode('latin-1').rstrip()


def decode(buf: bytes, field: C0Field) -> Any:
    """Decode @field out of a raw log page.

    Returns an int for every numeric kind (u128hilo included, as the
    full 128-bit value), and a str for ascii/uuid/guid.
    """
    raw = buf[field.offset:field.offset + field.size]
    if len(raw) != field.size:
        raise ValueError(
            f'log page too short for {field.name}: need '
            f'{field.offset + field.size} bytes, have {len(buf)}')

    if field.kind in _INT_SIZES:
        return int.from_bytes(raw, 'little')
    if field.kind in ('u128hilo', 'u128dec'):
        return int.from_bytes(raw, 'little')
    if field.kind == 'ascii':
        return normalize_ascii(raw)
    if field.kind == 'uuid':
        return render_uuid(raw)
    if field.kind == 'guid':
        return render_guid(raw)
    raise AssertionError(f'unhandled kind {field.kind!r}')


def coerce_json(field: C0Field, value: Any) -> Any:
    """Bring a value parsed out of JSON output into decode()'s form."""
    if field.kind == 'u128hilo':
        if not isinstance(value, dict):
            raise ValueError(
                f'{field.name}: expected a {{"hi","lo"}} object, got '
                f'{value!r}')
        return (int(value['hi']) << 64) | int(value['lo'])
    if field.kind == 'ascii':
        return normalize_ascii(str(value).encode('latin-1'))
    if field.kind in ('uuid', 'guid'):
        return str(value).lower()
    return int(value)


def parse_stdout_value(field: C0Field, text: str) -> Any:
    """Bring a value scraped out of text output into decode()'s form."""
    text = text.strip()
    if field.kind == 'ascii':
        return normalize_ascii(text.encode('latin-1'))
    if field.kind in ('uuid', 'guid'):
        return text.lower()
    if field.name in _STDOUT_HEX_FIELDS:
        return int(text, 16)
    return int(text)


def parse_stdout(text: str) -> Dict[str, str]:
    """Scrape "  <label><whitespace><value>" lines out of text output.

    Keyed by field name. Matching is by exact label prefix rather than
    by splitting on whitespace, because two labels ("Physical media
    units read    -") contain runs of spaces of their own. Values are
    returned as written; parse_stdout_value() interprets them.
    """
    found: Dict[str, str] = {}
    labelled = [f for f in FIELDS if f.stdout_label is not None]
    # Longest label first, so a label that is a prefix of another cannot
    # shadow it.
    labelled.sort(key=lambda f: len(f.stdout_label or ''), reverse=True)

    for line in text.splitlines():
        for field in labelled:
            prefix = '  ' + str(field.stdout_label)
            if line.startswith(prefix) and field.name not in found:
                found[field.name] = line[len(prefix):].strip()
                break
    return found


def distinctive_value(field: C0Field) -> int:
    """An offset-derived value for @field, for synthetic log pages.

    Chosen so that a decode reading the wrong offset, or the wrong
    number of bytes, produces a different number rather than
    accidentally the right one:

      * every field gets a distinct value, derived from its offset, so
        picking up a neighbour shows up;
      * every byte is non-zero and differs from its neighbours, so a
        truncated or byte-swapped read differs too.

    ASCII fields are filled with printable characters only. nvme-cli
    writes those buffers out byte for byte, and the test harness decodes
    the command's output as strict UTF-8, so an arbitrary byte there
    would fail the capture rather than the assertion.
    """
    seed = (field.offset % 251) + 1
    value = 0
    for i in range(field.size):
        if field.kind == 'ascii':
            # 0x21..0x7e: printable, no space, so trailing-blank
            # stripping cannot eat a real character.
            byte = 0x21 + ((seed + i * 7) % 0x5e)
        else:
            byte = ((seed + i * 7) % 255) + 1
        value |= byte << (8 * i)
    return value


def pack(version: int = 6,
         values: Optional[Dict[str, Any]] = None,
         guid: bytes = SCAO_GUID_BYTES) -> bytes:
    """Build a synthetic C0 log page.

    Every field is filled with distinctive_value() unless @values
    overrides it; ints are written little-endian, bytes verbatim (padded
    or truncated to the field width). @version sets log_page_version and
    @guid sets log_page_guid, so both stay steerable independently.
    """
    buf = bytearray(LOG_PAGE_SIZE)
    overrides = dict(values or {})

    for field in FIELDS:
        if field.name in ('log_page_version', 'log_page_guid'):
            continue
        raw = overrides.pop(field.name, None)
        if raw is None:
            raw = distinctive_value(field)
        if isinstance(raw, str):
            raw = raw.encode('latin-1')
        if isinstance(raw, (bytes, bytearray)):
            chunk = bytes(raw)[:field.size].ljust(field.size, b'\0')
        else:
            chunk = int(raw).to_bytes(field.size, 'little')
        buf[field.offset:field.offset + field.size] = chunk

    if overrides:
        raise KeyError(f'unknown C0 field(s): {sorted(overrides)}')

    version_field = by_name('log_page_version')
    buf[version_field.offset:version_field.offset + 2] = \
        int(version).to_bytes(2, 'little')
    guid_field = by_name('log_page_guid')
    buf[guid_field.offset:guid_field.offset + 16] = \
        bytes(guid)[:16].ljust(16, b'\0')

    return bytes(buf)


def expected_values(buf: bytes,
                    version: Optional[int] = None) -> Dict[str, Any]:
    """Decode every field a printer should emit for @buf."""
    if version is None:
        version = decode(buf, by_name('log_page_version'))
    return {f.name: decode(buf, f) for f in fields_for_version(version)}


def _check_table(fields: Sequence[C0Field]) -> None:
    """Guard the invariants the helpers above rely on."""
    seen: Dict[int, str] = {}
    for field in fields:
        if field.kind not in _INT_SIZES and field.kind not in (
                'u128hilo', 'u128dec', 'ascii', 'uuid', 'guid'):
            raise AssertionError(f'{field.name}: bad kind {field.kind!r}')
        if field.kind in _INT_SIZES and _INT_SIZES[field.kind] != field.size:
            raise AssertionError(
                f'{field.name}: kind {field.kind} is '
                f'{_INT_SIZES[field.kind]} bytes, size says {field.size}')
        end = field.offset + field.size
        if end > LOG_PAGE_SIZE:
            raise AssertionError(f'{field.name} runs past the log page')
        for offset in range(field.offset, end):
            if offset in seen:
                raise AssertionError(
                    f'{field.name} overlaps {seen[offset]} at byte '
                    f'{offset}')
            seen[offset] = field.name

    names = [f.name for f in fields]
    if len(set(names)) != len(names):
        raise AssertionError('duplicate field name in FIELDS')

    for attr in ('stdout_label', 'v1_key', 'v2_key'):
        keys = [getattr(f, attr) for f in fields if getattr(f, attr)]
        if len(set(keys)) != len(keys):
            raise AssertionError(f'duplicate {attr} in FIELDS')


_check_table(FIELDS)
