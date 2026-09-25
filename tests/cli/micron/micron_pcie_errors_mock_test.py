#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
#   Author: Broc Going <broc.going@micron.com>
#
"""Tests for the micron PCIe error commands, hardware-free.

vs-pcie-stats and clear-pcie-correctable-errors both report or reset PCIe
error state, and both pick their route from the drive model:

  M5407             a vendor 0xD6 admin command, which returns per-field
                    error counters for vs-pcie-stats and clears them for
                    clear-pcie-correctable-errors.
  M51CX/BY/CY       a vendor 0xC3 feature, for the clear command only.
  anything else     the PCIe AER status registers, read and written with
                    setpci, which the plugin locates through the controller's
                    sysfs PCI address.

On hardware only the attached drive's route runs, and the AER route needs a
device that exposes the AER capability.  Here the model is an input and
setpci is shadowed on PATH by a stand-in that models the AER status
registers, so all three routes and their failure modes are covered.

Tests in this module verify:
  * Which route each model takes, and the fall-back to AER when the vendor
    route fails.
  * vs-pcie-stats decoding: per-field counters from 0xD6, single status bits
    from the AER registers, the three text layouts and the JSON form.
  * clear-pcie-correctable-errors writing all ones to the correctable status
    register, reading back zero, and staying idempotent.
  * The failure paths: no setpci, a setpci that fails, and a controller whose
    PCI address cannot be read.
  * Error handling for a non-existent device and a bad --output-format.

Usage: python3 micron_pcie_errors_mock_test.py <nvme-binary> <mock-lib>
"""

import json
import os
import re
import shutil
import struct
from pathlib import Path

from micron_mock_test import (
    OPC_VENDOR_D6,
    SC_INVALID_FIELD,
    TestMicronMock,
    main,
)

_STATS = "vs-pcie-stats"
_CLEAR = "clear-pcie-correctable-errors"

_FID_CLEAR_PCI_CORRECTABLE = 0xC3

_JSON_KEY = "PCIE Stats"

# AER registers the plugin reads, as setpci names them.
_REG_CORRECTABLE = "ECAP_AER+0x10.L"
_REG_UNCORRECTABLE = "ECAP_AER+0x4.L"

# Uncorrectable fields, in the order the command emits them, with the bit each
# occupies in the register it is decoded from and its offset in the counter
# struct.
_UNCORRECTABLE_FIELDS = (
    ("Unsupported Request Error Status (URES)", 20, 15),
    ("ECRC Error Status (ECRCES)", 19, 14),
    ("Malformed TLP Status (MTS)", 18, 13),
    ("Receiver Overflow Status (ROS)", 17, 12),
    ("Unexpected Completion Status (UCS)", 16, 11),
    ("Completer Abort Status (CAS)", 15, 10),
    ("Completion Timeout Status (CTS)", 14, 9),
    ("Flow Control Protocol Error Status (FCPES)", 13, 8),
    ("Poisoned TLP Status (PTS)", 12, 7),
    ("Data Link Protocol Error Status (DLPES)", 4, 6),
)

_CORRECTABLE_FIELDS = (
    ("Advisory Non-Fatal Error Status (ANFES)", 13, 5),
    ("Replay Timer Timeout Status (RTS)", 12, 4),
    ("REPLAY_NUM Rollover Status (RRS)", 8, 3),
    ("Bad DLLP Status (BDS)", 7, 2),
    ("Bad TLP Status (BTS)", 6, 1),
    ("Receiver Error Status (RES)", 0, 0),
)

_ALL_FIELDS = _UNCORRECTABLE_FIELDS + _CORRECTABLE_FIELDS
_ALL_NAMES = tuple(name for name, _, _ in _ALL_FIELDS)

# struct pcie_error_counters: 16 u16 counters.
_COUNTER_STRUCT_SIZE = 32

# Models that decode the AER registers into per-field bits rather than
# printing the raw register values.
_BIT_DECODE_MODELS = ('M5407', 'M5410')

# A model that takes the AER route and prints the raw register values.
_GENERIC_MODEL = 'M51BX'

# Stand-in for setpci. Models the AER status registers as files, so a read
# after a clear observes the write, which is what makes the clear command's
# read-back meaningful.
_SETPCI = '''#!/usr/bin/env python3
import os
import sys

STATE = {state!r}
DEFAULTS = {defaults!r}

# setpci -s <bdf> <REG>[=<VALUE>]
request = sys.argv[3]
with open(os.path.join(STATE, "calls"), "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\\n")

if "=" in request:
    register, value = request.split("=", 1)
    # Writing ones to an AER status register clears the corresponding bits.
    written = int(value, 16)
    current = DEFAULTS.get(register, 0)
    path = os.path.join(STATE, register)
    if os.path.exists(path):
        with open(path) as f:
            current = int(f.read().strip(), 16)
    with open(path, "w") as f:
        f.write("%08x" % (current & ~written & 0xffffffff))
else:
    path = os.path.join(STATE, request)
    if os.path.exists(path):
        with open(path) as f:
            print(f.read().strip())
    else:
        print("%08x" % DEFAULTS.get(request, 0))
'''


def pack_error_counters(values=()):
    """Build a struct pcie_error_counters. @values maps a field name to its
    counter value."""
    buf = bytearray(_COUNTER_STRUCT_SIZE)
    offsets = {name: index for name, _, index in _ALL_FIELDS}
    for name, value in dict(values).items():
        struct.pack_into('<H', buf, offsets[name] * 2, value)
    return bytes(buf)


class PcieTestBase(TestMicronMock):
    """Shared setpci stand-in and field decoding."""

    def setUp(self):
        super().setUp()
        self.setpci_state = os.path.join(self.ipc_dir, 'setpci')
        os.makedirs(self.setpci_state)

    def install_setpci(self, correctable=0, uncorrectable=0):
        """Shadow setpci with a stand-in holding these register values."""
        defaults = {_REG_CORRECTABLE: correctable,
                    _REG_UNCORRECTABLE: uncorrectable}
        self.fake_tool('setpci', _SETPCI.format(state=self.setpci_state,
                                                defaults=defaults))

    def setpci_calls(self):
        """Return the setpci invocations the plugin made."""
        path = os.path.join(self.setpci_state, 'calls')
        if not os.path.exists(path):
            return []
        with open(path, encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    def register_value(self, register, default=0):
        """Return a register's value as the stand-in currently holds it."""
        path = os.path.join(self.setpci_state, register)
        if not os.path.exists(path):
            return default
        with open(path, encoding='utf-8') as f:
            return int(f.read().strip(), 16)

    def break_pci_address(self):
        """Leave the PCI IDs readable but the BDF unrecoverable.

        The model still has to be detected, so the PCI attributes have to
        stay reachable through <ctrl>/device -- they are moved into a real
        directory there.  get_pcie_bdf() then finds neither the address
        attribute nor a symlink to resolve.
        """
        ctrl = self.sysfs_path_ctrl()
        (ctrl / "address").unlink()

        link = ctrl / "device"
        target = Path(os.path.realpath(link))
        link.unlink()
        link.mkdir()
        for attr in ("vendor", "device", "subsystem_vendor",
                     "subsystem_device", "class"):
            shutil.copy(target / attr, link / attr)

    @staticmethod
    def expected_bits(correctable, uncorrectable):
        """Return the per-field values the AER bit decode should produce."""
        expected = {}
        for name, bit, _ in _UNCORRECTABLE_FIELDS:
            expected[name] = (uncorrectable >> bit) & 1
        for name, bit, _ in _CORRECTABLE_FIELDS:
            expected[name] = (correctable >> bit) & 1
        return expected


class TestMicronVsPcieStats(PcieTestBase):
    """vs-pcie-stats across its three routes."""

    def json_stats(self, device=None):
        data = self.run_plugin_cmd_json(_STATS, device=device)
        self.assertIn(_JSON_KEY, data,
                      f"Expected top-level {_JSON_KEY!r}, got {list(data)}")
        array = data[_JSON_KEY]
        self.assertIsInstance(array, list)
        self.assertEqual(len(array), 1,
                         f"Expected one stats object, got {len(array)}")
        return array[0]

    def text_fields(self, stdout):
        """Return {field: value} from the named-field text layout."""
        fields = {}
        for name, _, _ in _ALL_FIELDS:
            m = re.search(r"^" + re.escape(name) + r"\s*:\s*(\d+)$", stdout,
                          re.MULTILINE)
            if m:
                fields[name] = int(m.group(1))
        return fields

    # ---------------------------------------------------------------- #
    # Route selection                                                  #
    # ---------------------------------------------------------------- #

    def test_m5407_reads_the_vendor_counters(self):
        """M5407 gets per-field counters from the 0xD6 command."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = pack_error_counters()
        self.run_plugin_cmd_check(_STATS)

        self.assertIn(OPC_VENDOR_D6, self.server.opcodes())
        self.assertEqual(self.setpci_calls(), [],
                         "the AER registers were read despite 0xD6 working")

    def test_other_models_read_the_aer_registers(self):
        """Off M5407 the values come from the AER registers."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        self.run_plugin_cmd_check(_STATS)

        self.assertNotIn(OPC_VENDOR_D6, self.server.opcodes())
        self.assertEqual(len(self.setpci_calls()), 2,
                         "expected one read of each AER status register")

    def test_vendor_failure_falls_back_to_the_aer_registers(self):
        """A M5407 drive rejecting 0xD6 still reports what AER knows."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = SC_INVALID_FIELD
        self.install_setpci(correctable=1 << 12)
        result = self.run_plugin_cmd_check(_STATS)

        self.assertIn(OPC_VENDOR_D6, self.server.opcodes())
        self.assertEqual(self.text_fields(result.stdout)
                         ["Replay Timer Timeout Status (RTS)"], 1)

    # ---------------------------------------------------------------- #
    # Counter route decoding                                           #
    # ---------------------------------------------------------------- #

    def test_counters_are_decoded_per_field(self):
        """Each counter in the vendor struct lands in its own field."""
        values = {name: index + 1
                  for index, (name, _, _) in enumerate(_ALL_FIELDS)}
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = pack_error_counters(values)
        result = self.run_plugin_cmd_check(_STATS)

        self.assertEqual(self.text_fields(result.stdout), values)
        self.assertEqual(self.json_stats(), values)

    def test_counters_report_the_full_range(self):
        """A counter is 16 bits wide, so 65535 must not wrap or go negative."""
        values = {name: 0xFFFF for name, _, _ in _ALL_FIELDS}
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = pack_error_counters(values)

        self.assertEqual(self.json_stats(), values)

    def test_counter_route_requests_the_whole_struct(self):
        """The 0xD6 read asks for the counter struct, with cdw10 set to 1."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = pack_error_counters()
        self.run_plugin_cmd_check(_STATS)
        vendor = [c for c in self.server.commands
                  if c['opcode'] == OPC_VENDOR_D6]

        self.assertEqual(len(vendor), 1)
        self.assertEqual(vendor[0]['len'], _COUNTER_STRUCT_SIZE)
        self.assertEqual(vendor[0]['cdw10'], 1)

    # ---------------------------------------------------------------- #
    # AER route decoding                                               #
    # ---------------------------------------------------------------- #

    def test_aer_bits_are_decoded_to_their_fields(self):
        """On a bit-decoding model each field reports one register bit."""
        correctable = (1 << 0) | (1 << 6) | (1 << 12)     # RES, BTS, RTS
        uncorrectable = (1 << 4) | (1 << 12) | (1 << 20)  # DLPES, PTS, URES
        expected = self.expected_bits(correctable, uncorrectable)

        for model in _BIT_DECODE_MODELS:
            with self.subTest(model=model):
                self.select_model(model)
                self.install_setpci(correctable=correctable,
                                    uncorrectable=uncorrectable)
                result = self.run_plugin_cmd_check(_STATS)

                self.assertEqual(self.text_fields(result.stdout), expected)

    def test_aer_bit_decode_covers_every_field(self):
        """Every field's bit is read from the register it belongs to."""
        for name, bit, _ in _CORRECTABLE_FIELDS:
            with self.subTest(field=name):
                self.select_model('M5410')
                self.install_setpci(correctable=1 << bit)
                stats = self.json_stats()

                self.assertEqual(stats[name], 1)
                others = {k: v for k, v in stats.items() if k != name}
                self.assertEqual(set(others.values()), {0},
                                 f"setting bit {bit} affected another field")

    def test_aer_uncorrectable_bits_come_from_their_own_register(self):
        """The two registers are decoded independently."""
        for name, bit, _ in _UNCORRECTABLE_FIELDS:
            with self.subTest(field=name):
                self.select_model('M5410')
                self.install_setpci(uncorrectable=1 << bit)
                stats = self.json_stats()

                self.assertEqual(stats[name], 1)

    def test_json_always_reports_every_field(self):
        """All 16 fields appear whichever route produced the values."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()

        self.assertEqual(sorted(self.json_stats()), sorted(_ALL_NAMES))

    # ---------------------------------------------------------------- #
    # Text layouts                                                     #
    # ---------------------------------------------------------------- #

    def test_generic_model_prints_the_raw_register_values(self):
        """A model with neither route prints the two registers in hex."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci(correctable=0x1234, uncorrectable=0xABCD)
        result = self.run_plugin_cmd_check(_STATS)

        self.assertIn("PCIE Stats:", result.stdout)
        self.assertIn("Device correctable errors detected: 0x1234",
                      result.stdout)
        self.assertIn("Device uncorrectable errors detected: 0xabcd",
                      result.stdout)

    def test_generic_model_prints_no_named_fields(self):
        """The raw layout and the named layout are alternatives."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci(correctable=0x1234)
        result = self.run_plugin_cmd_check(_STATS)

        self.assertEqual(self.text_fields(result.stdout), {})

    def test_bit_decoding_models_print_named_fields(self):
        """The bit-decoding models list each field rather than the register."""
        for model in _BIT_DECODE_MODELS:
            with self.subTest(model=model):
                self.select_model(model)
                self.install_setpci(correctable=0x1234)
                result = self.run_plugin_cmd_check(_STATS)

                self.assertNotIn("PCIE Stats:", result.stdout)
                self.assertEqual(sorted(self.text_fields(result.stdout)),
                                 sorted(_ALL_NAMES))

    def test_json_is_the_same_shape_for_every_route(self):
        """JSON hides the route difference the text layouts expose."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = pack_error_counters()
        counter_keys = sorted(self.json_stats())

        self.select_model(_GENERIC_MODEL)
        self.install_setpci()

        self.assertEqual(sorted(self.json_stats()), counter_keys)

    def test_default_output_is_text(self):
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        result = self.run_plugin_cmd_check(_STATS)

        with self.assertRaises(ValueError,
                               msg="default output must not be JSON"):
            json.loads(result.stdout)

    # ---------------------------------------------------------------- #
    # Failure paths                                                    #
    # ---------------------------------------------------------------- #

    def test_missing_setpci_is_reported(self):
        """Without a working setpci the AER route cannot report anything."""
        self.select_model(_GENERIC_MODEL)
        self.fake_tool('setpci')
        result = self.run_plugin_cmd(_STATS)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to retrieve error count", result.stderr)

    def test_unreadable_pci_address_is_reported(self):
        """A controller with no PCI address has no AER registers to read."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        self.break_pci_address()
        result = self.run_plugin_cmd(_STATS)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to get PCI address", result.stderr)

    def test_pci_address_falls_back_to_the_device_link(self):
        """Without the address attribute the BDF comes from the device link.

        The attribute only exists on newer kernels, so the link is the
        fallback for older ones.
        """
        self.select_model(_GENERIC_MODEL)
        self.install_setpci(correctable=0x40)
        (self.sysfs_path_ctrl() / "address").unlink()
        result = self.run_plugin_cmd_check(_STATS)

        self.assertIn("0000:03:00.0", "\n".join(self.setpci_calls()))
        self.assertIn("Device correctable errors detected: 0x40",
                      result.stdout)

    def test_invalid_output_format_returns_error(self):
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        self.check_output_format_rejected(_STATS, "notaformat")

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_STATS)


class TestMicronClearPcieCorrectableErrors(PcieTestBase):
    """clear-pcie-correctable-errors across its three routes."""

    def test_hyperscale_models_use_the_vendor_feature(self):
        """M51CX/BY/CY clear through the 0xC3 feature, not setpci."""
        for model in ('M51CX', 'M51BY', 'M51CY'):
            with self.subTest(model=model):
                self.select_model(model)
                self.install_setpci()
                self.server.commands.clear()
                result = self.run_plugin_cmd_check(_CLEAR, args="--verbose")

                written = [c for c in self.server.commands
                           if c['fid'] == _FID_CLEAR_PCI_CORRECTABLE]
                self.assertTrue(written, "the 0xC3 feature was never written")
                self.assertEqual(self.setpci_calls(), [],
                                 "setpci was used although 0xC3 succeeded")
                self.assertIn("Device correctable errors cleared!",
                              result.stdout + result.stderr)

    def test_vendor_feature_sets_the_clear_bit(self):
        """The clear request is the top bit of the feature value."""
        self.select_model('M51CX')
        self.install_setpci()
        self.run_plugin_cmd_check(_CLEAR)
        written = [c for c in self.server.commands
                   if c['fid'] == _FID_CLEAR_PCI_CORRECTABLE]

        self.assertEqual(written[0]['cdw11'], 1 << 31)

    def test_m5407_uses_the_vendor_opcode(self):
        """M5407 clears with the 0xD6 command."""
        self.select_model('M5407')
        self.server.vendor[OPC_VENDOR_D6] = b""
        self.install_setpci()
        result = self.run_plugin_cmd_check(_CLEAR, args="--verbose")

        self.assertIn(OPC_VENDOR_D6, self.server.opcodes())
        self.assertEqual(self.setpci_calls(), [])
        self.assertIn("Device correctable errors cleared!",
                      result.stdout + result.stderr)

    def test_vendor_feature_failure_falls_back_to_aer(self):
        """A drive rejecting 0xC3 still gets cleared through setpci."""
        self.select_model('M51CX')
        self.server.feature_status[_FID_CLEAR_PCI_CORRECTABLE] = \
            SC_INVALID_FIELD
        self.install_setpci(correctable=0xFF)
        result = self.run_plugin_cmd_check(_CLEAR)

        self.assertIn(f"{_REG_CORRECTABLE}=0xffffffff",
                      "\n".join(self.setpci_calls()))
        self.assertIn("Device correctable errors detected:", result.stdout)

    def test_non_zero_feature_result_falls_back_to_aer(self):
        """The feature reporting a non-zero result counts as a failure.

        The plugin promotes the completion result to its return value, so a
        drive that accepts the command but reports a problem must not be
        treated as a successful clear.
        """
        self.select_model('M51CX')
        self.server.features[_FID_CLEAR_PCI_CORRECTABLE] = 1
        self.install_setpci(correctable=0xFF)
        self.run_plugin_cmd_check(_CLEAR)

        self.assertIn(f"{_REG_CORRECTABLE}=0xffffffff",
                      "\n".join(self.setpci_calls()))

    def test_aer_route_writes_all_ones_then_reads_back(self):
        """Clearing writes ones to every bit, then reports what remains."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci(correctable=0x1234)
        result = self.run_plugin_cmd_check(_CLEAR)
        calls = self.setpci_calls()

        self.assertEqual(len(calls), 2, f"unexpected setpci calls: {calls}")
        self.assertIn(f"{_REG_CORRECTABLE}=0xffffffff", calls[0])
        self.assertTrue(calls[1].endswith(_REG_CORRECTABLE),
                        f"the register was not read back: {calls[1]}")
        self.assertEqual(self.register_value(_REG_CORRECTABLE), 0)
        self.assertIn("Device correctable errors detected: 00000000",
                      result.stdout)

    def test_aer_route_leaves_the_uncorrectable_register_alone(self):
        """Only the correctable status register is cleared."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci(correctable=0xFF, uncorrectable=0xAA)
        self.run_plugin_cmd_check(_CLEAR)

        self.assertNotIn(_REG_UNCORRECTABLE, "\n".join(self.setpci_calls()))
        self.assertEqual(self.register_value(_REG_UNCORRECTABLE, 0xAA), 0xAA)

    def test_clearing_twice_succeeds(self):
        """Clearing an already-cleared register is not an error."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci(correctable=0xFF)

        first = self.run_plugin_cmd_check(_CLEAR)
        second = self.run_plugin_cmd_check(_CLEAR)

        self.assertIn("Device correctable errors detected: 00000000",
                      first.stdout)
        self.assertEqual(first.stdout, second.stdout)

    def test_verbose_message_on_the_aer_route(self):
        """Every route reports the same success message."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        result = self.run_plugin_cmd_check(_CLEAR, args="--verbose")

        self.assertIn("Device correctable errors cleared!",
                      result.stdout + result.stderr)

    def test_failing_write_is_reported(self):
        """A setpci that cannot write reports the clear failure."""
        self.select_model(_GENERIC_MODEL)
        self.fake_tool('setpci')
        result = self.run_plugin_cmd(_CLEAR)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to clear error count", result.stderr)

    def test_unreadable_pci_address_is_reported(self):
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        self.break_pci_address()
        result = self.run_plugin_cmd(_CLEAR)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to get PCI address", result.stderr)

    def test_unknown_model_still_takes_the_aer_route(self):
        """The command has no model gate; an unrecognised drive uses AER."""
        self.select_model(None)
        self.install_setpci(correctable=0x10)
        result = self.run_plugin_cmd_check(_CLEAR)

        self.assertIn("Device correctable errors detected: 00000000",
                      result.stdout)

    def test_namespace_path_succeeds(self):
        """A namespace path resolves to its parent controller."""
        self.select_model(_GENERIC_MODEL)
        self.install_setpci()
        self.run_plugin_cmd_check(_CLEAR, device=self.ns1)

        self.assertIn("0000:03:00.0", "\n".join(self.setpci_calls()))

    def test_bad_device_returns_error(self):
        self.check_bad_device_name(_CLEAR)


if __name__ == '__main__':
    main()
