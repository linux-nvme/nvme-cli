#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Dera smart-log-add command.

Tests retrieval and parsing of Dera vendor-specific additional SMART log
(LID 0xC0) and device status (admin passthru opcode 0xC0):
- Normal device status reporting
- Rebuilding device status reporting with percentage
- Non-rebuilding device status reporting (Card Read Only, Fatal Error, etc.)
- Out-of-range / unknown device status reporting
- Detailed telemetry parsing: capacitor, NAND, power, PCIe voltage, etc.
- Alias 'stat' invocation
- Error handling on log retrieval failure
- Error handling on status command failure

Usage: python3 dera_smart_log_mock_test.py <nvme-binary> <mock-lib>
"""

import struct

from tests.cli.nvme_mock import (MOCK_LIB, NVME_BIN, Reply, SC_INVALID_FIELD,
                                 MockTestCase, main)

_LID_DERA_SMART = 0xC0
_OPC_DERA_STATUS = 0xC0

# Device status codes defined in plugins/dera/dera-nvme.c
DEVICE_STATUS_READY = 0x00
DEVICE_STATUS_QUICK_REBUILDING = 0x01
DEVICE_STATUS_FULL_REBUILDING = 0x02
DEVICE_STATUS_RAW_REBUILDING = 0x03
DEVICE_STATUS_CARD_READ_ONLY = 0x04
DEVICE_STATUS_FATAL_ERROR = 0x05
DEVICE_STATUS_BUSY = 0x06
DEVICE_STATUS_LOW_LEVEL_FORMAT = 0x07
DEVICE_STATUS_FW_COMMITTING = 0x08
DEVICE_STATUS_OVER_TEMPERATURE = 0x09


def make_dera_smart_log(
    quick_rebuild_cnt0=0,
    quick_rebuild_cnt1=0,
    full_rebuild_cnt0=0,
    full_rebuild_cnt1=0,
    raw_rebuild_cnt0=0,
    raw_rebuild_cnt1=0,
    cap_aged=1,
    cap_aged_ratio=15,
    cap_status=0,
    cap_voltage=3300,
    cap_charge_ctrl_en=1,
    cap_charge_ctrl_val=100,
    cap_charge_max_thr=3500,
    cap_charge_min_thr=3000,
    dev_status=0,
    dev_status_up=0,
    nand_erase_err_cnt=12,
    nand_program_err_cnt=5,
    ddra_1bit_err=0,
    ddra_2bit_err=0,
    ddrb_1bit_err=0,
    ddrb_2bit_err=0,
    ddr_err_bit=0,
    pcie_corr_err=0,
    pcie_uncorr_err=0,
    pcie_fatal_err=0,
    pcie_err_bit=0,
    power_level=25,
    current_power=24500,
    nand_init_fail=0,
    fw_loader_version=b'LOAD_100',
    uefi_driver_version=b'UEFI_100',
    gpio0_err=0,
    gpio5_err=0,
    gpio_err_bit=0,
    rebuild_percent=50,
    pcie_volt_status=0,
    current_pcie_volt=12000,
    init_pcie_volt_thr=11500,
    rt_pcie_volt_thr=11500,
    init_pcie_volt_low=0,
    rt_pcie_volt_low=0,
    temp_sensor_abnormal=1,
    nand_read_retry_fail_cnt=2,
    fw_slot_version=b'FW_V1.00',
):
    """Build a 512-byte Dera SMART info log buffer (LID 0xC0)."""
    buf = bytearray(512)

    # 4-byte counters (0..23)
    buf[0:4] = struct.pack('<I', quick_rebuild_cnt0)
    buf[4:8] = struct.pack('<I', quick_rebuild_cnt1)
    buf[8:12] = struct.pack('<I', full_rebuild_cnt0)
    buf[12:16] = struct.pack('<I', full_rebuild_cnt1)
    buf[16:20] = struct.pack('<I', raw_rebuild_cnt0)
    buf[20:24] = struct.pack('<I', raw_rebuild_cnt1)

    # Capacitor attributes (24..37)
    buf[24] = cap_aged & 0xFF
    buf[25] = cap_aged_ratio & 0xFF
    buf[26] = cap_status & 0xFF
    buf[27:31] = struct.pack('<I', cap_voltage)
    buf[31] = cap_charge_ctrl_en & 0xFF
    buf[32:34] = struct.pack('<H', cap_charge_ctrl_val)
    buf[34:36] = struct.pack('<H', cap_charge_max_thr)
    buf[36:38] = struct.pack('<H', cap_charge_min_thr)

    # Status & error counters (38..47)
    buf[38] = dev_status & 0xFF
    buf[39] = dev_status_up & 0xFF
    buf[40:44] = struct.pack('<I', nand_erase_err_cnt)
    buf[44:48] = struct.pack('<I', nand_program_err_cnt)

    # DDR & PCIe errors (48..63)
    buf[48:50] = struct.pack('<H', ddra_1bit_err)
    buf[50:52] = struct.pack('<H', ddra_2bit_err)
    buf[52:54] = struct.pack('<H', ddrb_1bit_err)
    buf[54:56] = struct.pack('<H', ddrb_2bit_err)
    buf[56] = ddr_err_bit & 0xFF
    buf[57:59] = struct.pack('<H', pcie_corr_err)
    buf[59:61] = struct.pack('<H', pcie_uncorr_err)
    buf[61:63] = struct.pack('<H', pcie_fatal_err)
    buf[63] = pcie_err_bit & 0xFF

    # Power & NAND info (64..68)
    buf[64] = power_level & 0xFF
    buf[65:67] = struct.pack('<H', current_power)
    buf[67:69] = struct.pack('<H', nand_init_fail)

    # Firmware loader & UEFI driver versions (69..84)
    buf[69:77] = (bytes(fw_loader_version) + b'\x00' * 8)[:8]
    buf[77:85] = (bytes(uefi_driver_version) + b'\x00' * 8)[:8]

    # GPIO errors (85..90)
    buf[85:87] = struct.pack('<H', gpio0_err)
    buf[87:89] = struct.pack('<H', gpio5_err)
    buf[89:91] = struct.pack('<H', gpio_err_bit)

    # Rebuild & PCIe voltages (91..102)
    buf[91] = rebuild_percent & 0xFF
    buf[92] = pcie_volt_status & 0xFF
    buf[93:95] = struct.pack('<H', current_pcie_volt)
    buf[95:97] = struct.pack('<H', init_pcie_volt_thr)
    buf[97:99] = struct.pack('<H', rt_pcie_volt_thr)
    buf[99:101] = struct.pack('<H', init_pcie_volt_low)
    buf[101:103] = struct.pack('<H', rt_pcie_volt_low)

    # Temperature & NAND retry & FW slot (103..116)
    buf[103:105] = struct.pack('<H', temp_sensor_abnormal)
    buf[105:109] = struct.pack('<I', nand_read_retry_fail_cnt)
    buf[109:117] = (bytes(fw_slot_version) + b'\x00' * 8)[:8]

    return bytes(buf)


class TestDeraSmartLog(MockTestCase):
    """Run dera smart-log-add against simulated SMART log and status."""

    def run_smart_log(self, *args, **kwargs):
        return self.nvme('dera', 'smart-log-add', self.ctrl, *args, **kwargs)

    def test_smart_log_normal_output(self):
        """Verify normal device status and all parsed field values."""
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log()
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_READY)

        res = self.assertOk(self.run_smart_log())
        lines = res.stdout.splitlines()

        self.assertTrue(any('device_status' in l and 'Normal' in l for l in lines))
        self.assertTrue(any('dev_status_up' in l and 'Normal' in l for l in lines))
        self.assertTrue(any('cap_aged' in l and 'True' in l for l in lines))
        self.assertTrue(any('cap_aged_ratio' in l and '15%' in l for l in lines))
        self.assertTrue(any('cap_status' in l and 'Normal' in l for l in lines))
        self.assertTrue(any('cap_voltage' in l and '3300 mV' in l for l in lines))
        self.assertTrue(any('nand_erase_err_cnt' in l and '12' in l for l in lines))
        self.assertTrue(any('nand_program_err_cnt' in l and '5' in l for l in lines))
        self.assertTrue(any('power_level' in l and '25 W' in l for l in lines))
        self.assertTrue(any('current_power' in l and '24500 mW' in l for l in lines))
        self.assertTrue(any('nand_init_fail' in l and '0' in l for l in lines))
        self.assertTrue(any('pcie_volt_status' in l and 'Normal' in l for l in lines))
        self.assertTrue(any('current_pcie_volt' in l and '12000 mV' in l for l in lines))
        self.assertTrue(any('init_pcie_volt_low_cnt' in l and '0' in l for l in lines))
        self.assertTrue(any('rt_pcie_volt_low_cnt' in l and '0' in l for l in lines))
        self.assertTrue(any('temp_sensor_abnormal_cnt' in l and '1' in l for l in lines))
        self.assertTrue(any('nand_read_retry_fail_cnt' in l and '2' in l for l in lines))
        self.assertTrue(any('fw_slot_version' in l and 'FW_V1.00' in l for l in lines))

    def test_smart_log_rebuilding_status(self):
        """Verify device rebuilding status with percentage completion."""
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log(rebuild_percent=75)
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_QUICK_REBUILDING)

        res = self.assertOk(self.run_smart_log())
        self.assertIn('Quick Rebuilding 75% completed', res.stdout)

        # Full rebuilding
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log(rebuild_percent=30)
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_FULL_REBUILDING)
        res_full = self.assertOk(self.run_smart_log())
        self.assertIn('Full Rebuilding 30% completed', res_full.stdout)

        # Raw rebuilding
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log(rebuild_percent=99)
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_RAW_REBUILDING)
        res_raw = self.assertOk(self.run_smart_log())
        self.assertIn('Raw Rebuilding 99% completed', res_raw.stdout)

    def test_smart_log_card_read_only_status(self):
        """Verify non-rebuilding device status strings."""
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log()
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_CARD_READ_ONLY)
        res = self.assertOk(self.run_smart_log())
        self.assertIn('device_status                       : Card Read Only', res.stdout)

    def test_smart_log_unknown_status(self):
        """Verify unknown status handling when status is out of array bounds."""
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log(dev_status_up=99)
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=0xFE)
        res = self.assertOk(self.run_smart_log())
        lines = res.stdout.splitlines()
        self.assertTrue(any('device_status' in l and 'Unknown' in l for l in lines))
        self.assertTrue(any('dev_status_up' in l and 'Unknown' in l for l in lines))

    def test_smart_log_stat_alias(self):
        """Verify 'stat' command alias invokes identical behavior."""
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log()
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_READY)

        res = self.assertOk(self.nvme('dera', 'stat', self.ctrl))
        self.assertIn('device_status                       : Normal', res.stdout)
        self.assertIn('cap_voltage                         : 3300 mV', res.stdout)

    def test_smart_log_error_get_log_page(self):
        """Verify failure reporting when Get Log Page fails."""
        self.server.logs[_LID_DERA_SMART] = SC_INVALID_FIELD
        self.server.admin[_OPC_DERA_STATUS] = Reply(result=DEVICE_STATUS_READY)

        res = self.run_smart_log()
        self.assertNotEqual(res.returncode, 0)
        combined = res.stdout + res.stderr
        self.assertIn('Invalid Field in Command', combined)

    def test_smart_log_error_device_status(self):
        """Verify failure reporting when device status admin command fails."""
        self.server.logs[_LID_DERA_SMART] = make_dera_smart_log()
        self.server.admin[_OPC_DERA_STATUS] = SC_INVALID_FIELD

        res = self.run_smart_log()
        self.assertNotEqual(res.returncode, 0)
        combined = res.stdout + res.stderr
        self.assertIn('Invalid Field in Command', combined)


if __name__ == '__main__':
    main()
