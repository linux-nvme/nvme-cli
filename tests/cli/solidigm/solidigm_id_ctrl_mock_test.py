#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hardware-free tests for the Solidigm id-ctrl command.

The Solidigm id-ctrl command extends the core Identify Controller rendering
with vendor-specific fields from the 1024-byte vendor-specific area (vs[]).
The layout is defined in solidigm-id-ctrl.c as struct nvme_vu_id_ctrl_field:

  Offset (into vs)  Field       Size
  0..2              rsvd1       3 bytes
  3                 ss          u8  (stripeSize)
  4..23             health      20 chars
  24                cls         u8  (linkSpeed)
  25                nlw         u8  (negLnkWdth)
  26                scap        u8  (secCapab)
  27                sstat       u8  (secStatus)
  28..35            bl          8 chars (bootLoader)
  36..73            rsvd2       38 bytes
  74..81            ww          le64 (wwid)
  82..85            mic_bl      4 chars (bwLimGran)
  86..89            mic_fw      4 chars (ioLimGran)
  90..767           rsvd3       678 bytes
  768..771          signature   u32
  772               version     u8
  773               product_type u8
  774               nand_type   u8
  775               form_factor u8
  776..779          fw_status   u32
  780..783          p4_revision u32
  784..787          customer_id u32
  788..791          usage_model u32
  792..795          command_set u32  (bit-field: zns_nvme, mfnd_nvme,
                                     cdw1413, vpd_avail)

The vendor-specific area starts at byte 3072 of the 4096-byte Identify
Controller response (vs[1024] is the last field of nvme_id_ctrl).

Usage: python3 solidigm_id_ctrl_mock_test.py <nvme-binary> <mock-lib>
"""

import struct

from tests.cli.nvme_mock import (CNS_CTRL, HAVE_JSON, ID_CTRL_SIZE,
                                 OPC_IDENTIFY, SC_INVALID_FIELD,
                                 MockTestCase, id_ctrl, main)

# vs[] starts at byte 3072 of the 4096-byte Identify Controller response.
_VS_OFFSET = ID_CTRL_SIZE - 1024

# Offsets of struct nvme_vu_id_ctrl_field fields relative to vs[].
_OFF_SS           = 3
_OFF_HEALTH       = 4
_HEALTH_LEN       = 20
_OFF_CLS          = 24
_OFF_NLW          = 25
_OFF_SCAP         = 26
_OFF_SSTAT        = 27
_OFF_BL           = 28
_BL_LEN           = 8
_OFF_WW           = 74   # le64
_OFF_MIC_BL       = 82
_MIC_BL_LEN       = 4
_OFF_MIC_FW       = 86
_MIC_FW_LEN       = 4
_OFF_SIGNATURE    = 768  # u32
_OFF_VERSION      = 772  # u8
_OFF_PRODUCT_TYPE = 773  # u8
_OFF_NAND_TYPE    = 774  # u8
_OFF_FORM_FACTOR  = 775  # u8
_OFF_FW_STATUS    = 776  # u32
_OFF_P4_REVISION  = 780  # u32
_OFF_CUSTOMER_ID  = 784  # u32
_OFF_USAGE_MODEL  = 788  # u32
_OFF_COMMAND_SET  = 792  # u32 bit-field


def _sldgm_identify(*, ss=0, health=b'', cls=0, nlw=0, scap=0, sstat=0,
                    bl=b'', ww=0, mic_bl=b'', mic_fw=b'',
                    signature=0, version=0, product_type=0,
                    nand_type=0, form_factor=0, fw_status=0,
                    p4_revision=0, customer_id=0, usage_model=0,
                    command_set=0):
    """Build an Identify Controller buffer with Solidigm vendor fields."""
    buf = bytearray(id_ctrl())

    def vs_set(offset, data):
        abs_off = _VS_OFFSET + offset
        buf[abs_off:abs_off + len(data)] = data

    def vs_set_u8(offset, val):
        buf[_VS_OFFSET + offset] = val & 0xFF

    def vs_set_u32le(offset, val):
        struct.pack_into('<I', buf, _VS_OFFSET + offset, val & 0xFFFFFFFF)

    def vs_set_u64le(offset, val):
        struct.pack_into('<Q', buf, _VS_OFFSET + offset,
                         val & 0xFFFFFFFFFFFFFFFF)

    vs_set_u8(_OFF_SS, ss)
    if health:
        vs_set(_OFF_HEALTH, health[:_HEALTH_LEN])
    vs_set_u8(_OFF_CLS, cls)
    vs_set_u8(_OFF_NLW, nlw)
    vs_set_u8(_OFF_SCAP, scap)
    vs_set_u8(_OFF_SSTAT, sstat)
    if bl:
        vs_set(_OFF_BL, bl[:_BL_LEN])
    vs_set_u64le(_OFF_WW, ww)
    if mic_bl:
        vs_set(_OFF_MIC_BL, mic_bl[:_MIC_BL_LEN])
    if mic_fw:
        vs_set(_OFF_MIC_FW, mic_fw[:_MIC_FW_LEN])
    vs_set_u32le(_OFF_SIGNATURE, signature)
    vs_set_u8(_OFF_VERSION, version)
    vs_set_u8(_OFF_PRODUCT_TYPE, product_type)
    vs_set_u8(_OFF_NAND_TYPE, nand_type)
    vs_set_u8(_OFF_FORM_FACTOR, form_factor)
    vs_set_u32le(_OFF_FW_STATUS, fw_status)
    vs_set_u32le(_OFF_P4_REVISION, p4_revision)
    vs_set_u32le(_OFF_CUSTOMER_ID, customer_id)
    vs_set_u32le(_OFF_USAGE_MODEL, usage_model)
    vs_set_u32le(_OFF_COMMAND_SET, command_set)

    return bytes(buf)


class TestSolidigmIdCtrl(MockTestCase):
    """Run solidigm id-ctrl against a simulated Identify response."""

    def run_id_ctrl(self, *args):
        return self.nvme('solidigm', 'id-ctrl', self.ctrl, *args)

    def assertOkIdCtrl(self, *args):
        return self.assertOk(self.run_id_ctrl(*args))

    def test_default_output_contains_vendor_fields(self):
        """Normal output must include the Solidigm-specific field names."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(ss=4, cls=2, nlw=4)
        result = self.assertOkIdCtrl()

        for label in ('stripeSize', 'health', 'linkSpeed', 'negLnkWdth',
                      'secCapab', 'secStatus', 'bootLoader', 'wwid',
                      'bwLimGran', 'ioLimGran', 'signature', 'version',
                      'prodType', 'nandType', 'formFactor', 'fwStatus',
                      'P4Revision', 'customerID', 'usageModel'):
            self.assertIn(label, result.stdout,
                          f'Expected label {label!r} '
                          f'in solidigm id-ctrl output')

    def test_identify_failure_is_reported(self):
        """A controller status error must fail instead of printing data."""
        self.server.identify[CNS_CTRL] = SC_INVALID_FIELD
        result = self.run_id_ctrl()
        self.assertNotEqual(result.returncode, 0)

    def test_stripe_size_reported(self):
        """stripeSize (ss) byte is printed in normal output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(ss=8)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'stripeSize\s*:\s*8')

    def test_link_speed_reported(self):
        """linkSpeed (cls) byte appears in normal output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(cls=3)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'linkSpeed\s*:\s*3')

    def test_negotiated_link_width_reported(self):
        """negLnkWdth (nlw) byte appears in normal output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(nlw=4)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'negLnkWdth\s*:\s*4')

    def test_security_capability_reported(self):
        """secCapab (scap) byte appears in normal output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(scap=0xAB)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'secCapab\s*:\s*171')

    def test_security_status_reported(self):
        """secStatus (sstat) byte appears in normal output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(sstat=1)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'secStatus\s*:\s*1')

    def test_signature_reported_as_hex(self):
        """signature field is printed as a 0x-prefixed hex value."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(signature=0xDEADBEEF)
        result = self.assertOkIdCtrl()
        self.assertIn('0xDEADBEEF', result.stdout)

    def test_p4_revision_reported_as_hex(self):
        """P4Revision (git hash) is printed as a hex value."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(p4_revision=0xABCD1234)
        result = self.assertOkIdCtrl()
        self.assertIn('0xABCD1234', result.stdout)

    def test_product_type_and_nand_type(self):
        """prodType and nandType single-byte fields are printed."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(
            product_type=2, nand_type=5)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'prodType\s*:\s*2')
        self.assertRegex(result.stdout, r'nandType\s*:\s*5')

    def test_health_string_printed(self):
        """health string from vs[] is included in the output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(
            health=b'WARNING' + b'\x00' * 13)
        result = self.assertOkIdCtrl()
        self.assertIn('WARNING', result.stdout)

    def test_empty_health_defaults_to_healthy(self):
        """An all-zero health field should report 'healthy'."""
        self.server.identify[CNS_CTRL] = _sldgm_identify()  # health stays zero
        result = self.assertOkIdCtrl()
        self.assertIn('healthy', result.stdout)

    def test_boot_loader_string_printed(self):
        """bootLoader (bl) 8-char field appears in the output."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(bl=b'BL1.0001')
        result = self.assertOkIdCtrl()
        self.assertIn('BL1.0001', result.stdout)

    def test_zns_nvme_bit(self):
        """znsNVMe is bit 0 of command_set."""
        for bit_val, expected in ((0, 0), (1, 1)):
            with self.subTest(zns_nvme=bit_val):
                self.server.identify[CNS_CTRL] = _sldgm_identify(
                    command_set=bit_val)
                result = self.assertOkIdCtrl()
                self.assertRegex(result.stdout,
                                 rf'znsNVMe\s*:\s*{expected}')

    def test_vpd_avail_bit(self):
        """vpdAvail is bit 3 of command_set."""
        self.server.identify[CNS_CTRL] = _sldgm_identify(command_set=0x8)
        result = self.assertOkIdCtrl()
        self.assertRegex(result.stdout, r'vpdAvail\s*:\s*1')

    def test_json_output_contains_vendor_keys(self):
        """JSON output must include the Solidigm vendor-specific keys."""
        if not HAVE_JSON:
            self.skipTest('json-c not available')
        self.server.identify[CNS_CTRL] = _sldgm_identify(
            ss=4, cls=2, nlw=4, signature=0xCAFEBABE,
            version=1, product_type=2, nand_type=3, form_factor=2)
        result = self.assertOk(self.run_id_ctrl('-o', 'json'))
        output = self.parse_json_output(result.stdout,
                                        'solidigm id-ctrl -o json')
        for key in ('stripeSize', 'health', 'linkSpeed', 'negLnkWdth',
                    'secCapab', 'secStatus', 'bootLoader', 'wwid',
                    'bwLimGran', 'ioLimGran', 'signature', 'version',
                    'prodType', 'nandType', 'formFactor', 'fwStatus',
                    'P4Revision', 'customerID', 'usageModel',
                    'znsNVMe', 'mfndNVMe', 'cdw14map13', 'vpdAvail'):
            self.assertIn(key, output,
                          f'Expected key {key!r} in solidigm id-ctrl JSON')

    def test_json_stripe_size_matches_normal(self):
        """JSON stripeSize must equal the value shown in normal output."""
        if not HAVE_JSON:
            self.skipTest('json-c not available')
        self.server.identify[CNS_CTRL] = _sldgm_identify(ss=16)
        json_result = self.assertOk(self.run_id_ctrl('-o', 'json'))
        output = self.parse_json_output(json_result.stdout,
                                        'solidigm id-ctrl -o json')
        self.assertEqual(output['stripeSize'], 16)

    def test_json_command_set_bits(self):
        """JSON command_set sub-fields track the right bits."""
        if not HAVE_JSON:
            self.skipTest('json-c not available')
        # Set all four defined bits: zns_nvme(0), mfnd_nvme(1),
        # cdw1413(2), vpd_avail(3)
        self.server.identify[CNS_CTRL] = _sldgm_identify(command_set=0xF)
        output = self.parse_json_output(
            self.assertOk(self.run_id_ctrl('-o', 'json')).stdout,
            'solidigm id-ctrl -o json')
        for key in ('znsNVMe', 'mfndNVMe', 'cdw14map13', 'vpdAvail'):
            self.assertEqual(output[key], 1, f'{key} should be 1')

    def test_one_identify_request_sent(self):
        """Exactly one Identify Controller admin command is issued."""
        self.server.identify[CNS_CTRL] = _sldgm_identify()
        self.assertOkIdCtrl()

        cmds = [c for c in self.server.commands
                if c.admin and c.opcode == OPC_IDENTIFY and c.cns == CNS_CTRL]
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0].data_len, ID_CTRL_SIZE)


if __name__ == '__main__':
    main()
