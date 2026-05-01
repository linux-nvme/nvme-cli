# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli
#
# Copyright (c) 2022 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# Authors: Arunpandian J <apj.arun@samsung.com>
#          Joy Gu <jgu@purestorage.com>

"""
NVMe Copy Testcase:-

    Test classes are split by descriptor format group:

    TestNVMeCopyFormat0  - Descriptor Format 0 (16-bit guard, in-namespace copy).
    TestNVMeCopyFormat1  - Descriptor Format 1 (64-bit guard, in-namespace copy).
                           The namespace is reformatted to a 64-bit guard LBA
                           format before the test runs.
    TestNVMeCopyFormat23 - Descriptor Formats 2 and 3 (cross-namespace copy).
                           Format 3 additionally requires a 64-bit guard namespace
                           and reformats before running.

"""

import json

from nvme_test import TestNVMe, to_decimal


class TestNVMeCopy(TestNVMe):

    """
    Base class for NVMe Copy tests.

    Provides shared setUp/tearDown and helper methods used by all copy test
    subclasses.
        - Attributes:
              - ocfs          : optional copy formats supported (from id-ctrl)
              - original_cdfe : saved cdfe value restored in tearDown, or None
              - mcl           : Maximum Copy Length (blocks)
              - mssrl         : Maximum Single Source Range Length (blocks)
              - msrc          : Maximum Source Range Count
              - ns1_nsid      : numeric namespace ID of self.ns1
    """

    def setUp(self):
        """ Pre Section for TestNVMeCopy """
        super().setUp()
        self.ocfs = self.get_ocfs()
        self.original_cdfe = None
        self._refresh_ns_copy_limits()
        get_ns_id_cmd = f"{self.nvme_bin} get-ns-id {self.ns1}"
        result = self.run_cmd(get_ns_id_cmd)
        self.assertEqual(result.returncode, 0, "ERROR : nvme get-ns-id failed")
        self.ns1_nsid = int(result.stdout.strip().split(':')[-1])
        self.setup_log_dir(self.__class__.__name__)

    def tearDown(self):
        """ Post Section for TestNVMeCopy """
        if self.original_cdfe is not None:
            set_features_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
                f"{self.ctrl} --cdfe={self.original_cdfe}"
            self.run_cmd(set_features_cmd)
        super().tearDown()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refresh_ns_copy_limits(self):
        """ Read MCL, MSSRL, MSRC from the current namespace into instance attrs """
        self.mcl = to_decimal(self.get_id_ns_field_value("mcl"))
        self.mssrl = to_decimal(self.get_id_ns_field_value("mssrl"))
        self.msrc = to_decimal(self.get_id_ns_field_value("msrc"))

    def _check_format_supported(self, desc_format):
        """ Skip test if the given copy descriptor format is not supported """
        if not self.ocfs & (1 << desc_format):
            self.skipTest(f"descriptor format {desc_format} is not supported")

    def _check_ns_copy_limits(self):
        """ Skip test if namespace copy limits (mcl, mssrl, msrc) are not set """
        missing = [name for name, val in
                   [("mcl", self.mcl), ("mssrl", self.mssrl), ("msrc", self.msrc)]
                   if val == 0]
        if missing:
            self.skipTest(f"{', '.join(missing)} are 0, copy not supported on this namespace")

    def _get_current_ns_pif(self):
        """
        Return the Protection Information Format (pif) of the currently active
        LBA format on self.ns1.

        Reads the raw ``flbas`` byte from ``id-ns`` to determine the active
        lbaf index (NVMe spec: bits[3:0] are lbaf_index[3:0], bits[6:5] are
        lbaf_index[5:4]), then looks up that entry in the ``nvm-id-ns`` elbafs
        array.  Returns 0 if either command fails or the pif field is absent
        (0 = 16-bit guard / no PI, the safe default for format 0/2 copy).
        """
        id_ns_cmd = f"{self.nvme_bin} id-ns {self.ns1} --output-format=json"
        result = self.run_cmd(id_ns_cmd)
        if result.returncode != 0:
            return 0
        flbas = int(json.loads(result.stdout).get("flbas", 0))
        lbaf_idx = (flbas & 0xF) | (((flbas >> 5) & 0x3) << 4)

        nvm_id_ns_cmd = f"{self.nvme_bin} nvm-id-ns {self.ns1} --output-format=json"
        result = self.run_cmd(nvm_id_ns_cmd)
        if result.returncode != 0:
            return 0
        elbafs = json.loads(result.stdout).get("elbafs", [])
        if lbaf_idx < len(elbafs):
            return elbafs[lbaf_idx].get("pif", 0)
        return 0

    def _check_16b_guard_ns(self):
        """
        Skip the test if the current namespace uses a non-16-bit-guard PI
        format and namespace management is not available to restore it.

        Copy descriptor formats 0 and 2 require the namespace to use 16-bit
        guard PI (pif=0) or no PI.  When namespace management is supported,
        TestNVMe.setUp() already recreates the namespace with flbas=0 (no
        metadata, no PI), so this is a no-op in that case.  When namespace
        management is not available and the namespace is already in a 64-bit
        guard PI format (e.g. QEMU started with pif=2, or left over from a
        previous test run), the copy command would fail with "Invalid Format"
        rather than being skipped cleanly.
        """
        if not self.ns_mgmt_supported and self._get_current_ns_pif() != 0:
            self.skipTest(
                "current namespace uses non-16-bit-guard PI and namespace "
                "management is not supported; cannot run 16-bit guard copy test"
            )

    def _find_64b_guard_lbaf_index(self):
        """
        Search the nvm-id-ns elbafs for a format with 64-bit guard PI (pif == 2).

        Returns the lbaf index (0-based position in the lbafs[] array), or None
        if no such format exists or the nvm-id-ns command is not supported.
        """
        nvm_id_ns_cmd = f"{self.nvme_bin} nvm-id-ns {self.ns1} --output-format=json"
        result = self.run_cmd(nvm_id_ns_cmd)
        if result.returncode != 0:
            return None
        elbafs = json.loads(result.stdout).get("elbafs", [])
        for i, elbaf in enumerate(elbafs):
            if elbaf.get("pif", 0) == 2:  # NVME_NVM_PIF_64B_GUARD = 2
                return i
        return None

    def _create_ns_with_lbaf(self, lbaf_index):
        """
        Delete and recreate the default namespace using the given lbaf_index.

        The lbaf_index is encoded into the flbas byte per NVMe spec:
          flbas[3:0] = lbaf_index[3:0], flbas[6:5] = lbaf_index[5:4]

        After recreating, self.mcl/mssrl/msrc are refreshed from the new
        namespace.  Calls skipTest if namespace management is not supported
        or if the create/attach step fails.
        """
        if not self.ns_mgmt_supported:
            self.skipTest("namespace management not supported; cannot reformat namespace")

        # encode lbaf_index into the 8-bit flbas field
        flbas = (lbaf_index & 0xF) | (((lbaf_index >> 4) & 0x3) << 5)

        # get_lba_format_size() in the parent class indexes the id-ns lbafs[] array
        # using self.flbas, so set it to lbaf_index here for the size look-up.
        # This is intentional: lbaf_index is the direct array position, while flbas
        # (computed above) is the encoded byte passed to create-ns --flbas.
        self.flbas = lbaf_index
        (ds, ms) = self.get_lba_format_size()
        if ds == 0:
            self.skipTest(f"lbaf {lbaf_index} reports zero data size; cannot create namespace")
        ncap = int(self.get_ncap() / (ds + ms))

        ctrl_id = self.get_ctrl_id()
        self.delete_all_ns()
        err = self.create_and_validate_ns(self.default_nsid, ncap, ncap, flbas, 0)
        self.assertEqual(err, 0,
                         f"ERROR: failed to create namespace with lbaf {lbaf_index} (flbas={flbas:#x})")
        self.assertEqual(self.attach_ns(ctrl_id, self.default_nsid), 0,
                         "ERROR: failed to attach reformatted namespace")

        # refresh copy limits for the new namespace
        self._refresh_ns_copy_limits()

    def _setup_64b_guard_ns(self):
        """
        Reformat the default namespace to a 64-bit guard PI LBA format (pif == 2).

        Skips the test if:
          - namespace management is not supported, or
          - no LBA format with 64-bit guard PI exists on this controller.
        """
        lbaf_index = self._find_64b_guard_lbaf_index()
        if lbaf_index is None:
            self.skipTest("no LBA format with 64-bit guard PI (pif=2) found; "
                          "cannot run copy descriptor format 1/3 test")
        self._create_ns_with_lbaf(lbaf_index)

    def _enable_cdfe_for_format(self, desc_format):
        """
        Enable the host-behavior-support cdfe bit for the given cross-namespace
        copy descriptor format. Only the single required bit is enabled; other
        bits are left unchanged. The original value is saved in self.original_cdfe
        for tearDown to restore.
        """
        cdfe_bit = 1 << desc_format
        get_features_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
            f"{self.ctrl} --output-format=json"
        result = self.run_cmd(get_features_cmd)
        self.assertEqual(result.returncode, 0,
                         "ERROR : nvme feat host-behavior-support failed")
        data = json.loads(result.stdout)
        fields = data.get("Feature: 0x16", [{}])[0]
        current_cdfe = (
            (0x4 if fields.get("Copy Descriptor Format 2h Enable (CDF2E)") == "True" else 0) |
            (0x8 if fields.get("Copy Descriptor Format 3h Enable (CDF3E)") == "True" else 0) |
            (0x10 if fields.get("Copy Descriptor Format 4h Enable (CDF4E)") == "True" else 0)
        )
        if current_cdfe & cdfe_bit:
            return
        if self.original_cdfe is None:
            self.original_cdfe = current_cdfe
        new_cdfe = current_cdfe | cdfe_bit
        set_features_cmd = f"{self.nvme_bin} feat host-behavior-support " + \
            f"{self.ctrl} --cdfe={new_cdfe}"
        result = self.run_cmd(set_features_cmd)
        self.assertEqual(result.returncode, 0,
                         f"Failed to enable cdfe bit {cdfe_bit:#x} for format {desc_format}")

    def copy(self, sdlba, blocks, slbs, **kwargs):
        """ Wrapper for nvme copy
            - Args:
                - sdlba : destination logical block address
                - blocks : number of logical blocks (0-based)
                - slbs : source range logical block address
                - descriptor_format : copy descriptor format (optional)
                - snsids : source namespace id (optional)
                - sopts : source options (optional)
            - Returns:
                - None
        """
        desc_format = kwargs.get("descriptor_format", 0)
        copy_cmd = f"{self.nvme_bin} copy {self.ns1} " + \
            f"--format={desc_format} --sdlba={sdlba} --blocks={blocks} " + \
            f"--slbs={slbs}"
        if "snsids" in kwargs:
            copy_cmd += f" --snsids={kwargs['snsids']}"
        if "sopts" in kwargs:
            copy_cmd += f" --sopts={kwargs['sopts']}"
        self.assertEqual(self.exec_cmd(copy_cmd), 0)


class TestNVMeCopyFormat0(TestNVMeCopy):

    """
    NVMe Copy tests using Descriptor Format 0.

    Format 0 uses 16-bit guard PI and copies within a single namespace.
    No special namespace formatting is required; the test is skipped if the
    current namespace is already using a non-16-bit-guard PI format and
    namespace management is not available to restore it.
    """

    def setUp(self):
        """ Pre Section for TestNVMeCopyFormat0 """
        super().setUp()
        self._check_16b_guard_ns()

    def test_copy_format_0(self):
        """ Test copy with descriptor format 0 """
        self._check_format_supported(0)
        self._check_ns_copy_limits()
        self.copy(0, 1, 2, descriptor_format=0)


class TestNVMeCopyFormat1(TestNVMeCopy):

    """
    NVMe Copy tests using Descriptor Format 1.

    Format 1 uses 64-bit guard PI and copies within a single namespace.
    setUp reformats the namespace to a 64-bit guard LBA format; the test is
    skipped if no such format is available or namespace management is not
    supported.
    """

    def setUp(self):
        """ Pre Section for TestNVMeCopyFormat1 """
        super().setUp()
        self._setup_64b_guard_ns()

    def test_copy_format_1(self):
        """ Test copy with descriptor format 1 """
        self._check_format_supported(1)
        self._check_ns_copy_limits()
        self.copy(0, 1, 2, descriptor_format=1)


class TestNVMeCopyFormat23(TestNVMeCopy):

    """
    NVMe Copy tests using Descriptor Formats 2 and 3.

    Formats 2 and 3 perform cross-namespace copy operations.
    Format 2 uses 16-bit guard PI and works with the default namespace.
    Format 3 uses 64-bit guard PI; those tests reformat the namespace inline
    (rather than in setUp) so that format 2 tests can still use the standard
    namespace.
    """

    def _run_format_3_copy(self, **kwargs):
        """
        Reformat the namespace to 64-bit guard PI, check copy limits, enable
        cdfe for format 3, then execute the copy command.

        Additional keyword arguments are forwarded to self.copy() (e.g. sopts).
        """
        self._setup_64b_guard_ns()
        self._check_ns_copy_limits()
        self._enable_cdfe_for_format(3)
        self.copy(0, 1, 2, descriptor_format=3, snsids=self.ns1_nsid, **kwargs)

    def test_copy_format_2(self):
        """ Test copy with descriptor format 2 """
        self._check_format_supported(2)
        self._check_16b_guard_ns()
        self._check_ns_copy_limits()
        self._enable_cdfe_for_format(2)
        self.copy(0, 1, 2, descriptor_format=2, snsids=self.ns1_nsid)

    def test_copy_format_2_sopts(self):
        """ Test copy with descriptor format 2 and source options """
        self._check_format_supported(2)
        self._check_16b_guard_ns()
        self._check_ns_copy_limits()
        self._enable_cdfe_for_format(2)
        self.copy(0, 1, 2, descriptor_format=2, snsids=self.ns1_nsid, sopts=0)

    def test_copy_format_3(self):
        """ Test copy with descriptor format 3 """
        self._check_format_supported(3)
        self._run_format_3_copy()

    def test_copy_format_3_sopts(self):
        """ Test copy with descriptor format 3 and source options """
        self._check_format_supported(3)
        self._run_format_3_copy(sopts=0)
