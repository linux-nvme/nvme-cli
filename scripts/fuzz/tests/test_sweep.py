# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for nvme-fuzz sweep."""

import struct
import unittest

from nvme_fuzz import device, sweep
from nvme_fuzz.libfuzzer import Result

ASAN = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x55 in wdc_print_log /src/build/../plugins/wdc/wdc-nvme.c:12:3
SUMMARY: AddressSanitizer: heap-buffer-overflow x
"""


class InputsTest(unittest.TestCase):
    def test_variants(self) -> None:
        plain = device.Command(5, ('id', 'ctrl'), None, False)
        ins = sweep.inputs(plain, 2)
        self.assertEqual(len(ins), 5 * 2)
        self.assertEqual(sorted({i[1] for i in ins}), [0, 1, 2, 3, 4])
        self.assertTrue(all(i[0] == 5 for i in ins))
        # the same each time
        self.assertEqual(ins, sweep.inputs(plain, 2))

        arg = device.Command(6, ('id', 'ns'), '--namespace-id', False)
        variants = sorted({i[1] for i in sweep.inputs(arg, 1)})
        self.assertEqual(variants, [0, 1, 2, 3, 4, 9, 11])

    def test_pci_ids(self) -> None:
        cmd = device.Command(7, ('micron', 'vs-drive-info'), None, True)
        ins = sweep.inputs(cmd, 3)
        ids = [struct.unpack_from('<HH', i, 3) for i in ins]
        # each input the next model of the plugin, round robin
        models = device.PCI_IDS['micron']
        self.assertEqual(
            ids, [models[n % len(models)] for n in range(len(ins))]
        )


class ProblemTest(unittest.TestCase):
    def test_problem(self) -> None:
        def p(status: int, report: str, seconds: float, *files: str) -> str:
            return str(
                sweep.problem(Result(status, report, seconds, files), 10)
            )

        self.assertEqual(p(0, '', 0.1), 'None')
        self.assertEqual(
            p(1, ASAN, 0.1, 'crash-1'),
            'heap-buffer-overflow wdc_print_log plugins/wdc/wdc-nvme.c:12',
        )
        self.assertEqual(p(0, '', 0.1, 'log.bin'), 'wrote log.bin')
        self.assertEqual(p(0, '', 11), 'slow')


if __name__ == '__main__':
    unittest.main()
