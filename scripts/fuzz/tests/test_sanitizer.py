# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Tests for telling what a sanitizer or libFuzzer reports."""

import unittest

from nvme_fuzz import sanitizer
from nvme_fuzz.sanitizer import Finding

UBSAN = """\
../plugins/memblaze/memblaze-nvme.c:1362:59: runtime error: left shift of \
255 by 24 places cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior \
../plugins/memblaze/memblaze-nvme.c:1362:59
"""

LEAK = """\
==44575==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 2016 byte(s) in 42 object(s) allocated from:
    #0 0x55c957ac4dc7 in malloc /build/llvm/asan_malloc_linux.cpp:68:3
    #1 0x7f146dd6338e in json_object_new_object (/usr/lib64/libjson-c.so.5+\
0x538e) (BuildId: e84a)
    #2 0x55c957d64324 in json_print_smart_log \
/root/nvme-cli/.build-ci/../plugins/seagate/seagate-nvme.c:466:30
    #3 0x55c957d63429 in vs_smart_log \
/root/nvme-cli/.build-ci/../plugins/seagate/seagate-nvme.c:984:5
    #4 0x55c957bc4441 in run_command /root/nvme-cli/.build-ci/../src/\
plugin.c:477:8

SUMMARY: AddressSanitizer: 2016 byte(s) leaked in 42 allocation(s).
"""

ASAN = """\
==44747==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f30
READ of size 519 at 0x7f30780baad0 thread T0
    #0 0x55939fa8f513 in printf_common(void*, char const*, __va_list_tag*) \
/build/llvm/sanitizer_common_interceptors_format.inc:563:9
    #1 0x55939fa911cf in printf /build/llvm/sanitizer_common_interceptors\
.inc:1710:1
    #2 0x55939fcbad0e in get_market_log /root/nvme-cli/.build-ci/../plugins/\
intel/intel-nvme.c:423:4
    #3 0x55939fc0a441 in run_command /root/nvme-cli/.build-ci/../src/\
plugin.c:477:8

SUMMARY: AddressSanitizer: stack-buffer-overflow \
/root/nvme-cli/.build-ci/../plugins/intel/intel-nvme.c:423:4 in get_market_log
"""

ASSERT = """\
fuzz-device: json_object.c:709: json_object_object_add_ex: Assertion \
`json_object_get_type(jso) == json_type_object' failed.
==225390== ERROR: libFuzzer: deadly signal
"""

SIGNAL_STACK = """\
==1== ERROR: libFuzzer: deadly signal
    #0 0x55 in __sanitizer_print_stack_trace /llvm/asan_stack.cpp:87:3
    #1 0x55 in fuzzer::PrintStackTrace() /llvm/FuzzerUtil.cpp:210:5
    #2 0x7f in gsignal (/usr/lib/libc.so.6+0x44d47)
    #3 0x7f in abort (/usr/lib/libc.so.6+0x257c0)
    #4 0x7f in __assert_fail (/usr/lib/libc.so.6+0x3b253)
    #5 0x55 in json_directive_show /b/../src/nvme-print-json.c:5455:3
    #6 0x55 in dir_receive /b/../plugins/dir/dir-plugin.c:274:2
    #7 0x55 in LLVMFuzzerTestOneInput /b/../tests/fuzz/fuzz-device.c:528:2
    #8 0x55 in fuzzer::Fuzzer::ExecuteCallback /llvm/FuzzerLoop.cpp:614:13
"""


class ClassifyTest(unittest.TestCase):
    def test_ubsan(self) -> None:
        self.assertEqual(
            sanitizer.classify(UBSAN),
            Finding(
                'undefined-behavior', 'plugins/memblaze/memblaze-nvme.c:1362'
            ),
        )

    def test_leak(self) -> None:
        self.assertEqual(
            sanitizer.classify(LEAK),
            Finding(
                'leak',
                'json_print_smart_log plugins/seagate/seagate-nvme.c:466',
            ),
        )

    def test_asan(self) -> None:
        self.assertEqual(
            sanitizer.classify(ASAN),
            Finding(
                'stack-buffer-overflow',
                'get_market_log plugins/intel/intel-nvme.c:423',
            ),
        )

    def test_sanitizer_runtime(self) -> None:
        """The frames of the sanitizer runtime, as an intercepted
        snprintf(), are no nvme-cli frames."""
        report = (
            '==1==ERROR: AddressSanitizer: heap-buffer-overflow on x\n'
            '    #0 0x55 in vsnprintf /b/../sanitizer_common/'
            'sanitizer_common_interceptors.inc:1660:1\n'
            '    #1 0x55 in amzn_id_ctrl /b/../plugins/amzn/amzn-nvme.c'
            ':122:2\n'
            'SUMMARY: AddressSanitizer: heap-buffer-overflow x\n'
        )
        self.assertEqual(
            sanitizer.classify(report),
            Finding(
                'heap-buffer-overflow',
                'amzn_id_ctrl plugins/amzn/amzn-nvme.c:122',
            ),
        )

    def test_assert(self) -> None:
        self.assertEqual(sanitizer.kind(ASSERT), 'assert')

    def test_timeout_and_none(self) -> None:
        self.assertEqual(
            sanitizer.classify('TIMEOUT'), Finding('timeout', '-')
        )
        self.assertEqual(
            sanitizer.classify('==1== ERROR: libFuzzer: timeout after 10 s'),
            Finding('timeout', '-'),
        )
        self.assertEqual(
            sanitizer.classify('Executed x in 1 ms'), Finding('none', '-')
        )

    def test_frames(self) -> None:
        self.assertEqual(
            [f.function for f in sanitizer.frames(LEAK)],
            [
                'malloc',
                'json_object_new_object',
                'json_print_smart_log',
                'vs_smart_log',
                'run_command',
            ],
        )

    def test_stack(self) -> None:
        report = SIGNAL_STACK
        self.assertEqual(
            [f.function for f in sanitizer.stack(report)],
            ['json_directive_show', 'dir_receive', 'LLVMFuzzerTestOneInput'],
        )

    def test_summary(self) -> None:
        self.assertEqual(
            sanitizer.summary(ASAN),
            [
                ASAN.splitlines()[0],
                ASAN.splitlines()[1],
                ASAN.splitlines()[-1],
            ],
        )


if __name__ == '__main__':
    unittest.main()
