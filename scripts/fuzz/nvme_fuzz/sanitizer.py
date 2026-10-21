# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""What a sanitizer or libFuzzer reports about an input."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Frame:
    function: str
    # file:line, relative to the source tree where possible
    location: str


@dataclass(frozen=True, order=True)
class Finding:
    # e.g. heap-buffer-overflow, leak, timeout
    kind: str
    # The first nvme-cli frame or file:line, '-' if there is none
    location: str


# A frame symbolized by the sanitizer: "#3 0x55 in fn /src/x.c:12:3"
_SYMBOLIZED = re.compile(r'^\s+#(\d+) 0x[0-9a-f]+ in (\S+) (\S+?)(?::\d+)?$')
# A frame with a function, but in a library without debug information:
# "#3 0x55 in fn (/usr/lib64/libjson-c.so.5+0x538e)"
_FUNCTION = re.compile(r'^\s+#(\d+) 0x[0-9a-f]+ in (\S+) \(([^()+]+)\+0x')
# A frame which is not: "#3 0x55  (/build/fuzz-device+0x1234)"
_RAW = re.compile(r'^\s+#(\d+) 0x[0-9a-f]+ .*\(([^()+]+)\+(0x[0-9a-f]+)\)')

# Frames of the sanitizers, libFuzzer, the fuzz driver and the device mock
_SKIP_FUNCTIONS = (
    '__',
    'fuzzer::',
    'LLVMFuzzer',
    'main',
    'malloc',
    'calloc',
    'realloc',
    'free',
    'posix_memalign',
    'printf',
    'plugin_call_run',
    'run_command',
    'nvme_main',
)
_SKIP_LOCATIONS = (
    # the sanitizer runtimes, e.g. their printf()
    'compiler-rt',
    'sanitizer_common/',
    'asan/',
    'ubsan/',
    'libmock',
    'fuzz-driver',
    'fuzz-device.c',
    '??',
    'libc.so',
    'libjson-c',
    # the wrappers of json-c
    'nvme-json.h',
)


def _relative(path: str) -> str:
    """@path relative to the source tree: the compiler sees the sources
    as ../src/x.c from the build directory, or /build/dir/../src/x.c."""
    if '/../' in path:
        return path.rsplit('/../', 1)[1]
    return path.removeprefix('../')


def _addr2line(obj: str, offset: int) -> list[Frame]:
    """The frames at @offset of @obj, inlined functions included, the
    innermost first."""
    if not shutil.which('addr2line'):
        return [Frame('??', f'{obj}+{offset:#x}')]
    r = subprocess.run(
        ['addr2line', '-f', '-i', '-C', '-e', obj, hex(offset)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = r.stdout.splitlines()
    return [
        Frame(fn.strip(), _relative(loc.strip().split(' ')[0]))
        for fn, loc in zip(lines[::2], lines[1::2], strict=False)
    ]


def frames(report: str) -> list[Frame]:
    """The frames of the first stack in @report. Frames the sanitizer
    could not symbolize, as without llvm-symbolizer, go through
    addr2line."""
    res: list[Frame] = []
    for line in report.splitlines():
        sym = _SYMBOLIZED.match(line)
        fn = None if sym else _FUNCTION.match(line)
        raw = None if sym or fn else _RAW.match(line)
        m = sym or fn or raw
        if not m:
            if res and not line.strip():
                break
            continue
        if m.group(1) == '0' and res:
            break
        if sym:
            res.append(Frame(sym.group(2), _relative(sym.group(3))))
        elif fn:
            res.append(Frame(fn.group(2), Path(fn.group(3)).name))
        elif raw:
            res += _addr2line(raw.group(2), int(raw.group(3), 16) - 1)
    return res


# What runs from the signal to the frame which raised it
_CRASH_HANDLING = (
    '__sanitizer',
    'fuzzer::',
    '__sigaction',
    'pthread_kill',
    'gsignal',
    'raise',
    'abort',
    'perror',
    '__assert',
    '__GI_',
    '__libc_',
    '__restore_rt',
)


def stack(report: str) -> list[Frame]:
    """The frames of the first stack in @report, from where it went
    wrong to the input: without the crash handling and libFuzzer."""
    res = frames(report)
    while res and res[0].function.startswith(_CRASH_HANDLING):
        res.pop(0)
    for i, f in enumerate(res):
        if f.function.startswith('LLVMFuzzerTestOneInput'):
            return res[: i + 1]
    return res


def kind(report: str) -> str:
    """The kind of the finding in @report, 'none' without one."""
    if (
        'libFuzzer: timeout' in report
        or 'ALARM' in report
        or report == 'TIMEOUT'
    ):
        return 'timeout'
    if 'out-of-memory' in report:
        return 'oom'
    if 'LeakSanitizer: detected memory leaks' in report:
        return 'leak'
    m = re.search(r'SUMMARY: \w+Sanitizer: (\S+)', report)
    if m:
        return m.group(1)
    if 'runtime error:' in report:
        return 'undefined-behavior'
    if 'libFuzzer: deadly signal' in report:
        # An abort() without a sanitizer report, e.g. a failed assert()
        return 'assert' if 'Assertion' in report else 'signal'
    return 'none'


def classify(report: str) -> Finding:
    """The finding in @report and where it is."""
    k = kind(report)
    m = re.search(r'(\S+\.[ch]:\d+):\d+: runtime error', report)
    if m:
        return Finding(k, _relative(m.group(1)))
    if k in ('none', 'timeout', 'oom'):
        return Finding(k, '-')
    for f in frames(report):
        if f.function.startswith(_SKIP_FUNCTIONS) or any(
            s in f.location for s in _SKIP_LOCATIONS
        ):
            continue
        return Finding(k, f'{f.function} {f.location}')
    return Finding(k, '?')


def summary(report: str) -> list[str]:
    """The lines of @report which say what happened."""
    pat = re.compile(
        r'ERROR|runtime error|SUMMARY|Direct leak|READ of|'
        r'WRITE of|Assertion'
    )
    return [line for line in report.splitlines() if pat.search(line)]
