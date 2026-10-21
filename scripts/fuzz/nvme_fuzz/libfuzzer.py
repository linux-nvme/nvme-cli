# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""Running a libFuzzer binary on given inputs."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from .targets import sanitizer_env


def replay(binary: Path, path: Path, timeout: int = 20) -> tuple[int, str]:
    """Run @binary on the input @path once. Returns the exit status, -1 on
    a hang, and what it reported."""
    try:
        r = subprocess.run(
            [
                str(binary),
                '-close_fd_mask=3',
                f'-timeout={timeout}',
                str(path),
            ],
            env=sanitizer_env(dict(os.environ)),
            capture_output=True,
            text=True,
            errors='replace',
            timeout=timeout * 6,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return -1, 'TIMEOUT'
    return r.returncode, r.stderr


def coverage(binary: Path, inputs: Iterable[bytes]) -> int:
    """The number of edges @binary reaches with @inputs, -1 if it fails on
    one of them."""
    with tempfile.TemporaryDirectory(prefix='nvme-fuzz-cov-') as tmp:
        corpus = Path(tmp) / 'corpus'
        corpus.mkdir()
        for i, data in enumerate(inputs):
            (corpus / str(i)).write_bytes(data)
        # Findings are not of interest here, only how far the inputs go.
        # In its own directory, so nothing it writes stays behind.
        env = dict(
            os.environ,
            ASAN_OPTIONS='allocator_may_return_null=1:'
            'max_allocation_size_mb=1024:'
            'detect_leaks=0',
            UBSAN_OPTIONS='halt_on_error=0',
        )
        r = subprocess.run(
            [str(binary), '-runs=0', '-close_fd_mask=3', str(corpus)],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            errors='replace',
            check=False,
        )
    m = re.findall(r'INITED cov: (\d+)', r.stderr)
    return int(m[-1]) if m else -1


def inputs_of(paths: Iterable[Path]) -> list[Path]:
    """The input files of @paths, files or directories of them. Slow units
    are no findings."""
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files += sorted(
                f
                for f in p.iterdir()
                if f.is_file() and not f.name.startswith('slow-unit-')
            )
        else:
            files.append(p)
    return files


def copy_new(src: Path, dst: Path) -> int:
    """Copy the files of @src which @dst does not have. Returns how many."""
    n = 0
    for f in src.iterdir():
        if f.is_file() and not (dst / f.name).exists():
            shutil.copy(f, dst / f.name)
            n += 1
    return n
