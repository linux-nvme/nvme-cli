# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""nvme-fuzz build: a clang build of the fuzz targets for libFuzzer."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from .targets import SOURCE_ROOT, TARGETS


def compilers(env: dict[str, str]) -> tuple[str, str]:
    """The C and C++ compiler: CC if it names a clang, e.g. clang-19, with
    CXX or the clang++ of the same version, and clang and clang++ else.
    The sanitizer runtimes of both must match."""
    cc = env.get('CC', '')
    if 'clang' not in cc:
        return 'clang', 'clang++'
    return cc, env.get('CXX') or cc.replace('clang', 'clang++', 1)


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        '--buildtype',
        default='debugoptimized',
        help='meson build type (%(default)s: optimized, with '
        'the source lines in the reports)',
    )
    p.add_argument(
        'meson_options',
        nargs='*',
        metavar='-Dopt=value',
        help='more options for meson setup, after --',
    )


def main(args: argparse.Namespace) -> int:
    build_dir: Path = args.build_dir
    cc, cxx = compilers(dict(os.environ))
    env = dict(os.environ, CC=cc, CXX=cxx)
    options = [
        '--werror',
        f'--buildtype={args.buildtype}',
        '-Dfuzzing=true',
        '-Db_sanitize=address,undefined',
        # clang links the sanitizer runtime only into executables
        '-Db_lundef=false',
        *args.meson_options,
    ]
    if (build_dir / 'meson-private').is_dir():
        setup = ['meson', 'setup', '--reconfigure', *options, str(build_dir)]
    else:
        setup = ['meson', 'setup', *options, str(build_dir)]
    print(f'CC={cc} CXX={cxx} {" ".join(setup)}', flush=True)
    r = subprocess.run(setup, cwd=SOURCE_ROOT, env=env, check=False)
    if r.returncode:
        return r.returncode
    # Only the fuzz targets, and what they need
    names = [f'tests/fuzz/{n}' for n in built_targets(build_dir)]
    if not names:
        print('no fuzz targets in this configuration')
        return 1
    r = subprocess.run(
        ['meson', 'compile', '-C', str(build_dir), *names],
        env=env,
        check=False,
    )
    return r.returncode


def built_targets(build_dir: Path) -> list[str]:
    """The fuzz targets the configuration of @build_dir has: not all
    configurations have the device mock, or fabrics."""
    r = subprocess.run(
        ['meson', 'introspect', '--targets', str(build_dir)],
        capture_output=True,
        text=True,
        check=True,
    )
    names = {t['name'] for t in json.loads(r.stdout)}
    return [f'fuzz-{t}' for t in TARGETS if f'fuzz-{t}' in names]
