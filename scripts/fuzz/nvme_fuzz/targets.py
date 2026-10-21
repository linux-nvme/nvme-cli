# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE Software Solutions
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The fuzz targets in tests/fuzz and where their files are."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

# this file is scripts/fuzz/nvme_fuzz/ of the source tree
SOURCE_ROOT = Path(__file__).resolve().parents[3]
FUZZ_DIR = SOURCE_ROOT / 'tests' / 'fuzz'


@dataclass(frozen=True)
class Target:
    """A fuzz target and the libFuzzer options it runs with."""

    name: str
    # A dictionary in tests/fuzz, if any
    dictionary: str | None = None
    options: tuple[str, ...] = ()

    @property
    def seeds(self) -> Path:
        return FUZZ_DIR / 'corpus' / self.name

    def binary(self, build_dir: Path) -> Path:
        return build_dir / 'tests' / 'fuzz' / f'fuzz-{self.name}'

    def libfuzzer_options(self) -> list[str]:
        opts = list(self.options)
        if self.dictionary:
            opts.append(f'-dict={FUZZ_DIR / self.dictionary}')
        return opts


TARGETS: dict[str, Target] = {
    t.name: t
    for t in (
        Target('argconfig', 'argconfig.dict'),
        Target('ini', 'config.dict'),
        Target('global-config', 'config.dict'),
        Target('fabrics-conf', 'config.dict'),
        # It reads log pages, so it needs longer inputs. Large but valid logs
        # take seconds under ASan: only a much slower input is a hang.
        Target('device', options=('-max_len=16384', '-timeout=10')),
    )
}


def parse_targets(spec: str) -> list[Target]:
    """The targets of a comma-separated list of names."""
    targets = []
    for name in spec.split(','):
        if name not in TARGETS:
            raise argparse.ArgumentTypeError(
                f"unknown fuzz target '{name}', one of: {', '.join(TARGETS)}"
            )
        targets.append(TARGETS[name])
    return targets


# ASan and UBSan settings for a fuzz target. A device reports sizes of up
# to gigabytes: let ASan fail such an allocation instead of libFuzzer
# aborting as out of memory. A UBSan finding is a crash too.
SANITIZER_ENV = {
    'ASAN_OPTIONS': 'allocator_may_return_null=1:max_allocation_size_mb=1024',
    'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1',
}


def sanitizer_env(base: dict[str, str]) -> dict[str, str]:
    """@base with the sanitizer settings added to what it sets."""
    env = dict(base)
    for key, value in SANITIZER_ENV.items():
        env[key] = f'{env[key]}:{value}' if env.get(key) else value
    return env
