# SPDX-License-Identifier: LGPL-2.1-or-later

# Copied from https://github.com/python-sdbus/python-sdbus
# Copyright (C) 2020, 2021 igo95862

# This file is part of nvme-cli

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
from __future__ import annotations

from argparse import ArgumentParser
from os import environ
from pathlib import Path
from subprocess import run
from typing import List

source_root = Path(environ['MESON_SOURCE_ROOT'])
build_dir = Path(environ['MESON_BUILD_ROOT'])

tests_dir = source_root / 'tests'

all_python_modules = [
    tests_dir,
]

mypy_cache_dir = build_dir / '.mypy_cache'


def run_mypy(path: Path) -> None:
    print(f"Running mypy on {path}")
    run(
        args=(
            'mypy', '--strict',
            '--cache-dir', mypy_cache_dir,
            '--python-version', '3.8',
            '--namespace-packages',
            '--ignore-missing-imports',
            path,
        ),
        check=False,
        env={'MYPYPATH': str(tests_dir.absolute()), **environ},
    )


def linter_main() -> None:
    run(
        args=(
            'flake8',
            *all_python_modules,
        ),
        check=False,
    )

    for x in all_python_modules:
        run_mypy(x)


def get_all_python_files() -> List[Path]:
    python_files: List[Path] = []

    for python_module in all_python_modules:
        if python_module.is_dir():
            for a_file in python_module.iterdir():
                if a_file.suffix == '.py':
                    python_files.append(a_file)
        else:
            python_files.append(python_module)

    return python_files


def formater_main() -> None:
    all_python_files = get_all_python_files()

    run(
        args=('autopep8', '--in-place', *all_python_files),
        check=False,
    )

    run(
        args=(
            'isort',
            '-m', 'VERTICAL_HANGING_INDENT',
            '--trailing-comma',
            *all_python_files,
        ),
        check=False,
    )


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument(
        'mode',
        choices=('lint', 'format'),
    )

    args = parser.parse_args()

    mode = args.mode

    if mode == 'lint':
        linter_main()
    elif mode == 'format':
        formater_main()
    else:
        raise ValueError('Unknown mode', mode)


if __name__ == '__main__':
    main()
