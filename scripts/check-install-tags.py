#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
"""Fail if a file that meson installs has no install tag.

"meson install --tags" skips a file without a tag. Packagers who split
nvme-cli with tags would then lose that file. See the "Install tags"
section in Documentation/BUILDING.md.

Files of subprojects (meson wraps) are not checked: their tags are set
by the subproject, not by nvme-cli.

Usage: check-install-tags.py BUILDDIR

Exits with 77 (skipped, for meson test) when BUILDDIR has no meson
install plan. muon writes the plan as a list, not in meson's format,
so a muon build is skipped too.
"""

import json
import pathlib
import sys


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    plan_file = pathlib.Path(sys.argv[1], 'meson-info',
                             'intro-install_plan.json')
    if not plan_file.is_file():
        return 77

    with open(plan_file) as f:
        plan = json.load(f)
    if not isinstance(plan, dict):
        return 77

    untagged = sorted(
        info['destination']
        for files in plan.values()
        for info in files.values()
        if not info.get('tag') and not info.get('subproject')
    )
    for dest in untagged:
        print(f'no install tag: {dest}', file=sys.stderr)

    return 1 if untagged else 0


if __name__ == '__main__':
    sys.exit(main())
