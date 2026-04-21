# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# The accessor files (accessors.h, accessors.c, accessors.ld) are
# pre-generated and committed to the source tree.  They are NOT
# regenerated during a normal build.
#
# To regenerate them after changing private.h (e.g. adding or removing
# a // !generate-accessors annotation):
#
#   meson compile -C <build-dir> update-accessors

# ---------------------------------------------------------------------------
# Developer-only helper: run the generator and regenerate if structs change.
# NOT executed during a normal build (build_by_default: false).
# Usage: meson compile -C <build-dir> update-accessors
# ---------------------------------------------------------------------------

# Generated source files go to src/nvme/ (alongside the library sources).
# The generated version script goes to src/ (alongside the other .ld files).
# The generated SWIG include goes to libnvme/ (alongside nvme.i).
libnvme_src = libnvme_srcroot / 'src'
libnvme_src_nvme = libnvme_src / 'nvme'
libnvme_swig_dir = libnvme_srcroot / 'libnvme'

_py3 = find_program('python3', required: true)

_tgt_common = run_target(
    'update-common-accessors',
    command: [
        'update-accessors.sh',
        _py3,
        files('generate-accessors.py'),
        libnvme_src_nvme / 'accessors.h',
        libnvme_src_nvme / 'accessors.c',
        libnvme_src / 'accessors.ld',
        libnvme_src_nvme / 'private.h',
    ],
)

_tgt_fabrics = run_target(
    'update-fabrics-accessors',
    command: [
        'update-accessors.sh',
        _py3,
        files('generate-accessors.py'),
        libnvme_src_nvme / 'accessors-fabrics.h',
        libnvme_src_nvme / 'accessors-fabrics.c',
        libnvme_src / 'accessors-fabrics.ld',
        libnvme_src_nvme / 'private-fabrics.h',
    ],
)

_tgt_swig = run_target(
    'update-swig-accessors',
    command: [
        _py3,
        files('generate-swig-accessors.py'),
        '--output', libnvme_swig_dir / 'nvme-swig-accessors.i',
        libnvme_src_nvme / 'accessors.h',
        libnvme_src_nvme / 'accessors-fabrics.h',
    ],
)

# This alias allows generating all accessors in one shot.
alias_target('update-accessors', _tgt_common, _tgt_fabrics, _tgt_swig)
