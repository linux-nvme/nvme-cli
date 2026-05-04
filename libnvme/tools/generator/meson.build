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
# The generated SWIG includes and Python-only headers go to libnvme/ alongside
# nvme.i.
libnvme_src = libnvme_srcroot / 'src'
libnvme_src_nvme = libnvme_src / 'nvme'
libnvme_swig_dir = libnvme_srcroot / 'libnvme'

_py3 = find_program('python3', required: true)

# When -Dcheck-accessors=true the script runs in read-only CI mode: it exits
# non-zero if any generated file is out of sync with the source tree rather
# than updating it.
_check_flag = get_option('check-accessors') ? ['--check'] : []

_tgt_common = run_target(
    'update-common-accessors',
    command: [
        'update-accessors.sh',
        _py3,
        files('generate-accessors.py'),
        libnvme_src_nvme / 'accessors.h',
        libnvme_src_nvme / 'accessors.c',
        libnvme_src / 'accessors.ld',
    ] + _check_flag + [
        '--swig-out', libnvme_swig_dir / 'accessors.i',
        '--dict-table-out', libnvme_swig_dir / 'fctx_field_tables.h',
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
    ] + _check_flag + [
        '--swig-out', libnvme_swig_dir / 'accessors-fabrics.i',
        libnvme_src_nvme / 'private-fabrics.h',
    ],
)

# This alias allows generating/checking all accessors in one shot.
alias_target('update-accessors', _tgt_common, _tgt_fabrics)
