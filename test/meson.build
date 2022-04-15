# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>

# These tests all require interaction with a real NVMe device, so we don't
# define as meson unit-tests, and therefore get run as part of the 'test'
# target. However, they're available for developer use, when hardware is
# available.
main = executable(
    'main-test',
    ['test.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

cpp = executable(
    'test-cpp',
    ['cpp.cc'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

register = executable(
    'test-register',
    ['register.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

zns = executable(
    'test-zns',
    ['zns.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)
