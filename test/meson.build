# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
main = executable(
    'main-test',
    ['test.c'],
    dependencies: libuuid,
    link_with: libnvme,
    include_directories: incdir
)

cpp = executable(
    'test-cpp',
    ['cpp.cc'],
    link_with: libnvme,
    include_directories: incdir
)

register = executable(
    'test-register',
    ['register.c'],
    link_with: libnvme,
    include_directories: incdir
)

zns = executable(
    'test-zns',
    ['zns.c'],
    link_with: libnvme,
    include_directories: incdir
)

test('main', main)
test('main', main, args: ['nvme10'])
test('cpp', main)
test('register', main, args: ['nvme10'])
test('zns', main)
