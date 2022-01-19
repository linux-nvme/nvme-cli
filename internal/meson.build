# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2022 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
# Because libnvme is used as a subproject of nvme-cli,
# the config.h file must be generated as a private file
# hidden from nvme-cli.

config_h = configure_file(
    output: 'config.h',
    configuration: conf
)

internal_incdir = include_directories('.')

config_dep = declare_dependency(
  include_directories : internal_incdir,
  sources: config_h)
