# SPDX-License-Identifier: BSD-3
#
# This file is part of STorage Appliance Services (STAS).
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#

# Requires python3-sphinx and python3-sphinx-rtd-theme

sphinx_sources = [
    'conf.py',
    'libnvme.rst',
    'index.rst'
]

man_pages = [
    'libnvme.1'
]

mandir1 = join_paths(get_option('mandir'), 'man1')

if get_option('man')
    sphinx_build = find_program('sphinx-build-3', 'sphinx-build')

    custom_target(
        'man',
        command: [sphinx_build,
                   '-b', 'man',
                   meson.current_source_dir(),
                   meson.current_build_dir()],
        input: sphinx_sources,
        output: man_pages,
        install: true,
        install_dir: mandir1,
    )
endif
