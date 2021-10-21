# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#

################################################################################
# Building libnvme using meson and ninja:
#   meson .build
#   ninja -C .build
#
# Installing the code after building:
#   cd .build
#   sudo meson install
#
# Running unit tests:
#   cd .build
#   meson test
#
# In these examples, ".build" is the name of the directory where the build
# artifacts are saved. The directory need not be called ".build", but it must
# be a unique (non-existing) directory.
#
# Changing build options from the command line:
#   Build options can be changed at the command line without modifying the
#   "meson.build" files. This is particularly useful during debugging. For
#   example, the "buildtype" option allows to disable optimization to
#   facilitate debugging. This option can be specified on the command line as
#   follows:
#
#     meson .build -Dbuildtype=debug
#
#   Doing so overrides the value found in the meson.build, which is set to
#   "buildtype=release" below. The buildtype option can take any of the
#   following values.
#
#     plain:          no extra build flags are used, even for compiler warnings,
#                     useful for distro packagers and other cases where you need
#                     to specify all arguments by yourself
#
#     debug:          debug info is generated but the result is not optimized,
#                     this is the default
#
#     debugoptimized: debug info is generated and the code is optimized (on most
#                     compilers this means -g -O2)
#
#     release:        full optimization, no debug info
#
#   default_options:  https://mesonbuild.com/Builtin-options.html#compiler-options
#
#   Examples: meson .build -Dbuildtype=debug
#             meson .build -Db_sanitize=address
#             meson .build -Djson-c=true
#
# References: https://mesonbuild.com/
#             https://ninja-build.org/
#
################################################################################
project(
    'libnvme', ['c', 'cpp'],
    meson_version: '>= 0.47.0',
    version: 'v0.1',
    license: 'LGPLv2+',
    default_options: [
        'buildtype=release',
        'prefix=/usr',
    ]
)

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# https://autotools.io/libtool/version.html
# The relation between libtool's current:revison:age interface versioning
# and the .so filename, .so.x.y.z, is
# x = current - age
# y = age
# z = revision
# If libtool_soversion is updated as described in libtool's documentation,
# x.y.z will usually *not* be equal to meson.project_version().
libtool_soversion = [0, 0, 0]
libnvme_version = '@0@.@1@.@2@'.format(
  libtool_soversion[0] - libtool_soversion[2],
  libtool_soversion[2],
  libtool_soversion[1]
)

################################################################################
cc = meson.get_compiler('c')

prefixdir  = get_option('prefix')
libdir     = join_paths(prefixdir, get_option('libdir'))
includedir = join_paths(prefixdir, get_option('includedir'))
datadir    = join_paths(prefixdir, get_option('datadir'))
mandir     = join_paths(prefixdir, get_option('mandir'))
bindir     = join_paths(prefixdir, get_option('bindir'))

pkgconfiglibdir = get_option('pkgconfiglibdir') == '' ? join_paths(libdir, 'pkgconfig') : get_option('pkgconfiglibdir')

################################################################################
conf = configuration_data()

# Check for libuuid availability
libuuid = dependency('uuid', required: true)
conf.set('CONFIG_LIBUUID', libuuid.found(), description: 'Is libuuid required?')

# Check for json-c availability
json_c = dependency('json-c', version: '>=0.13', fallback : ['json-c', 'json_c'])
conf.set('CONFIG_JSONC', json_c.found(), description: 'Is json-c required?')

config_host_h = configure_file(
    output: 'config-host.h',
    configuration: conf
)

################################################################################
substs = configuration_data()
substs.set('NAME',    meson.project_name())
substs.set('VERSION', meson.project_version())
substs.set('LICENSE', meson.project_license()[0])
configure_file(
    input:         'libnvme.spec.in',
    output:        'libnvme.spec',
    configuration: substs,
)

################################################################################
add_project_arguments(['-fomit-frame-pointer', '-D_GNU_SOURCE', '-include', 'config-host.h'], language : 'c')
incdir = include_directories(['.', 'ccan', 'src'])

################################################################################
subdir('ccan')
subdir('src')
subdir('pynvme')
subdir('test')
subdir('examples')
subdir('doc')
