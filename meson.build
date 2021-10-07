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
    version: '0.1',
    license: 'LGPLv2+',
    default_options: [
        'buildtype=release',
        'prefix=/usr',
    ]
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

# Check for libjson-c availability
libjson = dependency('json-c', required: false)
if not libjson.found()
    libjson = cc.find_library('json-c', required: true)
endif
conf.set('CONFIG_JSONC', libjson.found(), description: 'Is json-c required?')

# Check for libsystemd availability
want_systemd = get_option('systemd')
if want_systemd != 'false'
    libsystemd = dependency('libsystemd', required: want_systemd == 'true')
    have = libsystemd.found()
else
    libsystemd = []
    have = false
endif
conf.set('CONFIG_SYSTEMD', have, description: 'Is libsystemd required?')

################################################################################
# The following commented-out text is the beginning of an effort to replace
# ccan/tools/configurator. It is not complete yet. Eventually we would like
# to replace everything that ccan/tools/configurator does with meson.
# To be continued...
################################################################################
#args = ['-g3', '-ggdb', '-Wall', '-Wundef', '-Wmissing-prototypes', '-Wmissing-declarations', '-Wstrict-prototypes', '-Wold-style-definition']
#conf.set10(
#    'HAVE_STRUCT_TIMESPEC',
#    cc.compiles(
#        '''
#            #include <time.h>
#            static void func(void) {
#                struct timespec ts;
#                ts.tv_sec = ts.tv_nsec = 1;
#            }
#            int main(int argc, char *argv[]) {
#                (void)func();
#                return 0;
#            }
#        ''',
#        no_builtin_args: true,
#        args: args,
#        name: 'struct timespec'
#    ),
#    description: 'Is struct timespec defined?'
#)
#conf.set10(
#    'HAVE_ASPRINTF',
#    cc.compiles(
#        '''
#            #define _GNU_SOURCE
#            #include <stdio.h>
#            static char *func(int x) {
#                char *p;
#                if (asprintf(&p, "%u", x) == -1)
#                    p = NULL;
#                return p;
#            }
#            int main(int argc, char *argv[]) {
#                (void)func(1000);
#                return 0;
#            }
#        ''',
#        no_builtin_args: true,
#        args: args,
#        name: 'asprintf()'
#    ),
#    description: 'Is asprintf() supported?'
#)

configure_file(
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
pkg = import('pkgconfig')
pkg.generate(
    filebase: meson.project_name(),
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'Manage "libnvme" subsystem devices (Non-volatile Memory Express)',
    url: 'http://github.com/linux-nvme/libnvme/',
    libraries: ['-L${libdir}', '-lnvme'],
    requires: [libuuid, libjson, libsystemd],
)

################################################################################
add_project_arguments('-include', 'config-host.h', language : 'c')
add_global_arguments(['-fomit-frame-pointer', '-D_GNU_SOURCE'], language : 'c')
incdir = include_directories(['ccan', 'src'])

################################################################################
subdir('ccan')
subdir('src')
subdir('pynvme')
subdir('test')
subdir('examples')
subdir('doc')

