# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
project(
    'libnvme', ['c', 'cpp'],
    meson_version: '>= 0.47.0',
    version: '1.0',
    license: 'LGPLv2+',
    default_options: [
        'c_std=gnu99',
        'warning_level=1',
        'buildtype=release',
        'prefix=/usr',
    ]
)

library_version = meson.project_version() + '.0'

################################################################################
cc = meson.get_compiler('c')

prefixdir  = get_option('prefix')
libdir     = join_paths(prefixdir, get_option('libdir'))
includedir = join_paths(prefixdir, get_option('includedir'))
datadir    = join_paths(prefixdir, get_option('datadir'))
mandir     = join_paths(prefixdir, get_option('mandir'))
bindir     = join_paths(prefixdir, get_option('bindir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))

pkgconfiglibdir = get_option('pkgconfiglibdir') == '' ? join_paths(libdir, 'pkgconfig') : get_option('pkgconfiglibdir')

################################################################################
conf = configuration_data()

conf.set('SYSCONFDIR', '"@0@"'.format(sysconfdir))

# Check for libuuid availability
libuuid_dep = dependency('uuid', required: true)
conf.set('CONFIG_LIBUUID', libuuid_dep.found(), description: 'Is libuuid required?')

# Check for json-c availability
json_c_dep = dependency('json-c',
			version: '>=0.13',
			required: true,
			fallback : ['json-c', 'json_c_dep'])
conf.set('CONFIG_JSONC', json_c_dep.found(), description: 'Is json-c required?')

# Check for OpenSSL availability
openssl_dep = dependency('openssl',
                         version: '>=1.1.0',
                         required: get_option('openssl'),
                         fallback : ['openssl', 'libssl_dep'])
if openssl_dep.found()
  conf.set('CONFIG_OPENSSL', true, description: 'Is OpenSSL available?')
  conf.set('CONFIG_OPENSSL_1',
           openssl_dep.version().version_compare('<2.0.0') and
           openssl_dep.version().version_compare('>=1.1.0'),
           description: 'OpenSSL version 1.x')
  conf.set('CONFIG_OPENSSL_3',
           openssl_dep.version().version_compare('>=3.0.0'),
           description: 'OpenSSL version 3.x')
endif

# local (cross-compilable) implementations of ccan configure steps
conf.set10(
    'HAVE_BUILTIN_TYPES_COMPATIBLE_P',
    cc.compiles(
        '''int main(void) {
               return __builtin_types_compatible_p(int, long);
           }
        ''',
        name: '__builtin_type_compatible_p'
    ),
    description: 'Is __builtin_types_compatible_p available?'
)
conf.set10(
    'HAVE_TYPEOF',
    cc.compiles(
        '''int main(void) {
                int a = 1;
                typeof(a) b;
                b = a;
           }
        ''',
        name: 'typeof'
    ),
    description: 'Is typeof available?'
)
conf.set10(
    'HAVE_BYTESWAP_H',
    cc.compiles(
        '''#include <byteswap.h>''',
        name: 'byteswap.h'
    ),
    description: 'Is byteswap.h include-able?'
)
conf.set10(
    'HAVE_BSWAP_64',
    cc.links(
        '''#include <byteswap.h>
            int main(void) {
                return bswap_64(0);
            }
        ''',
        name: 'bswap64'
    ),
    description: 'Is bswap_64 available?'
)
conf.set10(
    'HAVE_LITTLE_ENDIAN',
    build_machine.endian() == 'little',
    description: 'Building for little-endian'
)
conf.set10(
    'HAVE_BIG_ENDIAN',
    build_machine.endian() == 'big',
    description: 'Building for big-endian'
)
conf.set10(
    'HAVE_STATEMENT_EXPR',
    cc.compiles(
        '''int main(int argc, char **argv) {
               return ({ int x = argc; x == 1; });
           }
        ''',
        name: 'statement-expr'
    ),
    description: 'Can we use a statement as an expression?'
)
conf.set10(
    'HAVE_ISBLANK',
    cc.links(
        '''#include <ctype.h>
           int main(int argc, char **argv) {
               return isblank(argv[0][0]);
           }
        ''',
        name: 'isblank'
    ),
    description: 'Is isblank() available?'
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
add_project_arguments(
    [
        '-fomit-frame-pointer',
        '-D_GNU_SOURCE',
        '-include', 'internal/config.h',
    ],
    language : 'c',
)
incdir = include_directories(['.', 'ccan', 'src'])

################################################################################
subdir('internal')
subdir('ccan')
subdir('src')
subdir('libnvme')
subdir('test')
subdir('examples')
subdir('doc')
