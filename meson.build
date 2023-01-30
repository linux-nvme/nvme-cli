# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
project(
    'libnvme', ['c'],
    meson_version: '>= 0.50.0',
    version: '1.3',
    license: 'LGPL-2.1-or-later',
    default_options: [
        'c_std=gnu99',
        'warning_level=1',
        'buildtype=debug',
        'prefix=/usr/local',
    ]
)

maj_min = meson.project_version().split('-rc')[0]
library_version =  maj_min + '.0'

################################################################################
cc = meson.get_compiler('c')
cxx_available = add_languages('cpp', required: false)

prefixdir  = get_option('prefix')
libdir     = join_paths(prefixdir, get_option('libdir'))
includedir = join_paths(prefixdir, get_option('includedir'))
datadir    = join_paths(prefixdir, get_option('datadir'))
mandir     = join_paths(prefixdir, get_option('mandir'))
bindir     = join_paths(prefixdir, get_option('bindir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))

################################################################################
conf = configuration_data()

version_tag = get_option('version-tag')
if version_tag != ''
        conf.set('GIT_VERSION', '"@0@"'.format(version_tag))
else
    r = run_command('meson-vcs-tag.sh',
                    meson.current_source_dir(),
                    meson.project_version(),
                    check: true)
    conf.set('GIT_VERSION', '"@0@"'.format(r.stdout().strip()))
endif
conf.set('PROJECT_VERSION', '"@0@"'.format(meson.project_version()))

conf.set('SYSCONFDIR', '"@0@"'.format(sysconfdir))

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
  conf.set('CONFIG_OPENSSL', true,
           description: 'Is OpenSSL/LibreSSL available?')

  if openssl_dep.version().version_compare('<2.0.0')
    api_version = 1
  endif

  if openssl_dep.version().version_compare('>=3.0.0')
    api_version = 3

    # Test for LibreSSL v3.x with incomplete OpenSSL v3 APIs
    is_libressl = cc.has_header_symbol('openssl/opensslv.h',
                                       'LIBRESSL_VERSION_NUMBER',
                                       dependencies: openssl_dep)
    has_header = cc.has_header('openssl/core_names.h',
                               dependencies: openssl_dep)
    if is_libressl and not has_header
      api_version = 1
    endif

  endif

  conf.set('CONFIG_OPENSSL_@0@'.format(api_version), true,
           description: 'OpenSSL/LibreSSL API version @0@'.format(api_version))
endif

if get_option('libdbus').disabled()
    libdbus_dep = dependency('', required: false)
else
    # Check for libdus availability. Optional, only required for MCTP dbus scan
    libdbus_dep = dependency(
        'dbus-1',
        required: true,
        fallback: ['dbus', 'libdbus_dep'],
        default_options: [
            'default_library=static',
            'embedded_tests=false',
            'message_bus=false',
            'modular_tests=disabled',
            'tools=false',
        ],
    )
endif

conf.set('CONFIG_DBUS', libdbus_dep.found(), description: 'Enable dbus support?')

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
    host_machine.endian() == 'little',
    description: 'Building for little-endian'
)
conf.set10(
    'HAVE_BIG_ENDIAN',
    host_machine.endian() == 'big',
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
conf.set10(
    'HAVE_LINUX_MCTP_H',
    cc.compiles(
        '''#include <linux/mctp.h>''',
        name: 'linux/mctp.h'
    ),
    description: 'Is linux/mctp.h include-able?'
)

conf.set(
    'HAVE_LIBNSS',
    cc.links(
      '''int main(int argc, char **argv) {
             struct addrinfo hints, *result;
             return getaddrinfo(argv[1], argv[2], &hints, &result);
      }
      ''',
      name: 'libnss',
    ),
    description: 'Is network address and service translation available'
)

if cc.has_function_attribute('fallthrough')
  conf.set('fallthrough', '__attribute__((__fallthrough__))')
else
  conf.set('fallthrough', 'do {} while (0) /* fallthrough */')
endif

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
