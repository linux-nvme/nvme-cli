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
    version: '1.9',
    license: 'LGPL-2.1-or-later',
    default_options: [
        'c_std=gnu99',
        'warning_level=1',
        'buildtype=debugoptimized',
        'prefix=/usr/local',
        'sysconfdir=etc',
        'wrap_mode=nofallback'
    ]
)

vstr = meson.project_version().split('-rc')[0]
vid = vstr.split('.')
library_version = '.'.join([vid[0], vid[1]])
if vid.length() == 3
  library_version = '.'.join([library_version, vid[2]])
else
  library_version = library_version + '.0'
endif

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
    r = run_command('scripts/meson-vcs-tag.sh',
                    meson.current_source_dir(),
                    meson.project_version(),
                    check: true)
    conf.set('GIT_VERSION', '"@0@"'.format(r.stdout().strip()))
endif
conf.set('PROJECT_VERSION', '"@0@"'.format(meson.project_version()))

conf.set('SYSCONFDIR', '"@0@"'.format(sysconfdir))

if get_option('json-c').disabled()
    json_c_dep = dependency('', required: false)
else
    json_c_dep = dependency('json-c',
                            version: '>=0.13',
                            required: get_option('json-c'),
                            fallback : ['json-c', 'json_c_dep'])
endif
conf.set('CONFIG_JSONC', json_c_dep.found(), description: 'Is json-c required?')

if get_option('openssl').disabled()
  openssl_dep = dependency('', required: false)
else
  openssl_dep = dependency('openssl',
                           version: '>=1.1.0',
                           required: get_option('openssl'),
                           fallback : ['openssl', 'libssl_dep'])

  if openssl_dep.found()
    if openssl_dep.version().version_compare('<2.0.0')
      api_version = 1
    endif

    if openssl_dep.version().version_compare('>=3.0.0')
      api_version = 3
    endif

    # Test for LibreSSL v3.x with incomplete OpenSSL v3 APIs
    if openssl_dep.type_name() != 'internal'
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
endif

conf.set('CONFIG_OPENSSL', openssl_dep.found(),
         description: 'Is OpenSSL/LibreSSL available?')

if get_option('keyutils').disabled()
    keyutils_dep = dependency('', required: false)
else
    keyutils_dep = dependency('libkeyutils',
                              required : get_option('keyutils'))
endif
conf.set('CONFIG_KEYUTILS', keyutils_dep.found(),
         description: 'Is libkeyutils available?')

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
    'HAVE_NETDB',
    cc.links(
      '''#include <sys/types.h>
         #include <sys/socket.h>
         #include <netdb.h>
         int main(int argc, char **argv) {
             struct addrinfo hints, *result;
             return getaddrinfo(argv[1], argv[2], &hints, &result);
      }
      ''',
      name: 'netdb',
    ),
    description: 'Is network address and service translation available'
)
conf.set(
    'HAVE_GLIBC_IOCTL',
    cc.compiles(
        '''#include <sys/ioctl.h>
        int ioctl(int fd, unsigned long request, ...);
        ''',
        name: 'ioctl has glibc-style prototype'
    ),
    description: 'Is ioctl the glibc interface (rather than POSIX)'
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
    ],
    language : 'c',
)
incdir = include_directories(['.', 'ccan', 'src'])

################################################################################
subdir('internal')
subdir('ccan')
subdir('src')
subdir('libnvme')
if get_option('tests')
    subdir('test')
endif
subdir('examples')
subdir('doc')

################################################################################
if meson.version().version_compare('>=0.53.0')
    path_dict = {
        'prefixdir':         prefixdir,
        'sysconfdir':        sysconfdir,
        'bindir':            bindir,
        'includedir':        includedir,
        'datadir':           datadir,
        'mandir':            mandir,
        'libdir':            libdir,
        'build location':    meson.current_build_dir(),
    }
    summary(path_dict, section: 'Paths')
    dep_dict = {
        'json-c':            json_c_dep.found(),
        'OpenSSL':           openssl_dep.found(),
        'keyutitls':         keyutils_dep.found(),
        'libdbus':           libdbus_dep.found(),
        'Python 3':          py3_dep.found(),
    }
    summary(dep_dict, section: 'Dependencies')
    conf_dict = {
        'git version':       conf.get('GIT_VERSION'),
    }
    summary(conf_dict, section: 'Configuration')
endif
