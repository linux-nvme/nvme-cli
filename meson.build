# SPDX-License-Identifier: GPL-2.0-or-later
################################################################################

# The "version" must follow this syntax:
#   Official releases:
#       major.minor[.patch]              e.g. 3.0, 3.0.1

#   Release Candidates:
#       major.minor[.patch]-rc.*         e.g. 3.0-rc.1, 3.0.1-rc.1
#
#   Development versions:
#       alpha: major.minor[.patch]-a.*   e.g. 3.0-a.1, 3.0.1-a.1
#       beta:  major.minor[.patch]-b.*   e.g. 3.0-b.1, 3.0.1-b.1

project(
    'nvme-cli', ['c'],
    meson_version: '>= 0.62.0',
    license: [
        'GPL-2.0-only',         # nvme-cli
        'LGPL-2.1-or-later',    # libnvme
    ],
    version: '3.0-a.1',
    default_options: [
        'c_std=gnu99',
        'buildtype=debugoptimized',
        'prefix=/usr/local',
        'warning_level=1',
        'sysconfdir=etc',
        'wrap_mode=nofallback',
    ],
)

cc = meson.get_compiler('c')
cxx_available = add_languages('cpp', required: false, native: false)

################################################################################
# Determine which features we need to build: The nvme executable, the libnvme
# library, and/or the python bindings. These are controlled by the following
# meson options (see meson_options.txt)
#
# -Dnvme=[auto|enabled|disabled]      Default: enabled
# -Dlibnvme=[auto|enabled|disabled]   Default: enabled
# -Dpython=[auto|enabled|disabled]    Default: auto
#
# -Dnvme=auto is equivalent to -Dnvme=enabled
# -Dlibnvme=auto is equivalent to -Dlibnvme=enabled
#
# -Dpython=auto means build the python bindings if all the required
# dependencies are present. Also, -Dpython=enabled forces -Dlibnvme=enabled.
want_nvme = get_option('nvme').disabled() == false
want_libnvme = get_option('libnvme').disabled() == false

feature_python = get_option('python')
if feature_python.disabled()
    py3_dep = dependency('', required: false)  # Needed for muon
    want_python = false
else
    if feature_python.enabled()
        want_libnvme = true
    endif

    python3 = import('python').find_installation('python3')
    py3_dep = python3.dependency(required: feature_python.enabled())
    swig = find_program('swig', required: feature_python.enabled())
    header_found = cc.has_header('Python.h', dependencies: py3_dep, required: feature_python.enabled())
    want_python = want_libnvme and py3_dep.found() and swig.found() and header_found
endif


# Determine the libnvme.so version number from the project version. The version
# for libnvme.so has to be a 3 digit number such as 3.0.1. We expect the project
# version to be composed of 2 or 3 digits after stripping trailing identifiers
# such as "-rc.*". If the project version is composed of only two digits, then
# we append '.0' to it.
ver_digits = meson.project_version().split('-')[0]
num_digits = ver_digits.split('.').length()
if num_digits < 2 or num_digits > 3
    error('Invalid version: ', meson.project_version())
elif num_digits == 3
    libnvme_so_version = ver_digits
else
    libnvme_so_version = ver_digits + '.0'
endif

################################################################################
prefixdir      = get_option('prefix')
datadir        = join_paths(prefixdir, get_option('datadir'))
mandir         = join_paths(prefixdir, get_option('mandir'))
sbindir        = join_paths(prefixdir, get_option('sbindir'))
sysconfdir     = join_paths(prefixdir, get_option('sysconfdir'))
udevrulesdir   = join_paths(prefixdir, get_option('udevrulesdir'))
dracutrulesdir = join_paths(prefixdir, get_option('dracutrulesdir'))
systemddir     = join_paths(prefixdir, get_option('systemddir'))
rundir         = join_paths(prefixdir, get_option('rundir'))

###############################################################################
conf = configuration_data()
requires = ''

version_tag = get_option('version-tag')
if version_tag != ''
    conf.set('GIT_VERSION', '"@0@"'.format(version_tag))
else
    r = run_command(
        'scripts/meson-vcs-tag.sh',
        meson.current_source_dir(),
        meson.project_version(),
        check: true,
    )
    conf.set('GIT_VERSION', '"@0@"'.format(r.stdout().strip()))
endif

conf.set('SYSCONFDIR', '"@0@"'.format(sysconfdir))
conf.set('RUNDIR', '"@0@"'.format(rundir))

# Check for libjson-c availability
if get_option('json-c').disabled()
    json_c_dep = dependency('', required: false)
else
    json_c_dep = dependency(
        'json-c',
        required: get_option('json-c'),
        version: '>=0.13',
        fallback : ['json-c', 'json_c_dep'],
    )
    if json_c_dep.version().version_compare('>=0.14')
        conf.set('CONFIG_JSONC_14', true, description: 'Is json-c at least 0.14?')
        requires = 'Requires: json-c >= 0.14'
    else
        requires = 'Requires: json-c >= 0.13'
    endif
endif
conf.set('CONFIG_JSONC', json_c_dep.found(), description: 'Is json-c available?')

conf.set('NVME_VERSION', '"@0@"'.format(meson.project_version()))
conf.set('LIBNVME_VERSION', '"@0@"'.format(meson.project_version()))

conf.set10('DEFAULT_PDC_ENABLED', get_option('pdc-enabled'))

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
    'HAVE_SYS_RANDOM',
    cc.compiles(
        '''#include <sys/random.h>''',
        name: 'sys/random.h'
    ),
    description: 'Is sys/random.h(getrandom) include-able?'
)
conf.set10(
    'HAVE_ATTRIBUTE_UNUSED',
    cc.get_id() == 'clang',
    description: 'Is compiler warning about unused static line function?'
)
conf.set10(
    'HAVE_SED_OPAL',
    cc.compiles(
        '''#include <linux/sed-opal.h>''',
        name: 'linux/sed-opal.h'

    ),
    description: 'Is linux/sed-opal.h include-able?'
)
conf.set10(
    'HAVE_KEY_TYPE',
    cc.compiles(
        '''
            #include <linux/sed-opal.h>
            int main(void) {
                struct opal_key key;
                key.key_type = OPAL_INCLUDED;
            }
        ''',
        name: 'key_type'
    ),
    description: 'Does struct opal_key have a key_type field?'
)
conf.set(
    'HAVE_TM_GMTOFF',
    cc.compiles(
        '''
            #include <time.h>
            int main(void) {
                struct tm tm;
                tm.tm_gmtoff = 1;
            }
        ''',
        name: 'tm_gmtoff'
    ),
    description: 'Does struct tm have a tm_gmtoff field?'
)

if cc.has_function_attribute('fallthrough')
    conf.set('fallthrough', '__attribute__((__fallthrough__))')
else
    conf.set('fallthrough', 'do {} while (0) /* fallthrough */')
endif


if get_option('liburing').disabled()
    liburing_dep = dependency('', required: false)
else
    liburing_dep = dependency('liburing', version: '>=2.2', required: get_option('liburing'))
endif
conf.set('CONFIG_LIBURING', liburing_dep.found(), description: 'Is liburing available?')

if get_option('openssl').disabled()
    openssl_dep = dependency('', required: false)
else
    openssl_dep = dependency(
        'openssl',
        version: '>=3.0.0',
        required: get_option('openssl'),
        fallback : ['openssl', 'libssl_dep'],
    )
endif
if openssl_dep.found()
    # Test for LibreSSL v3.x with incomplete OpenSSL v3 APIs
    if openssl_dep.type_name() != 'internal'
        is_libressl = cc.has_header_symbol(
            'openssl/opensslv.h',
            'LIBRESSL_VERSION_NUMBER',
            dependencies: openssl_dep,
        )
        has_header = cc.has_header(
            'openssl/core_names.h',
            dependencies: openssl_dep,
        )
        if is_libressl and not has_header
            openssl_dep = dependency('', required: false)
        endif
    endif
endif
conf.set('CONFIG_OPENSSL', openssl_dep.found(), description: 'Is OpenSSL/LibreSSL available?')

if get_option('keyutils').disabled()
    keyutils_dep = dependency('', required: false)
else
    keyutils_dep = dependency('libkeyutils', required : get_option('keyutils'))
endif
conf.set('CONFIG_KEYUTILS', keyutils_dep.found(), description: 'Is libkeyutils available?')

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
    'HAVE_LINUX_MCTP_H',
    cc.compiles(
        '''#include <linux/mctp.h>''',
        name: 'linux/mctp.h'
    ),
    description: 'Is linux/mctp.h include-able?'
)

is_static = get_option('default_library') == 'static'
have_netdb = false
if not is_static
    have_netdb = cc.links(
        '''#include <sys/types.h>
        #include <sys/socket.h>
        #include <netdb.h>
        int main(int argc, char **argv) {
            struct addrinfo hints, *result;
            return getaddrinfo(argv[1], argv[2], &hints, &result);
        }
        ''',
        name: 'netdb',
    )
endif
conf.set(
    'HAVE_NETDB',
    have_netdb,
    description: 'Is network address and service translation available'
)

threads_dep = dependency('threads', required: true)
dl_dep = dependency('dl', required: false)
conf.set(
    'HAVE_LIBC_DLSYM',
    cc.has_function('dlsym', dependencies: dl_dep),
    description: 'Is dlsym function present',
)

project_config_file = 'nvme-config.h'
nvme_config_h = configure_file(output: project_config_file, configuration: conf)
config_dep = declare_dependency(sources: nvme_config_h)

# The -include option below requires the full path when
# nvme-cli is build as subproject of another meson project.
if meson.version().version_compare('>=1.4.0')
    nvme_config_h_path = nvme_config_h.full_path()
else
    nvme_config_h_path = meson.current_build_dir() / project_config_file
endif

add_project_arguments(
    [
        '-fomit-frame-pointer',
        '-D_GNU_SOURCE',
        '-include', nvme_config_h_path,
    ],
    language : 'c',
)

incdir = include_directories(
    [
        '.',
        'ccan',
        'libnvme',
        'libnvme/src',
    ]
)

################################################################################
libtype = get_option('default_library')
if libtype == 'static'
    requires = ''
endif

substs = configuration_data()
substs.set('VERSION', meson.project_version())
substs.set('NVMECLI_LICENSE', meson.project_license()[0])
substs.set('LIBNVME_LICENSE', meson.project_license()[1])
substs.set('UDEVRULESDIR', udevrulesdir)
substs.set('DRACUTRULESDIR', dracutrulesdir)
substs.set('REQUIRES', requires)
substs.set('DATADIR', datadir)
substs.set('MANDIR', mandir)
substs.set('RUNDIR', rundir)
substs.set('SBINDIR', sbindir)
substs.set('SYSCONFDIR', sysconfdir)
substs.set('SYSTEMDDIR', systemddir)
substs.set('SYSTEMCTL', get_option('systemctl'))
substs.set('PREFIX', prefixdir)
substs.set('URL', 'https://github.com/linux-nvme/nvme-cli/')
substs.set('VERSION_MAJOR', libnvme_so_version.split('.')[0])

configure_file(
    input:         'nvme.spec.in',
    output:        'nvme.spec',
    configuration: substs,
)

disc = configure_file(
    input: 'etc/discovery.conf.in',
    output: 'discovery.conf',
    configuration: substs,
    install: true,
    install_dir: join_paths(sysconfdir, 'nvme'),
)

dracut_files = [
    '70-nvmf-autoconnect.conf',
]

foreach file : dracut_files
    configure_file(
        input: 'nvmf-autoconnect/dracut-conf/' + file + '.in',
        output: file,
        configuration: substs,
        install: true,
        install_dir: dracutrulesdir,
    )
endforeach

systemd_files = [
    'nvmefc-boot-connections.service',
    'nvmf-autoconnect.service',
    'nvmf-connect-nbft.service',
    'nvmf-connect.target',
    'nvmf-connect@.service',
]

foreach file : systemd_files
    configure_file(
        input: 'nvmf-autoconnect/systemd/' + file + '.in',
        output: file,
        configuration: substs,
        install: true,
        install_dir: systemddir,
    )
endforeach

udev_files = [
    '65-persistent-net-nbft.rules',
    '70-nvmf-autoconnect.rules',
    '70-nvmf-keys.rules',
    '71-nvmf-hpe.rules',
    '71-nvmf-netapp.rules',
    '71-nvmf-vastdata.rules',
]

foreach file : udev_files
    configure_file(
        input: 'nvmf-autoconnect/udev-rules/' + file + '.in',
        output: file,
        configuration: substs,
        install: true,
        install_dir: udevrulesdir
    )
endforeach

################################################################################
subdir('ccan')      # declares: libccan
subdir('libnvme')   # declares: libnvme_dep

if want_nvme
    subdir('plugins')   # declares: plugin_sources
    subdir('util')      # declares: util_sources

    sources = [
        'fabrics.c',
        'nvme.c',
        'nvme-models.c',
        'nvme-print.c',
        'nvme-print-stdout.c',
        'nvme-print-binary.c',
        'nvme-rpmb.c',
        'plugin.c',
        'libnvme-wrap.c',
        'logging.c',
    ]
    if json_c_dep.found()
        sources += [
            'nvme-print-json.c',
        ]
    endif
    sources += plugin_sources
    sources += util_sources

    executable(
        'nvme',
        sources,
        dependencies: [ libnvme_dep, json_c_dep ],
        link_args: '-ldl',
        link_with: libccan,
        include_directories: [incdir, ],
        install: true,
        install_dir: sbindir
    )

    subdir('unit')
    if get_option('nvme-tests')
        subdir('tests')
    endif

    subdir('Documentation')
endif


################################################################################
install_data(
    'completions/bash-nvme-completion.sh',
    rename: 'nvme',
    install_dir: datadir / 'bash-completion/completions',
)
install_data(
    'completions/_nvme',
    install_dir: datadir / 'zsh/site-functions',
)

################################################################################
path_dict = {
    'prefixdir':        prefixdir,
    'sysconfdir':       sysconfdir,
    'sbindir':          sbindir,
    'datadir':          datadir,
    'mandir':           mandir,
    'udevrulesdir':     udevrulesdir,
    'dracutrulesdir':   dracutrulesdir,
    'rundir':           rundir,
    'systemddir':       systemddir,
    'build location':   meson.current_build_dir(),
}
summary(path_dict, section: 'Paths')

dep_dict = {
    'json-c':           json_c_dep.found(),
    'OpenSSL':          openssl_dep.found(),
    'keyutitls':        keyutils_dep.found(),
    'libdbus':          libdbus_dep.found(),
    'python3':          py3_dep.found(),
    'liburing':         liburing_dep.found(),
}
summary(dep_dict, section: 'Dependencies', bool_yn: true)

wanted_dict = {
    'nvme':             want_nvme,
    'libnvme':          want_libnvme,
    'python bindings ': want_python,
}
summary(wanted_dict, section: 'Features to build', bool_yn: true)

conf_dict = {
    'git version':      conf.get('GIT_VERSION'),
    'pdc enabled':      get_option('pdc-enabled'),
}
summary(conf_dict, section: 'Configuration', bool_yn: true)

