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
    meson_version: '>= 1.0.0',
    license: [
        'GPL-2.0-only',         # nvme-cli
        'LGPL-2.1-or-later',    # libnvme
    ],
    version: '3.1',
    default_options: [
        'c_std=gnu11',
        'buildtype=debugoptimized',
        'warning_level=1',
        'sysconfdir=etc',
        'wrap_mode=nofallback',
    ],
)

fs = import('fs')

cc = meson.get_compiler('c')
cxx_available = add_languages('cpp', required: false, native: false)
host_system = host_machine.system()

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
want_nvme = get_option('nvme').allowed()
want_libnvme = get_option('libnvme').allowed()
# require() fails the setup when an enabled option cannot be built, and
# turns an auto option off.
want_fabrics = get_option('fabrics').require(host_system == 'linux',
    error_message: 'fabrics requires Linux').allowed()
want_mi = get_option('mi').require(host_system == 'linux',
    error_message: 'mi requires Linux').allowed()
want_sed = get_option('sed').allowed()
want_top = get_option('top').require(host_system == 'linux',
    error_message: 'top requires Linux').allowed()
discoverd_opt = get_option('nvme-discoverd').require(want_fabrics,
    error_message: 'nvme-discoverd requires fabrics')
keysd_opt = get_option('nvme-keysd').require(want_fabrics,
    error_message: 'nvme-keysd requires fabrics')
want_deprecated_cmds = get_option('deprecated-cmds').allowed()
want_tests = get_option('tests')
want_ioctl_tests = want_tests and get_option('ioctl-tests')
want_examples = get_option('examples') and host_system == 'linux'
want_docs = get_option('docs')
want_docs_build = get_option('docs-build')

is_static = get_option('default_library') == 'static'
is_cross = meson.is_cross_build()

feature_python = get_option('python').require(want_fabrics,
    error_message: 'python requires fabrics')
if feature_python.disabled()
    py3_dep = dependency('', required: false)  # Needed for muon
    want_python = false
else
    if feature_python.enabled()
        want_libnvme = true
    endif

    python3 = import('python').find_installation(
        'python3',
        required: feature_python.enabled()
    )

    if python3.found()
        py3_dep = python3.dependency(required: feature_python.enabled())
        swig = find_program('swig', required: feature_python.enabled())
        header_found = cc.has_header(
            'Python.h',
            dependencies: py3_dep,
            required: feature_python.enabled()
        )
    else
        py3_dep = dependency('', required: false)
        swig = disabler()
        header_found = false
    endif

    want_python = (
        want_libnvme and
        py3_dep.found() and
        swig.found() and
        header_found
    )
endif

# Bump this only when making an ABI-incompatible change.
libnvme_so_version = '1.0.0'

# For PyPI builds, use only the major version (e.g., '3' instead of '3.0.0').
# This avoids the need for symbolic links which pip/wheel doesn't preserve.
if get_option('pypi')
    libnvme_so_version = libnvme_so_version.split('.')[0]
endif

libnvme_so_major = libnvme_so_version.split('.')[0]
libnvme_api_name = 'libnvme3'
libnvme_link_name = 'nvme3'

################################################################################
prefixdir      = get_option('prefix')
datadir        = prefixdir / get_option('datadir')
mandir         = prefixdir / get_option('mandir')
sbindir        = prefixdir / get_option('sbindir')
sysconfdir     = prefixdir / get_option('sysconfdir')
udevrulesdir   = prefixdir / get_option('udevrulesdir')
dracutrulesdir = prefixdir / get_option('dracutrulesdir')
systemddir     = prefixdir / get_option('systemddir')
nmdispatchdir  = prefixdir / get_option('nmdispatchdir')

# /run's location is fixed by the FHS -- unlike the dirs above, it must
# never scale with --prefix.
rundir         = get_option('rundir')

std_prefix = prefixdir == '/usr' or prefixdir == '/usr/local'

###############################################################################
conf = configuration_data()
requires = ''

version_tag = get_option('version-tag')
if version_tag != ''
    git_version = version_tag
else
    git_version = meson.project_version()

    git = find_program('git', required: false)
    if git.found() and fs.exists(meson.current_source_dir() / '.git')
        r = run_command(
            git,
            '-C', meson.current_source_dir(),
            'describe',
            '--abbrev=7',
            '--dirty=+',
            check: false,
        )

        if r.returncode() == 0
            git_version = r.stdout().strip().replace('^v', '')
        endif
    endif
endif
conf.set('GIT_VERSION', '"@0@"'.format(git_version))

conf.set('SYSCONFDIR', '"@0@"'.format(sysconfdir))
conf.set('RUNDIR', '"@0@"'.format(rundir))

conf.set('CONFIG_FABRICS', want_fabrics, description: 'Is fabrics enabled')
conf.set('CONFIG_MI', want_mi, description: 'Is MI enabled')
conf.set('CONFIG_SED', want_sed, description: 'Is SED enabled')
conf.set('CONFIG_LOOPBACK', want_ioctl_tests,
    description: 'Is the ioctl loopback test transport enabled')
conf.set('CONFIG_TOP', want_top, description: 'Is nvme top enabled')
conf.set('CONFIG_DEPRECATED_CMDS', want_deprecated_cmds,
    description: 'Deprecated commands enabled')

if host_system == 'windows'
    kernel32_dep = cc.find_library('kernel32', required: true)
    bcrypt_dep = cc.find_library('bcrypt', required: true)
    setupapi_dep = cc.find_library('setupapi', required: true)
    cfgmgr32_dep = cc.find_library('cfgmgr32', required: true)
    winpthread_dep = cc.find_library('winpthread', required: true)
endif

conf.set10(
    'NVME_HAVE_BCRYPT',
    cc.find_library('bcrypt', required: false).found(),
    description: 'Is bcrypt availabe'
)

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

# local (cross-compilable) implementations of ccan configure steps
conf.set10(
    'NVME_HAVE_BUILTIN_TYPES_COMPATIBLE_P',
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
    'NVME_HAVE_BYTESWAP_H',
    cc.compiles(
        '''#include <byteswap.h>''',
        name: 'byteswap.h'
    ),
    description: 'Is byteswap.h include-able?'
)
conf.set10(
    'NVME_HAVE_BSWAP_64',
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
    'NVME_HAVE_ISBLANK',
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
    'NVME_HAVE_SYS_RANDOM',
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
    'NVME_HAVE_SED_OPAL',
    cc.compiles(
        '''#include <linux/sed-opal.h>''',
        name: 'linux/sed-opal.h'

    ),
    description: 'Is linux/sed-opal.h include-able?'
)
conf.set10(
    'NVME_HAVE_KEY_TYPE',
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
    'NVME_HAVE_TM_GMTOFF',
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
conf.set('HAVE_STRSEP',
    cc.compiles(
        '''
            #include <string.h>

            int main(void) {
                char *s = NULL;
                char *p = strsep(&s, ",");
                return p != NULL;
            }
        ''',
        name: 'strsep'
    ),
    description: 'Is strsep available?'
)

if cc.has_function_attribute('fallthrough')
    conf.set('fallthrough', '__attribute__((fallthrough))')
else
    conf.set('fallthrough', 'do {} while (0) /* fallthrough */')
endif


liburing_opt = get_option('liburing').require(want_fabrics,
    error_message: 'liburing requires fabrics')
if liburing_opt.disabled()
    liburing_dep = dependency('', required: false)
else
    liburing_dep = dependency('liburing', version: '>=2.2', required: liburing_opt)
endif
conf.set('CONFIG_LIBURING', liburing_dep.found(), description: 'Is liburing available?')

libkmod_opt = get_option('libkmod').require(host_system == 'linux',
    error_message: 'libkmod requires Linux')
if libkmod_opt.disabled()
    libkmod_dep = dependency('', required: false)
else
    libkmod_dep = dependency('libkmod', required: libkmod_opt)
endif
conf.set('NVME_HAVE_LIBKMOD', libkmod_dep.found(), description: 'Is libkmod available?')

openssl_opt = get_option('openssl').require(host_system == 'linux',
    error_message: 'openssl requires Linux')
if openssl_opt.disabled()
    openssl_dep = dependency('', required: false)
else
    openssl_dep = dependency(
        'openssl',
        version: '>=3.0.0',
        required: openssl_opt,
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

keyutils_opt = get_option('keyutils').require(want_fabrics,
    error_message: 'keyutils requires fabrics')
if keyutils_opt.disabled()
    keyutils_dep = dependency('', required: false)
else
    keyutils_dep = dependency('libkeyutils', required : keyutils_opt)
endif
conf.set('CONFIG_KEYUTILS', keyutils_dep.found(), description: 'Is libkeyutils available?')

if get_option('libarchive').disabled()
    libarchive_dep = dependency('', required: false)
else
    libarchive_dep = dependency('libarchive', required: get_option('libarchive'))
endif
conf.set('CONFIG_LIBARCHIVE', libarchive_dep.found(), description: 'Is libarchive available?')

if not discoverd_opt.allowed() and not keysd_opt.allowed()
    libsystemd_dep = dependency('', required: false)
else
    # v253 for Type=notify-reload (nvme-discoverd.service, nvme-keysd.service).
    libsystemd_dep = dependency('libsystemd', version: '>=253',
                                 required: discoverd_opt.enabled() or
                                           keysd_opt.enabled())
endif
want_discoverd = discoverd_opt.require(libsystemd_dep.found(),
    error_message: 'nvme-discoverd requires libsystemd >=253').allowed()

# nvme-keysd decrypts credentials through sd_varlink (libsystemd v257).
keysd_opt = keysd_opt.require(
    libsystemd_dep.found() and libsystemd_dep.version().version_compare('>=257'),
    error_message: 'nvme-keysd requires libsystemd >=257')
# nvme-keysd derives the PSKs (OpenSSL) and writes the keyring (libkeyutils).
keysd_opt = keysd_opt.require(openssl_dep.found() and keyutils_dep.found(),
    error_message: 'nvme-keysd requires OpenSSL and libkeyutils')
want_keysd = keysd_opt.allowed()
conf.set('CONFIG_DISCOVERD', want_discoverd, description: 'Is nvme-discoverd enabled')
conf.set('CONFIG_KEYSD', want_keysd, description: 'Is nvme-keysd enabled')

# -Dnvmf-autoconnect=auto builds the legacy autoconnect only when
# nvme-discoverd is not built.
nvmf_autoconnect_opt = get_option('nvmf-autoconnect').require(want_fabrics,
    error_message: 'nvmf-autoconnect requires fabrics')
want_nvmf_autoconnect = (
    nvmf_autoconnect_opt.enabled() or
    (nvmf_autoconnect_opt.auto() and not want_discoverd)
)

# mDNS needs the sd_varlink client API (libsystemd v257) and the
# BrowseServices method of systemd-resolved (v258).
mdns_opt = get_option('mdns').require(want_discoverd, error_message: 'mdns requires nvme-discoverd')
want_mdns = mdns_opt.require(
    want_discoverd and libsystemd_dep.version().version_compare('>=258'),
    error_message: 'mdns requires libsystemd >=258').allowed()

libdbus_opt = get_option('libdbus').require(want_mi, error_message: 'libdbus requires mi')
if libdbus_opt.disabled()
    libdbus_dep = dependency('', required: false)
else
    # Check for libdbus availability. Optional, only required for MCTP dbus scan
    libdbus_dep = dependency(
        'dbus-1',
        required: libdbus_opt,
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
    'NVME_HAVE_LINUX_MCTP_H',
    cc.compiles(
        '''#include <linux/mctp.h>''',
        name: 'linux/mctp.h'
    ),
    description: 'Is linux/mctp.h include-able?'
)

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
    'NVME_HAVE_NETDB',
    have_netdb,
    description: 'Is network address and service translation available'
)

threads_dep = dependency('threads', required: true)
dl_dep = dependency('dl', required: false)
conf.set(
    'NVME_HAVE_LIBC_DLSYM',
    cc.has_function('dlsym', dependencies: dl_dep),
    description: 'Is dlsym function present',
)

conf.set('NVME_HAVE_SENDFILE', cc.has_function('sendfile'))

conf.set('NVME_HAVE_MMAP', cc.has_function('mmap'))

conf.set10(
    'NVME_HAVE_REALLOCARRAY',
    cc.has_function(
       'reallocarray',
       prefix : '#include <stdlib.h>',
       args : '-D_GNU_SOURCE'),
    description: 'Is reallocarray available',
)

conf.set10(
    'NVME_HAVE_ENODATA',
    cc.has_header_symbol('errno.h', 'ENODATA'),
    description: 'Does errno.h define ENODATA',
)

conf.set10(
    'NVME_HAVE_SIGACTION',
    cc.has_function(
        'sigaction',
        prefix : '#include <signal.h>'),
    description: 'Is sigaction available',
)

conf.set10(
    'HAVE_STORAGE_REINITIALIZE_MEDIA',
    host_system == 'windows' and cc.compiles(
        '''
            #include <winioctl.h>
            int main(void) {
                struct STORAGE_REINITIALIZE_MEDIA media;

                return (int)sizeof(media);
            }
        ''',
        name: 'STORAGE_REINITIALIZE_MEDIA'
    ),
    description: 'Does winioctl.h define struct STORAGE_REINITIALIZE_MEDIA'
)

conf.set(
    'NVME_HAVE_INT128',
    cc.compiles(
        '''
            int main(void) {
                __int128 v;
                v = 1;
            }
        ''',
        name: 'int128'
    ),
    description: 'Is __int128 available?'
)

project_config_file = 'nvme-config.h'
nvme_config_h = configure_file(output: project_config_file, configuration: conf)
config_dep = declare_dependency(
    sources: nvme_config_h,
    include_directories: '.',
)

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

# This handles a specific packaging scenario where libnvme is built and
# installed separately from nvme-cli. In this case, libnvme is installed
# under a non-standard prefix, and nvme-cli must be built against the
# previously installed libnvme headers.
#
# To support this layout, we explicitly add the libnvme include path from
# the non-standard prefix. This cannot be done using include_directories(),
# which only supports relative paths, while the libnvme include path is
# absolute.
if not want_libnvme and not std_prefix
    libnvme_hdr_location = prefixdir / get_option('includedir') / libnvme_api_name
    message(
        'Using non-standard libnvme headers location: ',
        libnvme_hdr_location
    )

    # Allow compiler to find headers in non-standard location
    add_project_arguments('-I' + libnvme_hdr_location, language : 'c')
endif

################################################################################
libtype = get_option('default_library')
if libtype == 'static'
    requires = ''
endif

if host_system == 'windows'
    add_project_arguments(
        [
            '-DNOMINMAX',   # don't include Windows min/max definitions
            '-D_POSIX_THREAD_SAFE_FUNCTIONS',   # enables gmtime_r support
        ],
        language : 'c',
    )
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
# mDNS uses systemd-resolved, so nvme-discoverd must start after it.
substs.set('DISCOVERD_AFTER_RESOLVED',
           want_mdns ? 'After=systemd-resolved.service' : '')
substs.set('PREFIX', prefixdir)
substs.set('URL', 'https://github.com/linux-nvme/nvme-cli/')
substs.set('LIBNVME_API_NAME', libnvme_api_name)
substs.set('LIBNVME_SO_VERSION', libnvme_so_major)


################################################################################
doc_tgts = []

subdir('ccan')      # declares: ccan_dep
subdir('shared')    # declares: shared_dep
subdir('libnvme')   # declares: libnvme_dep

if want_nvme
    subdir('plugins')   # declares: plugin_sources
    subdir('src')       # declares: sources

    sources += plugin_sources

    link_args_list = []
    link_deps = [
        config_dep,
        ccan_dep,
        libnvme_dep,
        shared_dep,
        json_c_dep,
        libkmod_dep,
    ]

    if host_system == 'windows'
        link_deps += [
            kernel32_dep,
            bcrypt_dep,
        ]

        if is_static
            # Keep these MinGW runtime dependencies in-process to avoid
            # requiring extra DLLs in PATH for static Windows builds.
            link_args_list += ['-Wl,-Bstatic']
            if json_c_dep.found()
                link_args_list += ['-ljson-c']
            endif
            link_args_list += ['-lwinpthread', '-Wl,-Bdynamic']
        else
            link_deps += [winpthread_dep]
        endif
    else
        link_args_list = ['-ldl']
    endif

    nvme_exe = executable(
        'nvme',
        sources,
        include_directories: 'src',
        dependencies: link_deps,
        link_args: link_args_list,
        install: true,
        install_dir: sbindir,
    )

    if host_system == 'windows' and want_libnvme and (not is_static)
        # Copy libnvme DLL next to nvme.exe so it can be found at
        # runtime without modifying PATH.
        cp = find_program('cp')
        custom_target('copy-libnvme-dll',
            input: libnvme,
            output: fs.name(libnvme.full_path()),
            command: [cp, '@INPUT@', '@OUTPUT@'],
            depends: [libnvme, nvme_exe],
            build_by_default: true,
        )
    endif

    if get_option('e2e-tests')
        # A standalone copy of the e2e runner, placed next to the 'nvme'
        # binary in the build root so it can be invoked directly -- e.g.
        # './.build/nvme-cli-e2e --controller=... ...' -- entirely
        # independent of 'meson test'.
        cp = find_program('cp')
        custom_target('nvme-cli-e2e',
            input: files('tests/nvme-cli-e2e'),
            output: 'nvme-cli-e2e',
            command: [cp, '@INPUT@', '@OUTPUT@'],
            build_by_default: true,
            install: false,
        )
    endif

    subdir('tests')

    if want_discoverd or want_keysd
        subdir('daemon-util')
    endif

    if want_discoverd
        subdir('discoverd')
    endif

    if want_keysd
        subdir('keysd')
    endif

    configure_file(
        input:         'nvme.spec.in',
        output:        'nvme.spec',
        configuration: substs,
    )

    configure_file(
        input: 'etc/nvme-fabrics.conf.sample.in',
        output: 'nvme-fabrics.conf.sample',
        configuration: substs,
        install: true,
        install_dir: sysconfdir / 'nvme',
        install_tag: 'nvmf',
    )

    if want_nvmf_autoconnect
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
                install_tag: 'nvmf-autoconnect',
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
                install_tag: 'nvmf-autoconnect',
            )
        endforeach
    endif

    # These rules provision keys and tune vendor devices; kept regardless of
    # which NVMe-oF autoconnect mechanism (if any) is in use.
    udev_files = {
        '65-persistent-net-nbft.rules': 'nvmf',
        '70-nvmf-keys.rules':           'nvmf-autoconnect',
        '71-nvmf-hpe.rules':            'nvmf',
        '71-nvmf-netapp.rules':         'nvmf',
        '71-nvmf-vastdata.rules':       'nvmf',
    }
    if want_nvmf_autoconnect
        udev_files += {'70-nvmf-autoconnect.rules': 'nvmf-autoconnect'}
    endif

    foreach file, tag : udev_files
        configure_file(
            input: 'nvmf-autoconnect/udev-rules/' + file + '.in',
            output: file,
            configuration: substs,
            install: true,
            install_dir: udevrulesdir,
            install_tag: tag,
        )
    endforeach

    if want_nvmf_autoconnect
        nm_dispatcher_files = [
            '80-nvmf-connect-nbft.sh'
        ]

        foreach file : nm_dispatcher_files
            configure_file(
                input: 'nvmf-autoconnect/nm-dispatcher/' + file + '.in',
                output: file,
                configuration: substs,
                install: true,
                install_mode: 'rwxr-xr-x',
                install_dir: nmdispatchdir,
                install_tag: 'nvmf-autoconnect',
            )
        endforeach
    endif

    subdir('completions')

    subdir('Documentation')
endif

if host_system == 'linux'
    valgrind_cmd = [
        'valgrind',
        '--leak-check=full',
        '--show-leak-kinds=all',
        '--error-exitcode=1',
        '--suppressions=' + meson.current_source_dir() / 'valgrind.supp',
    ]
    python3_supp = '/usr/lib/valgrind/python3.supp'
    if fs.is_file(python3_supp)
        valgrind_cmd += ['--suppressions=' + python3_supp]
    endif

    add_test_setup('valgrind',
        exe_wrapper: valgrind_cmd,
        timeout_multiplier: 5,
    )

    add_test_setup('asanubsan',
        timeout_multiplier: 2,
    )
endif

if doc_tgts.length() == 0
    doc_tgts += custom_target(
        'docs-dummy',
        output: 'docs.stamp',
        command: ['true'],
        build_by_default: false,
    )
endif

alias_target('docs', doc_tgts)

# Every installed file needs an install tag; see Documentation/BUILDING.md.
py3_prog = find_program('python3', required: false)
if want_tests and py3_prog.found()
    test(
        'nvme-cli - install-tags',
        py3_prog,
        args: [
            files('scripts/check-install-tags.py'),
            meson.project_build_root(),
        ],
    )
endif


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
    'nmdispatchdir':    nmdispatchdir,
    'build location':   meson.current_build_dir(),
}
summary(path_dict, section: 'Paths')

dep_dict = {
    'json-c':           json_c_dep.found(),
    'OpenSSL':          openssl_dep.found(),
    'keyutils':         keyutils_dep.found(),
    'libarchive':       libarchive_dep.found(),
    'libdbus':          libdbus_dep.found(),
    'python3':          py3_dep.found(),
    'liburing':         liburing_dep.found(),
    'libkmod':          libkmod_dep.found(),
    'libsystemd':       libsystemd_dep.found(),
}
if host_system == 'windows'
    dep_dict += {
        'kernel32':     kernel32_dep.found(),
        'bcrypt':       bcrypt_dep.found(),
        'setupapi':     setupapi_dep.found(),
        'cfgmgr32':     cfgmgr32_dep.found(),
    }
endif
summary(dep_dict, section: 'Dependencies', bool_yn: true)

wanted_dict = {
    'nvme':             want_nvme,
    'libnvme':          want_libnvme,
    'fabrics':          want_fabrics,
    'nvme-discoverd':   want_discoverd,
    'mdns':             want_mdns,
    'nvme-keysd':       want_keysd,
    'nvmf-autoconnect': want_nvmf_autoconnect,
    'deprecated-cmds':  want_deprecated_cmds,
    'python bindings ': want_python,
    'build docs':       want_docs_build,
}
summary(wanted_dict, section: 'Features to build', bool_yn: true)

if want_nvme
    plugin_dict = {
        'core':      ', '.join(core_plugins),
        'vendor':    ', '.join(vendor_plugins),
        'disabled':  ', '.join(disabled_plugins),
    }
    summary(plugin_dict, section: 'Plugins')
endif

c_args = get_option('c_args')
c_link_args = get_option('c_link_args')
conf_dict = {
    'git version':      conf.get('GIT_VERSION'),
    'CFLAGS':           c_args.length() > 0 ? ' '.join(c_args) : '(none)',
    'LDFLAGS':          c_link_args.length() > 0 ? ' '.join(c_link_args) : '(none)',
}
summary(conf_dict, section: 'Configuration', bool_yn: true)
