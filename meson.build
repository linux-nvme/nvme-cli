# SPDX-License-Identifier: GPL-2.0-or-later
################################################################################
project(
    'nvme-cli', ['c'],
    meson_version: '>= 0.50.0',
    license: 'GPL-2.0-only',
    version: '2.4',
    default_options: [
      'c_std=gnu99',
      'buildtype=debug',
      'prefix=/usr/local',
      'warning_level=1',
      'sysconfdir=etc',
      'wrap_mode=nofallback',
    ]
)

################################################################################
cc = meson.get_compiler('c')

prefixdir  = get_option('prefix')
datadir    = join_paths(prefixdir, get_option('datadir'))
mandir     = join_paths(prefixdir, get_option('mandir'))
sbindir    = join_paths(prefixdir, get_option('sbindir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))

udevrulesdir   = join_paths(prefixdir, get_option('udevrulesdir'))
dracutrulesdir = join_paths(prefixdir, get_option('dracutrulesdir'))
systemddir     = join_paths(prefixdir, get_option('systemddir'))

###############################################################################
conf = configuration_data()
requires = ''

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

conf.set('SYSCONFDIR', '"@0@"'.format(sysconfdir))

# Check for libnvme availability
libnvme_dep = dependency('libnvme', version: '>=1.4', required: true,
                         fallback : ['libnvme', 'libnvme_dep'])
libnvme_mi_dep = dependency('libnvme-mi', required: true,
                         fallback : ['libnvme', 'libnvme_mi_dep'])

# Check for libjson-c availability
if get_option('json-c').disabled()
    json_c_dep = dependency('', required: false)
else
    json_c_dep = dependency('json-c', required: get_option('json-c'), version: '>=0.13',
                            fallback : ['json-c', 'json_c_dep'])
    if json_c_dep.version().version_compare('>=0.14')
        conf.set('CONFIG_JSONC_14', true, description: 'Is json-c at least 0.14?')
        requires = 'Requires: json-c >= 0.14'
    else
        requires = 'Requires: json-c >= 0.13'
    endif
endif
conf.set('CONFIG_JSONC', json_c_dep.found(), description: 'Is json-c available?')

# Check for libhugetlbfs availability (optional)
if cc.has_header('hugetlbfs.h')
  libhugetlbfs_dep = cc.find_library('hugetlbfs',
                                     required : false)
else
  libhugetlbfs_dep = dependency('', required: false)
endif
conf.set('CONFIG_LIBHUGETLBFS', libhugetlbfs_dep.found(), description: 'Is libhugetlbfs available?')

# Set the nvme-cli version
conf.set('NVME_VERSION', '"' + meson.project_version() + '"')

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

configure_file(
    output: 'config.h',
    configuration: conf
)

################################################################################
libtype = get_option('default_library')
if libtype == 'static'
  requires = ''
endif

substs = configuration_data()
substs.set('NAME',    meson.project_name())
substs.set('VERSION', meson.project_version())
substs.set('LICENSE', meson.project_license()[0])
substs.set('UDEVRULESDIR', udevrulesdir)
substs.set('DRACUTRILESDIR', dracutrulesdir)
substs.set('REQUIRES', requires)
substs.set('DATADIR', datadir)
substs.set('MANDIR', mandir)
substs.set('SBINDIR', sbindir)
substs.set('SYSCONFDIR', sysconfdir)
substs.set('SYSTEMDDIR', systemddir)
substs.set('SYSTEMCTL', get_option('systemctl'))

configure_file(
  input:         'nvme.spec.in',
  output:        'nvme.spec',
  configuration: substs,
)

disc = configure_file(
  input: 'etc/discovery.conf.in',
  output: 'discovery.conf',
  configuration: substs,
)

dracut_files = [
  '70-nvmf-autoconnect.conf',
]

foreach file : dracut_files
  configure_file(
    input: 'nvmf-autoconnect/dracut-conf/' + file + '.in',
    output: file,
    configuration: substs,
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
  )
endforeach

udev_files = [
  '70-nvmf-autoconnect.rules',
  '71-nvmf-iopolicy-netapp.rules',
  '65-persistent-net-nbft.rules',
]

foreach file : udev_files
  configure_file(
    input: 'nvmf-autoconnect/udev-rules/' + file + '.in',
    output: file,
    configuration: substs,
  )
endforeach

################################################################################
add_project_arguments(['-fomit-frame-pointer', '-D_GNU_SOURCE',
                       '-include', 'config.h'], language : 'c')
incdir = include_directories(['ccan'])

################################################################################
sources = [
  'nbft.c',
  'fabrics.c',
  'nvme.c',
  'nvme-models.c',
  'nvme-print.c',
  'nvme-rpmb.c',
  'nvme-wrap.c',
  'plugin.c',
  'libnvme-wrap.c',
]
if json_c_dep.found()
    sources += [
        'nvme-print-json.c',
    ]
endif

subdir('ccan')
subdir('plugins')
subdir('unit')
if get_option('nvme-tests')
    subdir('tests')
endif
subdir('util')
subdir('Documentation')

executable(
  'nvme',
  sources,
  dependencies: [ libnvme_dep, libnvme_mi_dep, json_c_dep,
                  libhugetlbfs_dep ],
  link_args: '-ldl',
  include_directories: incdir,
  install: true,
  install_dir: sbindir
)

################################################################################
install_data('completions/bash-nvme-completion.sh',
             rename: 'nvme',
             install_dir: datadir + '/bash-completion/completions')
install_data('completions/_nvme',
             install_dir: datadir + '/zsh/site-functions')

foreach file : dracut_files
  install_data(meson.current_build_dir() + '/' + file,
               install_dir: dracutrulesdir)
endforeach

foreach file : systemd_files
  install_data(meson.current_build_dir() + '/' + file,
               install_dir: systemddir)
endforeach

foreach file : udev_files
  install_data(meson.current_build_dir() + '/' + file,
               install_dir: udevrulesdir)
endforeach

install_data(disc,
             install_dir: join_paths(sysconfdir, 'nvme'))

################################################################################
if meson.version().version_compare('>=0.53.0')
    path_dict = {
        'prefixdir':         prefixdir,
        'sysconfdir':        sysconfdir,
        'sbindir':           sbindir,
        'datadir':           datadir,
        'mandir':            mandir,
        'udevrulesdir':      udevrulesdir,
        'dracutrulesdir':    dracutrulesdir,
        'systemddir':        systemddir,
        'build location':    meson.current_build_dir(),
    }
    summary(path_dict, section: 'Paths')
    dep_dict = {
        'json-c':            json_c_dep.found(),
        'libhugetlbfs':      libhugetlbfs_dep.found(),
    }
    summary(dep_dict, section: 'Dependencies')
    conf_dict = {
        'pdc enabled':       get_option('pdc-enabled')
    }
    summary(conf_dict, section: 'Configuration')
endif
