################################################################################
project(
    'nvme-cli', ['c', 'cpp'],
    meson_version: '>= 0.47.0',
    license: 'LGPLv2+',
    version: run_command('./nvme-cli-version', check : true).stdout().strip(),
    default_options: [
      'c_std=gnu99',
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

###############################################################################
conf = configuration_data()

libnvme_dep = dependency('libnvme', fallback : ['libnvme', 'libnvme_dep'])

# Check for libuuid availability
libuuid = dependency('uuid', required: true)
conf.set('LIBUUID', libuuid.found(), description: 'Is libuuid required?')

# Check for libjson-c availability
json_c = dependency('json-c', version: '>=0.13', fallback : ['json-c', 'json_c'])
conf.set('CONFIG_JSONC', json_c.found(), description: 'Is json-c required?')

# Check for libhugetlbfs  availability
libhugetlbfs = dependency('hugetlbfs', required: false)
conf.set('LIBHUGETLBFS', libhugetlbfs.found(), description: 'Is libhugetlbfs required?')

# Set the nvme-cli version
conf.set('NVME_VERSION', '"' + meson.project_version() + '"')

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

configure_file(
    output: 'config.h',
    configuration: conf
)

################################################################################
substs = configuration_data()
substs.set('NAME',    meson.project_name())
substs.set('VERSION', meson.project_version())
substs.set('LICENSE', meson.project_license()[0])
configure_file(
    input:         'nvme.spec.in',
    output:        'nvme.spec',
    configuration: substs,
)

################################################################################
add_project_arguments(['-fomit-frame-pointer', '-D_GNU_SOURCE',
                       '-include', 'config.h'], language : 'c')
incdir = include_directories(['ccan'])

################################################################################
sources = [
  'fabrics.c',
  'nvme.c',
  'nvme-models.c',
  'nvme-print.c',
  'nvme-rpmb.c',
  'plugin.c',
]

subdir('ccan')
subdir('plugins')
subdir('tests')
subdir('util')

executable(
    'nvme',
    sources,
    dependencies: [ libnvme_dep, libuuid, json_c ],
    include_directories: incdir,
)
