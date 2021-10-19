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
libjson = dependency('json-c', required: true)
conf.set('LIBJSONC', libjson.found(), description: 'Is json-c required?')

# Check for libhugetlbfs  availability
libhugetlbfs = dependency('hugetlbfs', required: false)
conf.set('LIBHUGETLBFS', libhugetlbfs.found(), description: 'Is libhugetlbfs required?')

# Set the nvme-cli version
conf.set('NVME_VERSION', '"' + meson.project_version() + '"')

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
    input:         'nvme.spec.in',
    output:        'nvme.spec',
    configuration: substs,
)

################################################################################
add_project_arguments(['-fomit-frame-pointer', '-D_GNU_SOURCE',
                       '-include', 'config-host.h'], language : 'c')

################################################################################
sources = [
  'fabrics.c',
  'nvme.c',
  'nvme-models.c',
  'nvme-print.c',
  'nvme-rpmb.c',
  'plugin.c',
]

subdir('plugins')
subdir('tests')
subdir('util')

executable(
    'nvme',
    sources,
    dependencies: [ libnvme_dep, libuuid, libjson ],
)
