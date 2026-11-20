# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of nvme-cli.
#
# The log archives of the vendor plugins. Not part of libshared: the plugins
# which create archives link it, so that with plugin modules the code is in
# their modules and not in nvme.

if libarchive_dep.found()
    archive_sources = ['archive-util.c']
else
    archive_sources = ['archive-util-stub.c']
endif

# The functions of libshared come from nvme, like those the plugins call
archive_deps = [config_dep]
foreach d : [ccan_dep, shared_dep]
    archive_deps += d.partial_dependency(compile_args: true, includes: true)
endforeach
if libarchive_dlopen
    archive_deps += [
        libarchive_dep.partial_dependency(compile_args: true, includes: true),
        dl_dep,
    ]
elif libarchive_dep.found()
    archive_deps += [libarchive_dep]
endif

libshared_archive = static_library(
    'shared-archive',
    archive_sources,
    dependencies: archive_deps,
    # Each module has a copy of its own, which wdc.so doesn't export to sndk.so
    gnu_symbol_visibility: want_plugin_modules ? 'hidden' : '',
    install: false,
)

archive_util_dep = declare_dependency(
    link_with: libshared_archive,
)
