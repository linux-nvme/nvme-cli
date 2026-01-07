# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
if want_libnvme
    if openssl_dep.found() and meson.can_run_host_binaries()
        if openssl_dep.type_name() != 'internal'
            # Check for a bug in the EVP_PKEY_CTX_add1_hkdf_info implementation
            res = cc.run(
                files('test/hkdf_add1.c'),
                dependencies: [openssl_dep],
                name: 'check hkdf_add1'
            )
            if res.returncode() == 1
                warning('EVP_PKEY_CTX_add1_hkdf_info bahaves incorrectly')
            else
                message('EVP_PKEY_CTX_add1_hkdf_info behaves sanely')
            endif
        endif
    endif

    ############################################################################
    configure_file(
        input:         'libnvme.spec.in',
        output:        'libnvme.spec',
        configuration: substs,
    )

    ############################################################################
    subdir('src')       # declares: libnvme_dep
    subdir('libnvme')
    if get_option('tests')
        subdir('test')
    endif
    if get_option('examples')
        subdir('examples')
    endif
else
    # Fallback to using a pre-installed libnvme (if available)
    if std_prefix
        # When prefix points to a standard location, meson can use
        # standard methods (e.g. pkg-config) to find the library.
        libnvme_dep = dependency(
            'libnvme',
            version: '>=@0@'.format(libnvme_so_version),
            required: want_nvme,
        )
    else
        # When prefix points to a non-standard location
        # let's ask the C compiler to find the library for us.
        libnvme_dep = cc.find_library(
            'nvme',
            dirs: prefixdir / get_option('libdir'),
            required: want_nvme,
        )
    endif
endif

subdir('doc')
