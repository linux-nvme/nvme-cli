# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#

keysd_sources = files(
    'src/config.c',
    'src/creds.c',
    'src/import.c',
    'src/kmip-client.c',
    'src/main.c',
)

keysd_inc = include_directories('src')

nvme_keysd = executable(
    'nvme-keysd',
    keysd_sources,
    include_directories: keysd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
    install: true,
    install_dir: sbindir,
    install_tag: 'nvme-keysd',
)

if want_kmip
    nvme_keysd_kmip = executable(
        'nvme-keysd-kmip',
        files(
            'src/config.c',
            'src/kmip.c',
            'src/kmip-main.c',
            'src/kmip-psk.c',
            'src/kmip-tls.c',
            'src/ttlv.c',
        ),
        include_directories: keysd_inc,
        dependencies: [
            ccan_dep,
            daemon_util_dep,
            libnvme_dep,
            libsystemd_dep,
            openssl_dep,
            shared_dep,
        ],
        install: true,
        install_dir: sbindir,
        install_tag: 'nvme-keysd',
    )

    foreach unit : ['nvme-keysd-kmip.socket', 'nvme-keysd-kmip@.service']
        configure_file(
            input: 'systemd' / unit + '.in',
            output: unit,
            configuration: substs,
            install: true,
            install_dir: systemddir,
            install_tag: 'nvme-keysd',
        )
    endforeach

    # The encrypted client private keys. Only root reads them.
    install_emptydir(
        sysconfdir / 'nvme' / 'creds' / 'kmip',
        install_mode: 'rwx------',
        install_tag: 'nvme-keysd',
    )
endif

if get_option('tests')
    subdir('tests')
endif

configure_file(
    input: 'systemd/nvme-keysd.service.in',
    output: 'nvme-keysd.service',
    configuration: substs,
    install: true,
    install_dir: systemddir,
    install_tag: 'nvme-keysd',
)

# The encrypted credentials. Only root reads them.
install_emptydir(
    sysconfdir / 'nvme' / 'creds',
    install_mode: 'rwx------',
    install_tag: 'nvme-keysd',
)

configure_file(
    input: 'etc/nvme/nvme-keysd.conf.in',
    output: 'nvme-keysd.conf',
    configuration: substs,
    install: true,
    install_dir: sysconfdir / 'nvme',
    install_tag: 'nvme-keysd',
)
