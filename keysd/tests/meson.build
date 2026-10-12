# SPDX-License-Identifier: GPL-2.0-or-later

test_config = executable(
    'test-keysd-config',
    ['test-config.c', '../src/config.c'],
    include_directories: keysd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        shared_dep,
    ],
)

test('nvme-keysd - config', test_config)

test_ttlv = executable(
    'test-keysd-ttlv',
    ['test-ttlv.c', '../src/ttlv.c'],
    include_directories: keysd_inc,
)

test('nvme-keysd - ttlv', test_ttlv)

test_kmip = executable(
    'test-keysd-kmip',
    ['test-kmip.c', 'kmip-responses.c', '../src/kmip.c', '../src/ttlv.c'],
    include_directories: keysd_inc,
)

test('nvme-keysd - kmip', test_kmip)

test_kmip_tls = executable(
    'test-keysd-kmip-tls',
    ['test-kmip-tls.c', 'tls-server.c', '../src/kmip-tls.c'],
    include_directories: keysd_inc,
    dependencies: [
        daemon_util_dep,
        openssl_dep,
    ],
)

test('nvme-keysd - kmip tls', test_kmip_tls)

if want_kmip
    test_kmip_psk = executable(
        'test-keysd-kmip-psk',
        [
            'test-kmip-psk.c',
            'kmip-responses.c',
            'tls-server.c',
            '../src/config.c',
            '../src/kmip.c',
            '../src/kmip-psk.c',
            '../src/kmip-tls.c',
            '../src/ttlv.c',
        ],
        include_directories: keysd_inc,
        dependencies: [
            ccan_dep,
            daemon_util_dep,
            libnvme_dep,
            openssl_dep,
            shared_dep,
        ],
    )

    test('nvme-keysd - kmip psk', test_kmip_psk)

    test_kmip_client = executable(
        'test-keysd-kmip-client',
        ['test-kmip-client.c', '../src/config.c', '../src/kmip-client.c'],
        include_directories: keysd_inc,
        dependencies: [
            ccan_dep,
            daemon_util_dep,
            libsystemd_dep,
            shared_dep,
        ],
    )

    test('nvme-keysd - kmip client', test_kmip_client)

    test('nvme-keysd-kmip - --help', nvme_keysd_kmip, args: ['--help'])
    test('nvme-keysd-kmip - not socket activated', nvme_keysd_kmip,
         should_fail: true)
endif

test('nvme-keysd - --help', nvme_keysd, args: ['--help'])
test('nvme-keysd - unknown option', nvme_keysd,
     args: ['--bogus'], should_fail: true)
test('nvme-keysd - missing --config', nvme_keysd,
     args: ['--config', '/nonexistent/nvme-keysd.conf'],
     should_fail: true)
test('nvme-keysd - missing --creds-dir', nvme_keysd,
     args: ['--creds-dir', '/nonexistent/creds'], should_fail: true)
test('nvme-keysd - missing --fabrics-config', nvme_keysd,
     args: ['--fabrics-config', '/nonexistent/config.ini'],
     should_fail: true)
