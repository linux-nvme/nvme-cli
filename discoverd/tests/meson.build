# SPDX-License-Identifier: GPL-2.0-or-later

test_dlp = executable(
    'test-dlp',
    ['test-dlp.c', '../src/dlp.c', '../src/sysfs.c', '../src/tid.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - dlp', test_dlp, suite: 'unit')

test_tid = executable(
    'test-tid',
    ['test-tid.c', '../src/tid.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - tid', test_tid, suite: 'unit')

test_config = executable(
    'test-config',
    ['test-config.c', '../src/config.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - config', test_config, suite: 'unit')

test_netif = executable(
    'test-netif',
    ['test-netif.c', '../src/netif.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - netif', test_netif, suite: 'unit')

test_sysfs = executable(
    'test-sysfs',
    ['test-sysfs.c', '../src/sysfs.c', '../src/tid.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - sysfs', test_sysfs, suite: 'unit')

test_units_local = executable(
    'test-units-local',
    ['test-units-local.c', '../src/units-local.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - units-local', test_units_local, suite: 'unit')

test_control = executable(
    'test-control',
    ['test-control.c', '../src/control.c'],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - control', test_control, suite: 'unit')

test_inventory = executable(
    'test-inventory',
    ['test-inventory.c', '../src/inventory.c', '../src/tid.c'],
    c_args: [
        '-DNBFT_TABLES="@0@"'.format(
            meson.project_source_root() / 'libnvme/tests/nbft/tables'),
    ],
    include_directories: discoverd_inc,
    dependencies: [
        ccan_dep,
        daemon_util_dep,
        libnvme_dep,
        libsystemd_dep,
        shared_dep,
    ],
)

test('nvme-discoverd - inventory', test_inventory, suite: 'unit')

test('nvme-discoverd - help', nvme_discoverd, args: ['--help'], suite: 'mock')
test('nvme-discoverd - unknown-option', nvme_discoverd,
     args: ['--bogus'], should_fail: true,
     suite: 'mock')
test('nvme-discoverd - missing-nvme-path', nvme_discoverd,
     args: ['--nvme-path', '/nonexistent/nvme'], should_fail: true,
     suite: 'mock')
test('nvme-discoverd - missing-config', nvme_discoverd,
     args: ['--config', '/nonexistent/nvme-discoverd.conf'],
     should_fail: true,
     suite: 'mock')

# The daemon in a sandbox (--set-options test-base-dir/test-sysfs-dir):
# local units, control socket, fake_nvme.py as the units' nvme binary.
if python3.found()
    test('nvme-discoverd - sandbox',
         python3,
         args: [files('test_sandbox.py'), nvme_discoverd],
         depends: nvme_discoverd,
         suite: 'mock')
endif

# The hand-over from the pre-OS environment (the real nvme under
# libmock_nvme.so, as dracut runs it) to nvme-discoverd in a sandbox. See
# handover.py and issue #4328.
if python3.found() and want_fabrics and is_variable('have_mock_nvme') and have_mock_nvme
    handover_env = environment()
    handover_env.prepend('PYTHONPATH', meson.project_source_root(),
                         meson.current_source_dir())
    handover_env.set('NVME_DISCOVERD', nvme_discoverd.full_path())
    test('nvme-discoverd - handover',
         python3,
         args: [files('test_handover.py'), nvme_exe, mock_nvme_lib],
         env: handover_env,
         depends: [nvme_discoverd, nvme_exe, mock_nvme_lib],
         timeout: 120,
         suite: 'mock')
endif
