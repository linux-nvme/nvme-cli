# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>

mock_conf = configuration_data()

mock_conf.set(
    'NVME_HAVE_GLIBC_IOCTL',
    cc.compiles(
        '''#include <sys/ioctl.h>
        int ioctl(int fd, unsigned long request, ...);
        ''',
        name: 'ioctl has glibc-style prototype'
    ),
    description: 'Is ioctl the glibc interface (rather than POSIX)'
)

if host_system == 'windows'
    # Windows has neither LD_PRELOAD nor a passthru ioctl, so the mock is a
    # different implementation reached a different way: it is linked into each
    # test and rewrites libnvme's DeviceIoControl import thunk at runtime.
    # See mock-win.c and iat-hook.c for why --wrap can't do this job.
    mock_sources = ['mock-win.c', 'iat-hook.c', 'util.c']
    mock_c_args = [
        '-DLIBNVME_DLL_NAME="lib' + libnvme_link_name + '-'
            + libnvme_so_major + '.dll"',
    ]
    mock_deps = [config_dep, ccan_dep, libnvme_dep]
else
    mock_sources = ['mock.c', 'util.c']
    mock_c_args = [
        '-DNVME_HAVE_GLIBC_IOCTL='
            + (mock_conf.get('NVME_HAVE_GLIBC_IOCTL') ? '1' : '0'),
    ]
    mock_deps = [config_dep, ccan_dep, libnvme_dep, dl_dep]
endif

mock_ioctl = library(
    'mock-ioctl',
    mock_sources,
    dependencies: mock_deps,
    c_args: mock_c_args,
)

mock_ioctl_env = environment()
if host_system != 'windows'
    # Add mock-ioctl to the LD_PRELOAD path so it overrides libc.
    # Append to LD_PRELOAD so existing libraries, e.g. libasan, are kept.
    # If libasan isn't specified in the LD_PRELOAD path, ASAN warns about
    # mock-ioctl being loaded first because its memory allocations might not get
    # intercepted. But it appears this isn't a problem; ASAN errors in
    # mock-ioctl are reported. This is likely because the executable still links
    # with libasan before libc.
    mock_ioctl_env.append('LD_PRELOAD', mock_ioctl.full_path())
    mock_ioctl_env.set('ASAN_OPTIONS', 'verify_asan_link_order=0')
endif

mock_ioctl_tests = ['ana', 'async', 'features', 'identify', 'logs', 'zns',
                    'misc']

if want_fabrics
    mock_ioctl_tests += 'discovery'
endif

# On Windows the mock decodes the NVMe-specific Windows IOCTLs that
# are supported, which so far covers identify, get/set features and get log page.
# The remaining tests exercise command families that reach the driver by other
# routes (SCSI CDBs for read/write/flush, dedicated firmware/format/sanitize
# IOCTLs) or that libnvme does not implement on Windows at all. Enabling them
# needs a decoder per family, not a change here, so they stay off rather than
# reporting a pass they didn't earn.
if host_system == 'windows'
    mock_ioctl_tests = ['identify', 'features', 'logs']
endif

foreach mock_ioctl_test : mock_ioctl_tests
    exe = executable(
        'test-' + mock_ioctl_test,
        mock_ioctl_test + '.c',
        dependencies: [
            config_dep,
            ccan_dep,
            libnvme_dep,
        ],
        link_with: mock_ioctl,
    )
    test('libnvme - ' + mock_ioctl_test, exe, env: mock_ioctl_env)
endforeach
