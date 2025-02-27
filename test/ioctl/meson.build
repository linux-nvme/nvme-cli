mock_conf = configuration_data()

mock_conf.set(
    'HAVE_GLIBC_IOCTL',
    cc.compiles(
        '''#include <sys/ioctl.h>
        int ioctl(int fd, unsigned long request, ...);
        ''',
        name: 'ioctl has glibc-style prototype'
    ),
    description: 'Is ioctl the glibc interface (rather than POSIX)'
)

mock_ioctl = library(
    'mock-ioctl',
    ['mock.c', 'util.c'],
    dependencies: [dl_dep],
    c_args: ['-DHAVE_GLIBC_IOCTL=' + (mock_conf.get('HAVE_GLIBC_IOCTL') ? '1' : '0')])

# Add mock-ioctl to the LD_PRELOAD path so it overrides libc.
# Append to LD_PRELOAD so existing libraries, e.g. libasan, are kept.
# If libasan isn't specified in the LD_PRELOAD path, ASAN warns about mock-ioctl
# being loaded first because its memory allocations might not get intercepted.
# But it appears this isn't a problem; ASAN errors in mock-ioctl are reported.
# This is likely because the executable still links with libasan before libc.
mock_ioctl_env = environment()
mock_ioctl_env.append('LD_PRELOAD', mock_ioctl.full_path())
mock_ioctl_env.set('ASAN_OPTIONS', 'verify_asan_link_order=0')

ana = executable(
    'test-ana',
    'ana.c',
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir],
    link_with: mock_ioctl,
)

test('ana', ana, env: mock_ioctl_env)

discovery = executable(
    'test-discovery',
    'discovery.c',
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir],
    link_with: mock_ioctl,
)

test('discovery', discovery, env: mock_ioctl_env)

features = executable(
    'test-features',
    'features.c',
    dependencies: libnvme_dep,
    link_with: mock_ioctl,
)

test('features', features, env: mock_ioctl_env)

identify = executable(
    'test-identify',
    'identify.c',
    dependencies: libnvme_dep,
    link_with: mock_ioctl,
)

test('identify', identify, env: mock_ioctl_env)
