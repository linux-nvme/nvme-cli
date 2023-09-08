mock_ioctl = library(
    'mock-ioctl',
    ['mock.c', 'util.c'],
)

discovery = executable(
    'test-discovery',
    'discovery.c',
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir],
    link_with: mock_ioctl,
)

test('discovery', discovery, env: ['LD_PRELOAD=' + mock_ioctl.full_path()])

features = executable(
    'test-features',
    'features.c',
    dependencies: libnvme_dep,
    link_with: mock_ioctl,
)

test('features', features, env: ['LD_PRELOAD=' + mock_ioctl.full_path()])

identify = executable(
    'test-identify',
    'identify.c',
    dependencies: libnvme_dep,
    link_with: mock_ioctl,
)

test('identify', identify, env: ['LD_PRELOAD=' + mock_ioctl.full_path()])
