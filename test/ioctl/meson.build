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
