from distutils.core import setup, Extension

libnvme_module = Extension(
    '_nvme',
    sources = ['nvme_wrap.c'],
    libraries = ['nvme', 'json-c', 'uuid', 'systemd'],
    library_dirs = ['../src'],
    include_dirs = ['../ccan', '../src', '../src/nvme'],
)

setup(
    name='libnvme',
    author="Hannes Reinecke",
    author_email='hare@suse.de',
    description='python bindings for libnvme',
    ext_modules=[libnvme_module],
    py_modules=["nvme"],
)
