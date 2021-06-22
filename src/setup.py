from distutils.core import setup, Extension

libnvme_module = Extension('_libnvme',
        sources=['nvme/libnvme_wrap.c'],
        libraries=['nvme', 'json-c', 'uuid', 'systemd'], library_dirs=['./'],
        include_dirs = ['../ccan','nvme'])

setup(name='libnvme',
      author="Hannes Reinecke",
      author_email='hare@suse.de',
      description='python bindings for libnvme',
      ext_modules=[libnvme_module],
      py_modules=["libnvme"],
)
