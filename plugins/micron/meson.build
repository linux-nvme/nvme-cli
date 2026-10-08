# SPDX-License-Identifier: GPL-2.0-or-later

plugin_sources += [
    'plugins/micron/micron-nvme.c',
    'plugins/micron/micron-utils.c',
]

if host_system == 'windows'
  plugin_sources += ['plugins/micron/micron-utils-win.c']
elif host_system == 'freebsd'
  plugin_sources += ['plugins/micron/micron-utils-freebsd.c']
else
  plugin_sources += ['plugins/micron/micron-utils-linux.c']
endif
