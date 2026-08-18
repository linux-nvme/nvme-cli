# SPDX-License-Identifier: GPL-2.0-or-later

if host_system != 'windows'
  plugin_sources += [
      'plugins/micron/micron-nvme.c',
      'plugins/micron/micron-utils.c',
      'plugins/micron/micron-utils-linux.c',
  ]
else
  plugin_sources += [
      'plugins/micron/micron-nvme.c',
      'plugins/micron/micron-utils.c',
      'plugins/micron/micron-utils-win.c',
  ]
endif
