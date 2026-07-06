# SPDX-License-Identifier: GPL-2.0-or-later

# Define all available plugins and their source files
all_plugins = {
  'amzn': ['plugins/amzn/amzn-nvme.c'],
  'dapustor': ['plugins/dapustor/dapustor-nvme.c'],
  'dell': ['plugins/dell/dell-nvme.c'],
  'dera': ['plugins/dera/dera-nvme.c'],
  'fdp': ['plugins/fdp/fdp.c'],
  'ibm': ['plugins/ibm/ibm-nvme.c'],
  'innogrit': ['plugins/innogrit/innogrit-nvme.c'],
  'inspur': ['plugins/inspur/inspur-nvme.c'],
  'intel': ['plugins/intel/intel-nvme.c'],
  'mangoboost': ['plugins/mangoboost/mangoboost-nvme.c'],
  'memblaze': ['plugins/memblaze/memblaze-nvme.c'],
  'nvidia': ['plugins/nvidia/nvidia-nvme.c'],
  'seagate': ['plugins/seagate/seagate-nvme.c'],
  'shannon': ['plugins/shannon/shannon-nvme.c'],
  'ssstc': ['plugins/ssstc/ssstc-nvme.c'],
  'toshiba': ['plugins/toshiba/toshiba-nvme.c'],
  'transcend': ['plugins/transcend/transcend-nvme.c'],
  'virtium': ['plugins/virtium/virtium-nvme.c'],
  'ymtc': ['plugins/ymtc/ymtc-nvme.c'],
}
if host_system != 'windows'
  all_plugins += {
    'huawei': ['plugins/huawei/huawei-nvme.c'],
    'micron': [
      'plugins/micron/micron-nvme.c',
      'plugins/micron/micron-utils.c',
      'plugins/micron/micron-utils-linux.c'
      ],
    'netapp': ['plugins/netapp/netapp-nvme.c'],
    'sandisk': ['plugins/sandisk/sandisk-nvme.c', 'plugins/sandisk/sandisk-utils.c'],
    'scaleflux': ['plugins/scaleflux/sfx-nvme.c'],
    'wdc': ['plugins/wdc/wdc-nvme.c', 'plugins/wdc/wdc-utils.c'],
    'zns': ['plugins/zns/zns.c'],
  }
else
  all_plugins += {
    'micron': [
      'plugins/micron/micron-nvme.c',
      'plugins/micron/micron-utils.c',
      'plugins/micron/micron-utils-win.c'
      ],
  }
endif

# Get the list of plugins to build
selected_plugins = get_option('plugins')

# Build the plugin_sources list from simple plugins
plugin_sources = []
foreach plugin_name : selected_plugins
  plugin_name_stripped = plugin_name.strip()
  if plugin_name_stripped in all_plugins
    plugin_sources += all_plugins[plugin_name_stripped]
  endif
endforeach

if want_fabrics and 'nbft' in selected_plugins
    plugin_sources += ['plugins/nbft/nbft-plugin.c']
endif

if want_fabrics and 'exclusion' in selected_plugins
    plugin_sources += ['plugins/exclusion/exclusion-nvme.c']
endif

if want_fabrics and 'registry' in selected_plugins
    plugin_sources += ['plugins/registry/registry-nvme.c']
endif

if 'feat' in selected_plugins
  subdir('feat')
endif

if 'lm' in selected_plugins and host_system != 'windows'
  subdir('lm')
endif

if 'ocp' in selected_plugins and json_c_dep.found()
  subdir('ocp')
endif

if 'sed' in selected_plugins and conf.get('NVME_HAVE_SED_OPAL') != 0
  subdir('sed')
endif

if 'solidigm' in selected_plugins and json_c_dep.found()
  subdir('solidigm')
endif
