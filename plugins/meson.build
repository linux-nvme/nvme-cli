# SPDX-License-Identifier: GPL-2.0-or-later

# Define all available plugins and their source files
all_plugins = {}
if host_system != 'windows'
  all_plugins += {
    'amzn': ['plugins/amzn/amzn-nvme.c'],
    'dapustor': ['plugins/dapustor/dapustor-nvme.c'],
    'dell': ['plugins/dell/dell-nvme.c'],
    'dera': ['plugins/dera/dera-nvme.c'],
    'fdp': ['plugins/fdp/fdp.c'],
    'huawei': ['plugins/huawei/huawei-nvme.c'],
    'ibm': ['plugins/ibm/ibm-nvme.c'],
    'innogrit': ['plugins/innogrit/innogrit-nvme.c'],
    'inspur': ['plugins/inspur/inspur-nvme.c'],
    'intel': ['plugins/intel/intel-nvme.c'],
    'mangoboost': ['plugins/mangoboost/mangoboost-nvme.c'],
    'memblaze': ['plugins/memblaze/memblaze-nvme.c'],
    'micron': ['plugins/micron/micron-nvme.c'],
    'netapp': ['plugins/netapp/netapp-nvme.c'],
    'nvidia': ['plugins/nvidia/nvidia-nvme.c'],
    'sandisk': ['plugins/sandisk/sandisk-nvme.c', 'plugins/sandisk/sandisk-utils.c'],
    'scaleflux': ['plugins/scaleflux/sfx-nvme.c'],
    'seagate': ['plugins/seagate/seagate-nvme.c'],
    'shannon': ['plugins/shannon/shannon-nvme.c'],
    'ssstc': ['plugins/ssstc/ssstc-nvme.c'],
    'toshiba': ['plugins/toshiba/toshiba-nvme.c'],
    'transcend': ['plugins/transcend/transcend-nvme.c'],
    'virtium': ['plugins/virtium/virtium-nvme.c'],
    'wdc': ['plugins/wdc/wdc-nvme.c', 'plugins/wdc/wdc-utils.c'],
    'ymtc': ['plugins/ymtc/ymtc-nvme.c'],
    'zns': ['plugins/zns/zns.c'],
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

if host_system != 'windows'
  if 'feat' in selected_plugins
    subdir('feat')
  endif

  if 'lm' in selected_plugins
    subdir('lm')
  endif

  if 'ocp' in selected_plugins
    subdir('ocp')
  endif

  if 'sed' in selected_plugins and conf.get('HAVE_SED_OPAL') != 0
    subdir('sed')
  endif

  if 'solidigm' in selected_plugins and json_c_dep.found()
    subdir('solidigm')
  endif
endif
