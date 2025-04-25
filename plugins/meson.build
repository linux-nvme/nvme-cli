# SPDX-License-Identifier: GPL-2.0-or-later

sources += [
  'plugins/amzn/amzn-nvme.c',
  'plugins/dapustor/dapustor-nvme.c',
  'plugins/dell/dell-nvme.c',
  'plugins/dera/dera-nvme.c',
  'plugins/fdp/fdp.c',
  'plugins/huawei/huawei-nvme.c',
  'plugins/innogrit/innogrit-nvme.c',
  'plugins/inspur/inspur-nvme.c',
  'plugins/intel/intel-nvme.c',
  'plugins/mangoboost/mangoboost-nvme.c',
  'plugins/memblaze/memblaze-nvme.c',
  'plugins/micron/micron-nvme.c',
  'plugins/nbft/nbft-plugin.c',
  'plugins/netapp/netapp-nvme.c',
  'plugins/nvidia/nvidia-nvme.c',
  'plugins/sandisk/sandisk-nvme.c',
  'plugins/sandisk/sandisk-utils.c',
  'plugins/scaleflux/sfx-nvme.c',
  'plugins/seagate/seagate-nvme.c',
  'plugins/shannon/shannon-nvme.c',
  'plugins/ssstc/ssstc-nvme.c',
  'plugins/toshiba/toshiba-nvme.c',
  'plugins/transcend/transcend-nvme.c',
  'plugins/virtium/virtium-nvme.c',
  'plugins/wdc/wdc-nvme.c',
  'plugins/wdc/wdc-utils.c',
  'plugins/ymtc/ymtc-nvme.c',
  'plugins/zns/zns.c',
]

subdir('feat')
subdir('lm')
subdir('ocp')

if conf.get('HAVE_SED_OPAL') != 0
  subdir('sed')
endif

if json_c_dep.found()
  subdir('solidigm')
endif
