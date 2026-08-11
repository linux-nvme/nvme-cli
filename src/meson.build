# SPDX-License-Identifier: GPL-2.0-or-later

sources = [
    'src/args.c',
    'src/argconfig.c',
    'src/global-config.c',
    'src/logging.c',
    'src/nvme-cmds.c',
    'src/nvme-models.c',
    'src/nvme-pci-ids.c',
    'src/nvme-print-binary.c',
    'src/nvme-print-stdout.c',
    'src/nvme-print.c',
    'src/nvme-rpmb.c',
    'src/nvme.c',
    'src/plugin.c',
    'src/field-parser.c',
]

if host_system == 'linux'
    sources += [
        'src/nvme-pci-ids-linux.c',
        'src/dashboard.c',
    ]
elif host_system == 'windows'
    sources += [
        'src/nvme-pci-ids-win.c',
    ]
endif

if json_c_dep.found()
    sources += [
        'src/nvme-print-json.c',
        'src/json.c',
    ]
endif

if want_fabrics
    sources += [
        'src/fabrics.c',
        'src/config-convert.c',
        'src/config-create.c',
    ]
endif

if want_top
    sources += 'src/nvme-print-stdout-top.c'
endif
