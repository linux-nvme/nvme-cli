# SPDX-License-Identifier: GPL-2.0-or-later

sources = [
    'src/args.c',
    'src/argconfig.c',
    'src/global-config.c',
    'src/global-ctx.c',
    'src/global-options.c',
    'src/logging.c',
    'src/nvme-pci-ids.c',
    'src/nvme-print-binary.c',
    'src/nvme-print-stdout.c',
    'src/nvme-print-stdout-log.c',
    'src/nvme-print.c',
    'src/nvme.c',
    'src/nvme-cmds-enumerate.c',
    'src/nvme-cmds-discovery.c',
    'src/nvme-cmds-fabrics.c',
    'src/nvme-cmds-feature.c',
    'src/plugin.c',
    'src/privsep.c',
    'src/field-parser.c',
]

if want_plugin_modules
    sources += ['src/plugin-loader.c']
endif

if host_system == 'linux'
    sources += [
        'src/nvme-pci-ids-linux.c',
        'src/dashboard.c',
    ]
elif host_system == 'windows'
    sources += [
        'src/nvme-pci-ids-win.c',
    ]
elif host_system == 'freebsd'
    sources += [
        'src/nvme-pci-ids-freebsd.c',
    ]
endif

if json_c_dep.found()
    sources += [
        'src/nvme-print-json.c',
        'src/nvme-json.c',
    ]
endif

if want_fabrics
    sources += [
        'src/fabrics.c',
        'src/config-convert.c',
        'src/config-create.c',
        'src/pre-os.c',
    ]
endif

if want_top
    sources += ['src/nvme-iostat.c', 'src/nvme-print-stdout-top.c']
endif
