sources += [
  'plugins/ocp/ocp-utils.c',
  'plugins/ocp/ocp-nvme.c',
  'plugins/ocp/ocp-clear-features.c',
  'plugins/ocp/ocp-smart-extended-log.c',
  'plugins/ocp/ocp-fw-activation-history.c',
  'plugins/ocp/ocp-telemetry-decode.c',
  'plugins/ocp/ocp-hardware-component-log.c',
  'plugins/ocp/ocp-print.c',
  'plugins/ocp/ocp-print-stdout.c',
  'plugins/ocp/ocp-print-binary.c',
]

if json_c_dep.found()
  sources += [
    'plugins/ocp/ocp-print-json.c',
  ]
endif
