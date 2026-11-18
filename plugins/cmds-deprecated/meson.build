# SPDX-License-Identifier: GPL-2.0-or-later
#
# The deprecated top-level commands, which run the commands that replace
# them. plugins/meson.build builds this plugin with -Ddeprecated-cmds.

plugin_extension = false

plugin_sources += [
    'plugins/cmds-deprecated/deprecated-plugin.c',
]

plugin_commands = [
    'id-ctrl',
    'id-ns',
    'id-ns-granularity',
    'id-ns-lba-format',
    'list-ns',
    'list-ctrl',
    'nvm-id-ctrl',
    'nvm-id-ns',
    'nvm-id-ns-lba-format',
    'primary-ctrl-caps',
    'list-secondary',
    'cmdset-ind-id-ns',
    'ns-descs',
    'id-nvmset',
    'id-uuid',
    'id-iocs',
    'id-domain',
    'list-endgrp',
    'create-ns',
    'delete-ns',
    'attach-ns',
    'detach-ns',
    'get-ns-id',
    'supported-log-pages',
    'telemetry-log',
    'fw-log',
    'changed-ns-list-log',
    'smart-log',
    'ana-log',
    'error-log',
    'effects-log',
    'endurance-log',
    'predictable-lat-log',
    'pred-lat-event-agg-log',
    'persistent-event-log',
    'endurance-event-agg-log',
    'lba-status-log',
    'resv-notif-log',
    'boot-part-log',
    'phy-rx-eom-log',
    'self-test-log',
    'fid-support-effects-log',
    'mi-cmd-support-effects-log',
    'media-unit-stat-log',
    'supported-cap-config-log',
    'mgmt-addr-list-log',
    'rotational-media-info-log',
    'changed-alloc-ns-list-log',
    'dispersed-ns-participating-nss-log',
    'reachability-groups-log',
    'reachability-associations-log',
    'host-discovery-log',
    'ave-discovery-log',
    'pull-model-ddc-req-log',
    'power-measurement-log',
    'fw-commit',
    'fw-download',
    'security-send',
    'security-recv',
    'resv-acquire',
    'resv-register',
    'resv-release',
    'resv-report',
    'sanitize-log',
    'dir-receive',
    'dir-send',
    'io-mgmt-recv',
    'io-mgmt-send',
    'nvme-mi-recv',
    'nvme-mi-send',
]
plugin_command_aliases = {
    'fw-commit': 'fw-activate',
}

if want_fabrics
  plugin_commands += [
      'gen-dhchap-key',
      'check-dhchap-key',
      'gen-tls-key',
      'check-tls-key',
      'tls-key',
  ]
endif
