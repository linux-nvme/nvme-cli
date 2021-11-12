adoc_sources = [
  'nvme-admin-passthru',
  'nvme-ana-log',
  'nvme-attach-ns',
  'nvme-boot-part-log',
  'nvme-capacity-mgmt',
  'nvme-changed-ns-list-log',
  'nvme-cmdset-ind-id-ns',
  'nvme-compare',
  'nvme-connect-all',
  'nvme-connect',
  'nvme-copy',
  'nvme-create-ns',
  'nvme-delete-ns',
  'nvme-dera-stat',
  'nvme-detach-ns',
  'nvme-device-self-test',
  'nvme-dir-receive',
  'nvme-dir-send',
  'nvme-disconnect-all',
  'nvme-disconnect',
  'nvme-discover',
  'nvme-dsm',
  'nvme-effects-log',
  'nvme-endurance-event-agg-log',
  'nvme-endurance-log',
  'nvme-error-log',
  'nvme-fid-support-effects-log',
  'nvme-flush',
  'nvme-format',
  'nvme-fw-commit',
  'nvme-fw-download',
  'nvme-fw-log',
  'nvme-gen-hostnqn',
  'nvme-get-feature',
  'nvme-get-lba-status',
  'nvme-get-log',
  'nvme-get-ns-id',
  'nvme-get-property',
  'nvme-help',
  'nvme-huawei-id-ctrl',
  'nvme-huawei-list',
  'nvme-id-ctrl',
  'nvme-id-domain',
  'nvme-id-iocs',
  'nvme-id-ns',
  'nvme-id-nvmset',
  'nvme-intel-id-ctrl',
  'nvme-intel-internal-log',
  'nvme-intel-lat-stats',
  'nvme-intel-market-name',
  'nvme-intel-smart-log-add',
  'nvme-intel-temp-stats',
  'nvme-io-passthru',
  'nvme-lba-status-log',
  'nvme-list-ctrl',
  'nvme-list-endgrp',
  'nvme-list-ns',
  'nvme-list-subsys',
  'nvme-list',
  'nvme-lnvm-create',
  'nvme-lnvm-diag-bbtbl',
  'nvme-lnvm-diag-set-bbtbl',
  'nvme-lnvm-factory',
  'nvme-lnvm-id-ns',
  'nvme-lnvm-info',
  'nvme-lnvm-init',
  'nvme-lnvm-list',
  'nvme-lnvm-remove',
  'nvme-lockdown',
  'nvme-micron-clear-pcie-errors',
  'nvme-micron-internal-log',
  'nvme-micron-nand-stats',
  'nvme-micron-pcie-stats',
  'nvme-micron-selective-download',
  'nvme-micron-smart-add-log',
  'nvme-micron-temperature-stats',
  'nvme-netapp-ontapdevices',
  'nvme-netapp-smdevices',
  'nvme-ns-descs',
  'nvme-ns-rescan',
  'nvme-nvm-id-ctrl',
  'nvme-persistent-event-log',
  'nvme-predictable-lat-log',
  'nvme-pred-lat-event-agg-log',
  'nvme-primary-ctrl-caps',
  'nvme-read',
  'nvme-reset',
  'nvme-resv-acquire',
  'nvme-resv-notif-log',
  'nvme-resv-register',
  'nvme-resv-release',
  'nvme-resv-report',
  'nvme-rpmb',
  'nvme-sanitize-log',
  'nvme-sanitize',
  'nvme-security-recv',
  'nvme-security-send',
  'nvme-self-test-log',
  'nvme-set-feature',
  'nvme-set-property',
  'nvme-show-hostnqn',
  'nvme-show-regs',
  'nvme-smart-log',
  'nvme-subsystem-reset',
  'nvme-supported-log-pages',
  'nvme-telemetry-log',
  'nvme-toshiba-clear-pcie-correctable-errors',
  'nvme-toshiba-vs-internal-log',
  'nvme-toshiba-vs-smart-add-log',
  'nvme-transcend-badblock',
  'nvme-transcend-healthvalue',
  'nvme',
  'nvme-verify',
  'nvme-virtium-save-smart-to-vtview-log',
  'nvme-virtium-show-identify',
  'nvme-wdc-capabilities',
  'nvme-wdc-cap-diag',
  'nvme-wdc-clear-assert-dump',
  'nvme-wdc-clear-fw-activate-history',
  'nvme-wdc-clear-pcie-correctable-errors',
  'nvme-wdc-cloud-SSD-plugin-version',
  'nvme-wdc-drive-essentials',
  'nvme-wdc-drive-log',
  'nvme-wdc-drive-resize',
  'nvme-wdc-enc-get-log',
  'nvme-wdc-get-crash-dump',
  'nvme-wdc-get-drive-status',
  'nvme-wdc-get-latency-monitor-log',
  'nvme-wdc-get-pfail-dump',
  'nvme-wdc-id-ctrl',
  'nvme-wdc-log-page-directory',
  'nvme-wdc-namespace-resize',
  'nvme-wdc-purge-monitor',
  'nvme-wdc-purge',
  'nvme-wdc-vs-drive-info',
  'nvme-wdc-vs-error-reason-identifier',
  'nvme-wdc-vs-fw-activate-history',
  'nvme-wdc-vs-internal-log',
  'nvme-wdc-vs-nand-stats',
  'nvme-wdc-vs-smart-add-log',
  'nvme-wdc-vs-telemetry-controller-option',
  'nvme-wdc-vs-temperature-stats',
  'nvme-write',
  'nvme-write-uncor',
  'nvme-write-zeroes',
  'nvme-zns-changed-zone-list',
  'nvme-zns-close-zone',
  'nvme-zns-finish-zone',
  'nvme-zns-id-ctrl',
  'nvme-zns-id-ns',
  'nvme-zns-offline-zone',
  'nvme-zns-open-zone',
  'nvme-zns-report-zones',
  'nvme-zns-reset-zone',
  'nvme-zns-set-zone-desc',
  'nvme-zns-zone-append',
  'nvme-zns-zone-mgmt-recv',
  'nvme-zns-zone-mgmt-send',
]

want_docs = get_option('docs')
if want_docs != 'false'
  mandir = join_paths(get_option('mandir'), 'man1')
  htmldir = join_paths(get_option('htmldir'), 'nvme')

  asciidoctor = find_program('asciidoc', required : false)
  if asciidoctor.found()
    # Build documentation before installing

    # man pages
    if want_docs == 'all' or want_docs == 'man'
      xmlto = find_program('xmlto', required: false)
      if xmlto.found()
        foreach adoc : adoc_sources
          input = adoc + '.txt'
          xml = custom_target(
            adoc.underscorify() + '_xml',
            input: adoc + '.txt',
            output: '@BASENAME@.xml',
            command: [asciidoctor,
                      '-f', files('asciidoc.conf'),
                      '-b', 'docbook',
                      '-d', 'manpage',
                      '-o', '@OUTPUT@',
                      '@INPUT@'],
          )
          custom_target(
            adoc.underscorify() + '_man',
            input: xml,
            output: '@BASENAME@.1',
            command: [xmlto,
                      '-m', files('manpage-normal.xsl'),
                      '-o', '@OUTDIR@',
                      '--skip-validation',
                      'man',
                      '@INPUT@'],
            install: true,
            install_dir: mandir)
        endforeach
      endif
    endif

    # html
    if want_docs == 'all' or want_docs == 'html'
      foreach adoc : adoc_sources
        input = adoc + '.txt'
        custom_target(
          adoc.underscorify() + '_html',
          input: adoc + '.txt',
          output: '@BASENAME@.html',
          command: [asciidoctor,
                    '-f', files('asciidoc.conf'),
                    '-b', 'xhtml11',
                    '-d', 'manpage',
                    '-o', '@OUTPUT@',
                    '@INPUT@'],
          install: true,
          install_dir: htmldir)
      endforeach
    endif

  else
    # asciidoctor not found, install pre compiled documetationx

    foreach adoc : adoc_sources
      if want_docs == 'all' or want_docs == 'man'
        man = files(adoc + '.1')
        install_data(man, install_dir: mandir)
      endif
      if want_docs == 'all' or want_docs == 'html'
        html = files(adoc + '.html')
        install_data(html, install_dir: htmldir)
      endif
    endforeach

  endif
endif
