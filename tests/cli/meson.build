# SPDX-License-Identifier: GPL-2.0-or-later
#
# CLI-driven tests: they exercise the built nvme binary but need no NVMe
# hardware. Hardware/device tests live in ../e2e/; C and Python unit tests
# live in ../unit/.

cli_test_env = environment()
cli_test_env.prepend('PYTHONPATH', meson.project_source_root())
# Without json-c, some commands ignore '-o json' and print text.
cli_test_env.set('NVME_TEST_JSON', json_c_dep.found() ? '1' : '0')

if python3.found()
    # Standalone CLI test for the ownership registry.  It needs no device
    # (it uses NVME_REGISTRY_DIR).
    if want_fabrics and 'registry' in selected_plugins
        test('nvme-cli - registry',
             python3,
             args: [files('nvme_registry_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe,
             suite: 'mock')
    endif

    # Standalone CLI test for the "keys" plugin. Needs no device. Restricted
    # to the commands that need no keyring access (the test's docstring
    # lists them), so it only needs OpenSSL, not a working kernel keyring.
    if want_fabrics and 'keys' in selected_plugins and openssl_dep.found()
        test('nvme-cli - keys',
             python3,
             args: [files('nvme_keys_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe,
             suite: 'mock')
    endif

    # Standalone CLI test for "nvme config-convert". Needs no device; uses
    # an explicit --config/--output pair under /tmp instead. Requires
    # json-c since the legacy config.json reader is a no-op without it,
    # and the "config" plugin, which has the command.
    if want_fabrics and 'config' in selected_plugins and json_c_dep.found()
        test('nvme-cli - config-convert',
             python3,
             args: [files('nvme_config_convert_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe,
             suite: 'mock')
    endif

    # Standalone CLI test for "nvme config-create". Needs no device; uses an
    # explicit --output under /tmp instead. "config create" lives in the
    # "config" plugin, so it needs that plugin selected too.
    if want_fabrics and 'config' in selected_plugins
        test('nvme-cli - config-create',
             python3,
             args: [files('nvme_config_create_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe,
             suite: 'mock')
    endif

    if want_fabrics
        test('nvme-cli - nbft-interface-references',
             python3,
             args: [
                 files('nvme_nbft_test.py'),
                 nvme_exe,
                 files('nbft/NBFT-secondary-hfi-gap'),
                 files('nbft/NBFT-unresolved-discovery-hfi'),
                 files('nbft/NBFT-unlinked-discovery'),
             ],
             env: cli_test_env,
             depends: nvme_exe,
             suite: 'mock')
    endif

    have_mock_nvme = (not is_static) and (host_system == 'linux')

    if have_mock_nvme
        mock_nvme_lib = shared_library(
            'mock_nvme',
            'libmock_nvme.c',
            include_directories: '../..',
            dependencies: dl_dep,
            install: false
        )
        # cli_test_env.prepend('MOCK_DEBUG', '1')

        if want_mi
            mock_mctp_lib = shared_library(
                'mock_mctp',
                'libmock_mctp.c',
                dependencies: dl_dep,
                install: false
            )
        endif

        if want_fabrics
            test('nvme-cli - fabrics',
                 python3,
                 args: [files('nvme_fabrics_mock_test.py'), nvme_exe, mock_nvme_lib],
                 env: cli_test_env,
                 depends: [nvme_exe, mock_nvme_lib],
                 suite: 'mock')
        endif

        # [name, script, env, timeout]. With privsep, each also runs with
        # the commands going through the helper.
        mock_cli_tests = [
            ['pif-sts', 'nvme_pif_sts_test.py', cli_test_env, 30],
            ['init-pi-tags', 'nvme_init_pi_tags_test.py', cli_test_env, 30],
            ['dry-run', 'nvme_dry_run_test.py', cli_test_env, 30],
            ['sel', 'nvme_sel_test.py', cli_test_env, 30],
            ['format', 'nvme_format_test.py', cli_test_env, 30],
            ['passthru', 'nvme_passthru_test.py', cli_test_env, 30],
            ['host-metadata', 'nvme_host_metadata_test.py', cli_test_env,
             30],
            ['fuzz-record', 'nvme_fuzz_record_test.py', cli_test_env, 30],
            ['device-self-test', 'nvme_device_self_test_test.py',
             cli_test_env, 30],
            ['sanitize', 'nvme_sanitize_test.py', cli_test_env, 30],
        ]

        if 'feat' in selected_plugins
            mock_cli_tests += [
                ['features', 'nvme_features_test.py', cli_test_env, 30],
            ]
        endif

        if 'fw' in selected_plugins
            mock_cli_tests += [
                ['fw', 'nvme_fw_test.py', cli_test_env, 30],
            ]
        endif

        if 'ns' in selected_plugins
            mock_cli_tests += [
                ['ns', 'nvme_ns_test.py', cli_test_env, 30],
            ]
        endif

        if 'id' in selected_plugins and json_c_dep.found()
            mock_cli_tests += [
                ['ns-descs', 'nvme_ns_descs_test.py', cli_test_env, 30],
            ]
        endif

        if 'dir' in selected_plugins and json_c_dep.found()
            mock_cli_tests += [
                ['dir-receive', 'nvme_dir_receive_test.py', cli_test_env,
                 30],
            ]
        endif

        if 'ns' in selected_plugins and 'resv' in selected_plugins
            mock_cli_tests += [
                ['ctratt', 'nvme_ctratt_test.py', cli_test_env, 30],
            ]
        endif

        if 'rpmb' in selected_plugins
            mock_cli_tests += [
                ['rpmb', 'nvme_rpmb_test.py', cli_test_env, 30],
            ]
        endif

        if 'zns' in selected_plugins
            mock_cli_tests += [
                ['zns-append', 'nvme_zns_append_test.py', cli_test_env, 30],
            ]
        endif

        # A command of the sandisk plugin which falls back to the wdc one
        if 'sandisk' in selected_plugins and 'wdc' in selected_plugins and \
           json_c_dep.found()
            mock_cli_tests += [
                ['json-document', 'nvme_json_document_test.py', cli_test_env,
                 30],
                ['sndk-fallback', 'nvme_sndk_fallback_test.py', cli_test_env,
                 30],
            ]
        endif

        if 'ymtc' in selected_plugins
            mock_cli_tests += [
                ['ymtc', 'nvme_ymtc_test.py', cli_test_env, 30],
            ]
        endif

        if 'id' in selected_plugins
            test('nvme-cli - usage',
                 python3,
                 args: [files('nvme_usage_test.py'), nvme_exe],
                 depends: nvme_exe,
                 suite: 'mock')
        endif

        # The host and AVE discovery printers need the fabrics code.
        if want_fabrics and json_c_dep.found() and 'log' in selected_plugins
            mock_cli_tests += [
                ['discovery-logs', 'nvme_discovery_logs_test.py',
                 cli_test_env, 30],
            ]
        endif

        if 'id' in selected_plugins and 'log' in selected_plugins and \
           'feat' in selected_plugins
            mock_cli_tests += [
                ['print', 'nvme_print_test.py', cli_test_env, 300],
            ]

            # The decoders print the same with and without the sandbox
            compare_env = cli_test_env
            compare_env.set('NVME_TEST_COMPARE_SANDBOX', '1')
            test('nvme-cli - print-sandbox-compare',
                 python3,
                 args: [files('nvme_print_test.py'), nvme_exe,
                        mock_nvme_lib],
                 env: compare_env,
                 depends: [nvme_exe, mock_nvme_lib],
                 timeout: 600,
                 suite: 'mock')
        endif

        if 'sed' in selected_plugins and want_sed and \
                conf.get('NVME_HAVE_SED_OPAL') != 0
            sed_ioctls = []
            foreach ioc : ['PSID_REVERT_TPR', 'REVERT_LSP', 'SET_SID_PW']
                if cc.has_header_symbol('linux/sed-opal.h', 'IOC_OPAL_' + ioc)
                    sed_ioctls += ioc
                endif
            endforeach
            sed_test_env = cli_test_env
            sed_test_env.set('NVME_SED_IOCTLS', ','.join(sed_ioctls))
            mock_cli_tests += [
                ['sed', 'nvme_sed_test.py', sed_test_env, 30],
            ]
        endif

        foreach t : mock_cli_tests
            test('nvme-cli - ' + t[0],
                 python3,
                 args: [files(t[1]), nvme_exe, mock_nvme_lib],
                 env: t[2],
                 depends: [nvme_exe, mock_nvme_lib],
                 timeout: t[3],
                 suite: 'mock')

            sandbox_env = t[2]
            sandbox_env.set('NVME_SANDBOX', '1')
            test('nvme-cli - ' + t[0] + '-sandbox',
                 python3,
                 args: [files(t[1]), nvme_exe, mock_nvme_lib],
                 env: sandbox_env,
                 depends: [nvme_exe, mock_nvme_lib],
                 timeout: t[3],
                 suite: 'mock')
        endforeach

        if want_privsep
            # it runs the commands of the id plugin
            if 'id' in selected_plugins
                test('nvme-cli - privsep',
                     python3,
                     args: [files('nvme_privsep_test.py'), nvme_exe,
                            mock_nvme_lib, privsep_helper],
                     env: cli_test_env,
                     depends: [nvme_exe, mock_nvme_lib, privsep_helper],
                     suite: 'mock')
            endif

            foreach t : mock_cli_tests
                privsep_env = t[2]
                privsep_env.set('NVME_PRIVSEP_TEST_HELPER',
                                privsep_helper.full_path())
                test('nvme-cli - ' + t[0] + '-privsep',
                     python3,
                     args: [files(t[1]), nvme_exe, mock_nvme_lib],
                     env: privsep_env,
                     depends: [nvme_exe, mock_nvme_lib, privsep_helper],
                     timeout: t[3],
                     suite: 'mock')
            endforeach
        endif
    endif

    if 'ocp' in selected_plugins
        subdir('ocp')
    endif

    if 'micron' in selected_plugins
        subdir('micron')
    endif

    if 'wdc' in selected_plugins
        subdir('wdc')
    endif

    if 'samsung' in selected_plugins
        subdir('samsung')
    endif

    if 'seagate' in selected_plugins
        subdir('seagate')
    endif
endif
