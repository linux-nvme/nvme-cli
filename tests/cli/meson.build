# SPDX-License-Identifier: GPL-2.0-or-later
#
# CLI-driven tests: they exercise the built nvme binary but need no NVMe
# hardware. Hardware/device tests live in ../e2e/; C and Python unit tests
# live in ../unit/.

cli_test_env = environment()
cli_test_env.prepend('PYTHONPATH', meson.project_source_root())

if python3.found()
    # Standalone CLI test for the ownership registry.  It needs no device
    # (it uses NVME_REGISTRY_DIR).
    if want_fabrics and 'registry' in selected_plugins
        test('nvme-cli - registry-cli',
             python3,
             args: [files('nvme_registry_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif

    # Standalone CLI test for the "keys" plugin. Needs no device. Restricted
    # to the commands that need no keyring access (the test's docstring
    # lists them), so it only needs OpenSSL, not a working kernel keyring.
    if want_fabrics and 'keys' in selected_plugins and openssl_dep.found()
        test('nvme-cli - keys-cli',
             python3,
             args: [files('nvme_keys_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif

    # Standalone CLI test for "nvme config-convert". Needs no device; uses
    # an explicit --config/--output pair under /tmp instead. Requires
    # json-c since the legacy config.json reader is a no-op without it.
    if want_fabrics and json_c_dep.found()
        test('nvme-cli - config-convert-cli',
             python3,
             args: [files('nvme_config_convert_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif

    # Standalone CLI test for "nvme config-create". Needs no device; uses an
    # explicit --output under /tmp instead. "config create" lives in the
    # "config" plugin, so it needs that plugin selected too.
    if want_fabrics and 'config' in selected_plugins
        test('nvme-cli - config-create-cli',
             python3,
             args: [files('nvme_config_create_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
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
             depends: nvme_exe)
    endif

    if (not is_static) and (not is_cross) and (host_system == 'linux')
        mock_nvme_lib = shared_library(
            'mock_nvme',
            'libmock_nvme.c',
            include_directories: '../..',
            dependencies: dl_dep,
            install: false
        )
        # cli_test_env.prepend('MOCK_DEBUG', '1')

        if want_fabrics
            test('nvme-cli - fabrics-mock-cli',
                 python3,
                 args: [files('nvme_fabrics_mock_test.py'), nvme_exe, mock_nvme_lib],
                 env: cli_test_env,
                 depends: [nvme_exe, mock_nvme_lib])
        endif

        test('nvme-cli - pif-sts-cli',
             python3,
             args: [files('nvme_pif_sts_test.py'), nvme_exe, mock_nvme_lib],
             env: cli_test_env,
             depends: [nvme_exe, mock_nvme_lib])

        test('nvme-cli - init-pi-tags-cli',
             python3,
             args: [files('nvme_init_pi_tags_test.py'), nvme_exe, mock_nvme_lib],
             env: cli_test_env,
             depends: [nvme_exe, mock_nvme_lib])

        if 'samsung' in selected_plugins
            test('nvme-cli - samsung-cli',
                 python3,
                 args: [files('nvme_samsung_test.py'), nvme_exe, mock_nvme_lib],
                 env: cli_test_env,
                 depends: [nvme_exe, mock_nvme_lib])
        endif
    endif
endif
