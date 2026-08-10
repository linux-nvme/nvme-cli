# SPDX-License-Identifier: GPL-2.0-or-later
#
# CLI-driven tests: they exercise the built nvme binary but need no NVMe
# hardware. Hardware/device tests live in ../e2e/; C and Python unit tests
# live in ../unit/.

cli_test_env = environment()
cli_test_env.prepend('PYTHONPATH', meson.project_source_root())

# Standalone CLI test for the ownership registry.  It needs no device (it
# uses NVME_REGISTRY_DIR).
if want_fabrics and 'registry' in selected_plugins
    _py3 = find_program('python3', required: false)
    if _py3.found()
        test('nvme-cli - registry-cli',
             _py3,
             args: [files('nvme_registry_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif
endif

# Standalone CLI test for the "keys" plugin. Needs no device. Restricted to
# gen-dhchap/gen-tls/check-dhchap/check-tls (no keyring access), so it only
# needs OpenSSL, not a working kernel keyring.
if want_fabrics and 'keys' in selected_plugins and openssl_dep.found()
    _py3 = find_program('python3', required: false)
    if _py3.found()
        test('nvme-cli - keys-cli',
             _py3,
             args: [files('nvme_keys_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif
endif

# Standalone CLI test for "nvme config-convert". Needs no device; uses an
# explicit --config/--output pair under /tmp instead. Requires json-c since
# the legacy config.json reader is a no-op without it.
if want_fabrics and json_c_dep.found()
    _py3 = find_program('python3', required: false)
    if _py3.found()
        test('nvme-cli - config-convert-cli',
             _py3,
             args: [files('nvme_config_convert_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif
endif

# Standalone CLI test for "nvme config-create". Needs no device; uses an
# explicit --output under /tmp instead.
if want_fabrics
    _py3 = find_program('python3', required: false)
    if _py3.found()
        test('nvme-cli - config-create-cli',
             _py3,
             args: [files('nvme_config_create_test.py'), nvme_exe],
             env: cli_test_env,
             depends: nvme_exe)
    endif
endif

if want_fabrics
    _py3 = find_program('python3', required: false)
    if _py3.found()
        test('nvme-cli - nbft-interface-references',
             _py3,
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
endif
