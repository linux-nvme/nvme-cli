# SPDX-License-Identifier: GPL-2.0-or-later
#
# Plugin test suites — each is gated by the plugin being present in both the
# plugin-tests array option and in selected_plugins.

plugin_tests = get_option('plugin-tests')

if 'micron' in plugin_tests and 'micron' in selected_plugins
    subdir('micron')
endif

if 'ocp' in plugin_tests and 'ocp' in selected_plugins
    subdir('ocp')
endif
