# SPDX-License-Identifier: GPL-2.0-or-later
#
# Plugin test suites — each is gated by the plugin being present in both the
# plugin-tests array option and in selected_plugins.
#
# known_plugin_tests must be kept in sync with the 'plugin-tests' choices in
# meson_options.txt -- meson option() choices are a static literal list, so
# there's no way to derive either list from the other or from the
# tests/e2e/plugins/ directory layout at configure time.

known_plugin_tests = ['micron', 'ocp']

plugin_tests = get_option('plugin-tests')

foreach name : known_plugin_tests
    if name in plugin_tests and name in selected_plugins
        subdir(name)
    endif
endforeach
