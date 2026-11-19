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

# The tests of a plugin of nvme itself live in cmds_<plugin>, see
# plugins/meson.build. Python can't import a package with a '-'.
fs = import('fs')
foreach name : known_plugin_tests
    if name in plugin_tests and name in selected_plugins
        if fs.is_dir(meson.current_source_dir() / ('cmds_' + name))
            subdir('cmds_' + name)
        else
            subdir(name)
        endif
    endif
endforeach
