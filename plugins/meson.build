# SPDX-License-Identifier: GPL-2.0-or-later

# Get the list of plugins to build
selected_plugins = get_option('plugins')

# Build the plugin_sources list by pulling in each selected plugin's own
# meson.build, which handles any platform/feature conditions for itself.
plugin_sources = []
foreach plugin_name : selected_plugins
  plugin_name_stripped = plugin_name.strip()
  if plugin_name_stripped != ''
    subdir(plugin_name_stripped)
  endif
endforeach
