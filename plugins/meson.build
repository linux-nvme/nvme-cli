# SPDX-License-Identifier: GPL-2.0-or-later

fs = import('fs')

selected_plugins = get_option('plugins')

plugin_sources = []
enabled_plugins = []
foreach plugin_name : selected_plugins
  plugin_name_stripped = plugin_name.strip()
  if plugin_name_stripped != ''
    n_sources_before = plugin_sources.length()
    subdir(plugin_name_stripped)
    if plugin_sources.length() > n_sources_before
      enabled_plugins += plugin_name_stripped
    endif
  endif
endforeach

# Pull the full list of valid plugin names straight out of the 'plugins'
# option's choices in meson_options.txt, so that file stays the single
# source of truth instead of duplicating the list here.
options_txt = fs.read(meson.project_source_root() / 'meson_options.txt')
plugins_choices_txt = options_txt.split('\'plugins\'')[1].split('[')[1].split(']')[0]
all_plugin_names = []
foreach entry : plugins_choices_txt.split(',')
  name = entry.strip().strip('\'')
  if name != ''
    all_plugin_names += name
  endif
endforeach

core_plugins = []
vendor_plugins = []
disabled_plugins = []
foreach plugin_name : all_plugin_names
  if plugin_name in enabled_plugins
    is_core = false
    foreach src : plugin_sources
      if src.startswith('plugins/' + plugin_name + '/') and fs.read(meson.project_source_root() / src).contains('.core = true')
        is_core = true
      endif
    endforeach
    if is_core
      core_plugins += plugin_name
    else
      vendor_plugins += plugin_name
    endif
  else
    disabled_plugins += plugin_name
  endif
endforeach
