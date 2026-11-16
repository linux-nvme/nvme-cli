# SPDX-License-Identifier: GPL-2.0-or-later

fs = import('fs')

selected_plugins = get_option('plugins')
# The sandisk plugin runs the commands of the wdc one for older drives
if 'sandisk' in selected_plugins and 'wdc' not in selected_plugins
    selected_plugins += 'wdc'
endif

# Each plugin directory appends its sources to plugin_sources. It may set
# plugin_name, the name of the plugin on the command line, when it is not
# the name of the directory, and plugin_needs to the plugins whose
# functions it calls.
plugin_sources = []
enabled_plugins = []
plugin_defs = []
foreach plugin_dir : selected_plugins
  plugin_dir = plugin_dir.strip()
  if plugin_dir != ''
    n_sources_before = plugin_sources.length()
    plugin_name = plugin_dir
    plugin_needs = []
    subdir(plugin_dir)
    if plugin_sources.length() > n_sources_before
      enabled_plugins += plugin_dir
      srcs = []
      foreach i : range(n_sources_before, plugin_sources.length())
        srcs += plugin_sources[i]
      endforeach
      plugin_defs += {
        'dir': plugin_dir,
        'name': plugin_name,
        'sources': srcs,
        'needs': plugin_needs,
      }
    endif
  endif
endforeach

# The plugins other plugins need come first, they are linked to them
plugin_providers = []
foreach def : plugin_defs
  foreach need : def['needs']
    if need not in enabled_plugins
      error('the @0@ plugin needs the @1@ plugin'.format(def['dir'], need))
    endif
    if need not in plugin_providers
      plugin_providers += need
    endif
  endforeach
endforeach
ordered_plugin_defs = []
foreach def : plugin_defs
  if def['dir'] in plugin_providers
    ordered_plugin_defs += def
  endif
endforeach
foreach def : plugin_defs
  if def['dir'] not in plugin_providers
    ordered_plugin_defs += def
  endif
endforeach

plugin_deps = []
foreach d : [config_dep, ccan_dep, libnvme_dep, shared_dep, json_c_dep,
             libkmod_dep]
  plugin_deps += d.partial_dependency(compile_args: true, includes: true,
                                      sources: true)
endforeach

# Every plugin is a library of its own, linked into nvme as a whole
plugin_libs = []
foreach def : ordered_plugin_defs
  srcs = []
  foreach s : def['sources']
    srcs += meson.project_source_root() / s
  endforeach
  plugin_libs += static_library(
    'plugin-' + def['dir'],
    srcs,
    include_directories: include_directories('../src'),
    c_args: ['-DNVME_PLUGIN_NAME="@0@"'.format(def['name'])],
    dependencies: plugin_deps,
    install: false,
  )
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
