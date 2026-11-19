# SPDX-License-Identifier: GPL-2.0-or-later

fs = import('fs')

selected_plugins = get_option('plugins')

# A plugin lives in plugins/<plugin>, or in plugins/cmds-<plugin> for the
# plugins of nvme itself. Its directory appends its sources to
# plugin_sources. It may set plugin_name, the name of the plugin on the
# command line, when it is not the name of the directory, and plugin_needs
# to the plugins whose functions it calls. Plugins needed by a selected
# plugin are selected as well: each round visits the plugins needed by the
# previous round.
plugin_sources = []
enabled_plugins = []
plugin_defs = []
visited_plugins = []
pending_plugins = selected_plugins
foreach round : range(16)
  if pending_plugins.length() == 0
    break
  endif
  needed_plugins = []
  foreach plugin_dir : pending_plugins
    plugin_dir = plugin_dir.strip()
    if plugin_dir == '' or plugin_dir in visited_plugins
      continue
    endif
    visited_plugins += plugin_dir
    plugin_subdir = plugin_dir
    if fs.is_dir(meson.current_source_dir() / ('cmds-' + plugin_dir))
      plugin_subdir = 'cmds-' + plugin_dir
    endif
    n_sources_before = plugin_sources.length()
    plugin_name = plugin_subdir
    plugin_needs = []
    subdir(plugin_subdir)
    if plugin_sources.length() > n_sources_before
      enabled_plugins += plugin_dir
      srcs = []
      foreach i : range(n_sources_before, plugin_sources.length())
        srcs += plugin_sources[i]
      endforeach
      plugin_defs += {
        'dir': plugin_dir,
        'subdir': plugin_subdir,
        'name': plugin_name,
        'sources': srcs,
        'needs': plugin_needs,
      }
      foreach need : plugin_needs
        if need not in visited_plugins and need not in needed_plugins
          needed_plugins += need
        endif
      endforeach
    endif
  endforeach
  pending_plugins = needed_plugins
endforeach
if pending_plugins.length() > 0
  error('plugin_needs nest too deep: @0@'.format(pending_plugins))
endif
# Treat the implicitly selected plugins as selected
foreach plugin_dir : visited_plugins
  if plugin_dir not in selected_plugins
    selected_plugins += plugin_dir
  endif
endforeach

# Build the providers first, each after the providers it needs, as they
# are linked to it. The other plugins follow in their original order.
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
ordered_providers = []
foreach round : range(plugin_providers.length())
  foreach def : plugin_defs
    if def['dir'] in plugin_providers and def['dir'] not in ordered_providers
      ready = true
      foreach need : def['needs']
        if need not in ordered_providers
          ready = false
        endif
      endforeach
      if ready
        ordered_plugin_defs += def
        ordered_providers += def['dir']
      endif
    endif
  endforeach
endforeach
if ordered_providers.length() != plugin_providers.length()
  error('the plugins need each other: @0@'.format(plugin_providers))
endif
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

# Every plugin is a library of its own: a module nvme loads when the
# plugin is used, or linked into nvme as a whole. Modules take the symbols
# of nvme from the program, which exports them. The plugins other plugins
# need are shared libraries, as modules cannot be linked to.
plugin_libs = []
plugin_targets = {}
plugin_module_targets = []
if want_plugin_modules
  # Marks the module directory of the build tree, see plugin-loader.c
  configure_file(
    output: 'nvme-plugin-dir',
    configuration: {'NVME_PLUGIN_ABI': '"' + conf.get_unquoted('NVME_PLUGIN_ABI') + '"'},
  )

  # The plugins of this build and their modules, which are named after
  # the directory of the plugin. A missing module is "not installed".
  plugin_names = []
  foreach def : plugin_defs
    plugin_names += '{ "@0@", "@1@" }'.format(def['name'], def['subdir'])
  endforeach
  configure_file(
    output: 'plugin-names.h',
    configuration: {'NVME_PLUGIN_NAMES': ', '.join(plugin_names)},
  )
endif
plugin_names_inc = include_directories('.')
foreach def : ordered_plugin_defs
  srcs = []
  foreach s : def['sources']
    srcs += meson.project_source_root() / s
  endforeach
  c_args = ['-DNVME_PLUGIN_NAME="@0@"'.format(def['name'])]
  if not want_plugin_modules
    plugin_libs += static_library(
      'plugin-' + def['dir'],
      srcs,
      include_directories: include_directories('../src'),
      c_args: c_args,
      dependencies: plugin_deps,
      install: false,
    )
    continue
  endif

  link_with = []
  foreach need : def['needs']
    link_with += plugin_targets[need]
  endforeach
  module_kwargs = {
    'name_prefix': '',
    'name_suffix': 'so',
    'include_directories': include_directories('../src'),
    'c_args': c_args + [
      '-DNVME_PLUGIN_MODULE',
      '-DNVME_PLUGIN_ID=' + def['subdir'].replace('-', '_'),
    ],
    'dependencies': plugin_deps,
    'link_with': link_with,
    'override_options': ['b_lundef=false'],
    'build_rpath': '$ORIGIN',
    'install_rpath': '$ORIGIN',
    'install': true,
    'install_dir': plugin_module_dir,
  }
  if def['dir'] in plugin_providers
    target = shared_library(def['subdir'], srcs, kwargs: module_kwargs)
  else
    target = shared_module(def['subdir'], srcs, kwargs: module_kwargs)
  endif
  plugin_targets += {def['dir']: target}
  plugin_module_targets += target
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
plugin_subdirs = {}
foreach def : plugin_defs
  plugin_subdirs += {def['dir']: def['subdir']}
endforeach
foreach plugin_name : all_plugin_names
  if plugin_name in enabled_plugins
    is_core = false
    plugin_subdir = plugin_subdirs.get(plugin_name, plugin_name)
    foreach src : plugin_sources
      if src.startswith('plugins/' + plugin_subdir + '/') and fs.read(meson.project_source_root() / src).contains('.core = true')
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
