/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#if NVME_PLUGIN_MODULES
/* The directory of the plugin modules */
const char *nvme_plugin_dir(void);
/* Load the module of the plugin @name, if there is one */
void nvme_load_plugin(const char *name);
/* Load all modules */
void nvme_load_plugins(void);
/* Whether @name is a plugin of this build, as a module */
bool nvme_plugin_known(const char *name);
#else
static inline const char *nvme_plugin_dir(void) { return "nvme"; }
static inline void nvme_load_plugin(const char *name) { (void)name; }
static inline void nvme_load_plugins(void) {}
static inline bool nvme_plugin_known(const char *name)
{
	(void)name;
	return false;
}
#endif
