// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The plugin modules. nvme loads a module when its plugin is used: by its
 * name on the command line, or all of them for the lists of commands. A
 * module is named after the directory of its plugin, which may differ from
 * the name of the plugin, e.g. cmds-id.so for "nvme id".
 *
 * The module <module>.so exports nvme_plugin_<id>_abi, the interface it was
 * built for, and nvme_plugin_<id>_init(), which registers its plugin, with
 * <id> the module name with '_' for '-'. The loader calls it only when the
 * interface is the one of this nvme.
 */
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/auxv.h>

#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>

#include "command-index.h"
#include "plugin-loader.h"
#include "plugin-names.h"

#define MODULE_SUFFIX ".so"
/* The file in the build tree's module directory, see plugins/meson.build */
#define BUILD_TREE_MARKER "nvme-plugin-dir"

static void **modules;
static size_t nr_modules;
static bool all_loaded;

/* Set-user-ID and file capabilities: only the installed modules */
static bool secure_exec(void)
{
#ifdef __linux__
	return getauxval(AT_SECURE);
#else
	return issetugid();
#endif
}

static int exe_path(char *buf, size_t size)
{
#if defined(__linux__)
	ssize_t len = readlink("/proc/self/exe", buf, size - 1);

	if (len < 0)
		return -errno;
	buf[len] = '\0';
	return 0;
#elif defined(__FreeBSD__)
	return -elf_aux_info(AT_EXECPATH, buf, size);
#else
	return -ENOTSUP;
#endif
}

/*
 * The modules of a build tree are in plugins/ next to the program, with a
 * marker file. Run from there, nvme takes them.
 */
static bool build_tree_dir(char *buf, size_t size)
{
	char marker[PATH_MAX];
	char *slash;

	if (exe_path(buf, size))
		return false;
	slash = strrchr(buf, '/');
	if (!slash)
		return false;
	*slash = '\0';
	if (strlen(buf) + strlen("/plugins") >= size)
		return false;
	strcat(buf, "/plugins");

	snprintf(marker, sizeof(marker), "%s/" BUILD_TREE_MARKER, buf);
	return !access(marker, F_OK);
}

const char *nvme_plugin_dir(void)
{
	static char buf[PATH_MAX];
	static const char *dir;
	const char *env;

	if (dir)
		return dir;

	dir = NVME_PLUGIN_DIR;
	if (secure_exec())
		return dir;

	env = getenv("NVME_PLUGIN_DIR");
	if (env && *env)
		dir = env;
	else if (build_tree_dir(buf, sizeof(buf)))
		dir = buf;

	return dir;
}

static bool is_loaded(void *handle)
{
	size_t i;

	for (i = 0; i < nr_modules; i++) {
		if (modules[i] == handle)
			return true;
	}
	return false;
}

/* The symbol @sym of the module @name, see NVME_PLUGIN_INIT() */
static void *module_sym(void *handle, const char *name, const char *sym)
{
	char buf[NAME_MAX + 32];
	char *c;

	snprintf(buf, sizeof(buf), "nvme_plugin_%s_%s", name, sym);
	for (c = buf; *c; c++) {
		if (*c == '-')
			*c = '_';
	}
	return dlsym(handle, buf);
}

static void load_module(const char *dir, const char *name)
{
	char path[PATH_MAX];
	void (*init)(void);
	const char *abi;
	void **tmp;
	void *handle;
	int len;

	len = snprintf(path, sizeof(path), "%s/%s" MODULE_SUFFIX, dir, name);
	if (len < 0 || (size_t)len >= sizeof(path))
		return;

	handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		fprintf(stderr, "cannot load plugin %s\n", dlerror());
		return;
	}
	/* dlopen() counts, the module is initialized once */
	if (is_loaded(handle)) {
		dlclose(handle);
		return;
	}

	abi = module_sym(handle, name, "abi");
	init = (void (*)(void))module_sym(handle, name, "init");
	if (!abi || !init) {
		fprintf(stderr, "ignoring %s: not a plugin of nvme\n", path);
		dlclose(handle);
		return;
	}
	if (!streq(abi, NVME_PLUGIN_ABI)) {
		fprintf(stderr,
			"ignoring %s: built for nvme %s, this is nvme %s\n",
			path, abi, NVME_PLUGIN_ABI);
		dlclose(handle);
		return;
	}

	tmp = realloc(modules, (nr_modules + 1) * sizeof(*modules));
	if (!tmp) {
		dlclose(handle);
		return;
	}
	modules = tmp;
	/* never closed, the plugin lives as long as the program */
	modules[nr_modules++] = handle;
	init();
}

/* A plugin or module name, not a path */
static bool valid_name(const char *name)
{
	size_t len = strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-_");

	return len && len <= NAME_MAX - strlen(MODULE_SUFFIX) && !name[len];
}

/* The plugins of this build and their modules */
static const struct {
	const char *name;
	const char *module;
} plugins[] = { NVME_PLUGIN_NAMES };

/* The module of the plugin @name, or @name for a module name */
static const char *plugin_module(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(plugins); i++) {
		if (streq(name, plugins[i].name))
			return plugins[i].module;
	}
	return name;
}

void nvme_load_plugin(const char *name)
{
	const char *module = plugin_module(name);
	char path[PATH_MAX];
	int len;

	if (all_loaded || !valid_name(module))
		return;

	len = snprintf(path, sizeof(path), "%s/%s" MODULE_SUFFIX,
		       nvme_plugin_dir(), module);
	if (len < 0 || (size_t)len >= sizeof(path) || access(path, F_OK))
		return;

	load_module(nvme_plugin_dir(), module);
}

bool nvme_plugin_known(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(plugins); i++) {
		if (streq(name, plugins[i].name))
			return true;
	}
	return false;
}

const struct nvme_command_entry *nvme_command_index(void)
{
	static const struct nvme_command_entry index[] = {
		NVME_COMMAND_INDEX
	};

	return index;
}

static int is_module(const struct dirent *entry)
{
	size_t len = strlen(entry->d_name);
	size_t suffix = strlen(MODULE_SUFFIX);

	return len > suffix &&
	       streq(entry->d_name + len - suffix, MODULE_SUFFIX);
}

/* The name of the plugin of the module file @file, or the module name */
static const char *file_plugin(const char *file, char *buf, size_t size)
{
	size_t i;

	snprintf(buf, size, "%.*s", (int)(strlen(file) - strlen(MODULE_SUFFIX)),
		 file);
	for (i = 0; i < ARRAY_SIZE(plugins); i++) {
		if (streq(buf, plugins[i].module))
			return plugins[i].name;
	}
	return buf;
}

/* Load the modules in the order of their plugin names, not file names */
static int by_plugin(const struct dirent **a, const struct dirent **b)
{
	char buf_a[NAME_MAX + 1], buf_b[NAME_MAX + 1];

	return strcmp(file_plugin((*a)->d_name, buf_a, sizeof(buf_a)),
		      file_plugin((*b)->d_name, buf_b, sizeof(buf_b)));
}

void nvme_load_plugins(void)
{
	struct dirent **entries;
	const char *dir;
	int n, i;

	if (all_loaded)
		return;
	all_loaded = true;

	dir = nvme_plugin_dir();
	n = scandir(dir, &entries, is_module, by_plugin);
	if (n < 0)
		return;

	for (i = 0; i < n; i++) {
		char *name = entries[i]->d_name;

		/* the module name: the file name without the suffix */
		name[strlen(name) - strlen(MODULE_SUFFIX)] = '\0';
		if (valid_name(name))
			load_module(dir, name);
		free(entries[i]);
	}
	free(entries);
}
