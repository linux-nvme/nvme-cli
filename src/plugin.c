// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/wrap-util.h>

#include "argconfig.h"
#include "args.h"
#include "cleanup.h"
#include "plugin.h"

static int version_cmd(struct plugin *plugin)
{
	struct program *prog = plugin->parent;

	if (plugin->name) {
		printf("%s %s version %s (git %s)\n",
			prog->name, plugin->name, plugin->version, GIT_VERSION);
	} else {
		printf("%s version %s (git %s)\n",
		       prog->name, prog->version, GIT_VERSION);
	}
	printf("libnvme version %s (git %s)\n",
		libnvme_get_version(LIBNVME_VERSION_PROJECT),
		libnvme_get_version(LIBNVME_VERSION_GIT));
	return 0;
}

static int help(int argc, char **argv, struct plugin *plugin)
{
	char man[0x100];
	struct program *prog = plugin->parent;
	char *str = argv[1];
	int i;

	if (argc == 1) {
		general_help(plugin, NULL);
		return 0;
	}

	for (i = 0; plugin->commands[i]; i++) {
		struct command *command = plugin->commands[i];

		if (strcmp(str, command->name))
			if (!command->alias ||
			    (command->alias && strcmp(str, command->alias)))
				continue;

		if (plugin->name)
			snprintf(man, sizeof(man), "%s-%s-%s", prog->name,
				plugin->name, command->name);
		else
			snprintf(man, sizeof(man), "%s-%s", prog->name, command->name);
		if (execlp("man", "man", man, (char *)NULL))
			perror(argv[1]);
	}

	general_help(plugin, str);

	return 0;
}

enum ext_filter {
	EXT_GROUP,	/* extension->group matches the given title */
	EXT_CORE_ONLY,	/* core, not shown next to a built-in group */
	EXT_VENDOR,	/* vendor (non-core) */
};

static bool extension_matches(struct plugin *extension, enum ext_filter filter,
			      const char *group_title)
{
	switch (filter) {
	case EXT_GROUP:
		return extension->group && !strcmp(extension->group, group_title);
	case EXT_CORE_ONLY:
		return extension->core && !extension->group;
	case EXT_VENDOR:
		return !extension->core;
	}
	return false;
}

static int plugin_name_cmp(const void *a, const void *b)
{
	struct plugin *const *pa = a;
	struct plugin *const *pb = b;

	return strcmp((*pa)->name, (*pb)->name);
}

/*
 * Collect extensions matching filter into a name-sorted, NULL-terminated
 * array so the plugin listings in general_help() print alphabetically
 * regardless of registration order. Caller must free() the result.
 */
static struct plugin **sorted_extensions(struct plugin *extensions, enum ext_filter filter,
					 const char *group_title)
{
	struct plugin *extension;
	struct plugin **list;
	size_t count = 0, i = 0;

	for (extension = extensions; extension; extension = extension->next)
		if (extension_matches(extension, filter, group_title))
			count++;

	list = malloc((count + 1) * sizeof(*list));
	if (!list)
		return NULL;

	for (extension = extensions; extension; extension = extension->next)
		if (extension_matches(extension, filter, group_title))
			list[i++] = extension;
	list[i] = NULL;

	qsort(list, count, sizeof(*list), plugin_name_cmp);

	return list;
}

static void usage_cmd(struct plugin *plugin)
{
	struct program *prog = plugin->parent;

	if (plugin->name)
		printf("usage: %s %s %s\n", prog->name, plugin->name, prog->usage);
	else
		printf("usage: %s %s\n", prog->name, prog->usage);
}

static void build_command_usage(char *use, size_t size, struct program *prog,
				struct plugin *plugin, struct command *cmd)
{
	const char *device = cmd->no_device ? "" : " <device>";

	if (!plugin->name)
		snprintf(use, size, "%s %s%s [OPTIONS]", prog->name, cmd->name, device);
	else
		snprintf(use, size, "%s %s %s%s [OPTIONS]", prog->name, plugin->name,
			cmd->name, device);
}

void plugin_add_group(struct plugin *plugin, const char *title,
		      struct command **commands)
{
	struct command_group *group, **tail;
	struct command **merged;
	size_t old_count = 0, new_count = 0;

	group = malloc(sizeof(*group));
	if (!group)
		return;
	group->title = title;
	group->commands = commands;
	group->next = NULL;

	for (tail = &plugin->groups; *tail; tail = &(*tail)->next)
		;
	*tail = group;

	if (plugin->commands)
		while (plugin->commands[old_count])
			old_count++;
	while (commands[new_count])
		new_count++;

	merged = realloc(plugin->commands, (old_count + new_count + 1) * sizeof(*merged));
	if (!merged)
		return;

	memcpy(&merged[old_count], commands, (new_count + 1) * sizeof(*merged));
	plugin->commands = merged;
}

static void print_device_desc(void)
{
	printf("'<device>' is one of:\n");
	printf("  - an NVMe controller device (ex: /dev/nvme0)\n");
	printf("  - an NVMe namespace device (ex: /dev/nvme0n1)\n");
#ifdef CONFIG_MI
	printf("  - a mctp address (ex: mctp:<net>,<eid>[:ctrl-id])\n");
#endif
}

void general_help(struct plugin *plugin, char *str)
{
	struct program *prog = plugin->parent;
	struct plugin *extension;
	unsigned int i = 0;
	unsigned int padding = 15;
	unsigned int curr_length = 0;
	bool have_deprecated = false;
	bool needs_device = false;

	for (i = 0; plugin->commands[i]; i++) {
		if (!plugin->commands[i]->no_device) {
			needs_device = true;
			break;
		}
	}

	printf("%s-%s\n", prog->name, prog->version);

	usage_cmd(plugin);

	if (prog->desc) {
		printf("\n");
		shr_print_word_wrapped(prog->desc, 0, 0, stdout);
		printf("\n");
	}

	if (needs_device) {
		printf("\n");
		print_device_desc();
	}

	if (plugin->desc) {
		printf("\n");
		shr_print_word_wrapped(plugin->desc, 0, 0, stdout);
		printf("\n");
	}

	printf("\nThe following are all implemented sub-commands:\n");
	if (str)
		printf("Note: Only sub-commands including %s\n", str);

	/*
	 * iterate through all commands to get maximum length
	 * Still need to handle the case of ultra long strings, help messages, etc
	 */
	for (i = 0; plugin->commands[i]; i++) {
		curr_length = 2 + strlen(plugin->commands[i]->name);
		if (padding < curr_length)
			padding = curr_length;
		if (plugin->commands[i]->deprecated)
			have_deprecated = true;
	}

	if (plugin->groups) {
		struct command_group *group;

		for (group = plugin->groups; group; group = group->next) {
			bool header_printed = false;

			for (i = 0; group->commands[i]; i++) {
				struct command *command = group->commands[i];

				if (command->deprecated)
					continue;
				if (str && !strstr(command->name, str))
					continue;
				if (!header_printed && group->title) {
					printf("\n\033[1m%s:\033[0m\n", group->title);
					header_printed = true;
				}
				printf("  %-*s %s\n", padding, command->name, command->help);
			}

			/*
			 * Core plugins tagged with .group are shown next to the
			 * built-in group they relate to instead of the flat
			 * "core NVMe/NVMeoF plugins" list further down.
			 */
			if (!plugin->name && group->title) {
				__cleanup_free struct plugin **sorted =
					sorted_extensions(prog->extensions->next, EXT_GROUP,
							  group->title);
				size_t j;

				for (j = 0; sorted && sorted[j]; j++) {
					extension = sorted[j];

					if (str && !strstr(extension->name, str))
						continue;
					if (!header_printed) {
						printf("\n\033[1m%s:\033[0m\n", group->title);
						header_printed = true;
					}
					printf("  %-*s %s\n", padding, extension->name,
					       extension->desc);
				}
			}
		}
	} else {
		/* Not yet migrated to plugin_add_group(): flat listing. */
		for (i = 0; plugin->commands[i]; i++) {
			if (plugin->commands[i]->deprecated)
				continue;
			if (!str || strstr(plugin->commands[i]->name, str))
				printf("  %-*s %s\n", padding, plugin->commands[i]->name,
				       plugin->commands[i]->help);
		}
	}

	printf("\n");
	if (!str || strstr("version", str))
		printf("  %-*s %s\n", padding, "version", "Shows the program version");
	if (!str || strstr("help", str))
		printf("  %-*s %s\n", padding, "help", "Display this help");
	printf("\n");

	if (plugin->name)
		printf("See '%s %s help <command>' for more information on a specific command\n",
			prog->name, plugin->name);
	else
		printf("See '%s help <command>' for more information on a specific command\n",
			prog->name);

	/*
	 * The first plugin is the built-in. If we're not showing help for the
	 * built-in, don't show the program's other extensions
	 */
	if (!plugin->name) {
		bool have_core = false, have_vendor = false;

		extension = prog->extensions->next;
		while (extension) {
			if (extension->core && !extension->group)
				have_core = true;
			else if (!extension->core)
				have_vendor = true;
			extension = extension->next;
		}

		if (have_core) {
			__cleanup_free struct plugin **sorted =
				sorted_extensions(prog->extensions->next, EXT_CORE_ONLY, NULL);
			size_t j;

			printf("\nThe following are core NVMe/NVMeoF plugins:\n");
			if (str)
				printf("Note: Only extensions including %s\n", str);

			for (j = 0; sorted && sorted[j]; j++) {
				if (!str || strstr(sorted[j]->name, str))
					printf("  %-*s %s\n", 15, sorted[j]->name, sorted[j]->desc);
			}
		}

		if (have_vendor) {
			__cleanup_free struct plugin **sorted =
				sorted_extensions(prog->extensions->next, EXT_VENDOR, NULL);
			size_t j;

			printf("\nThe following are vendor specific plugins:\n");
			if (str)
				printf("Note: Only extensions including %s\n", str);

			for (j = 0; sorted && sorted[j]; j++) {
				if (!str || strstr(sorted[j]->name, str))
					printf("  %-*s %s\n", 15, sorted[j]->name, sorted[j]->desc);
			}
		}

		if (have_core || have_vendor)
			printf("\nSee '%s <plugin> help' for more information on a plugin\n",
					prog->name);
	}

	if (have_deprecated) {
		printf("\nThe following sub-commands are deprecated and will be removed in the next major version:\n");
		if (str)
			printf("Note: Only sub-commands including %s\n", str);

		i = 0;
		for (; plugin->commands[i]; i++) {
			if (!plugin->commands[i]->deprecated)
				continue;
			if (!str || strstr(plugin->commands[i]->name, str))
				printf("  %-*s %s\n", padding, plugin->commands[i]->name,
				       plugin->commands[i]->help);
		}
	}
}

int handle_plugin(int argc, char **argv, struct plugin *plugin)
{
	char use[0x100];
	struct plugin *extension;
	struct program *prog = plugin->parent;
	struct command **cmd = plugin->commands;
	struct command *cr = NULL;
	bool opt_help = false, opt_version = false;
	bool cr_valid = false;
	char *str;
	int err;

	if (!argc) {
		general_help(plugin, NULL);
		return 0;
	}

	/*
	 * look for global options before the sub command parser and
	 * pre-fill the global nvme_args variable.
	 */
	NVME_ARGS(global_opts,
		OPT_FLAG("help",     'h', &opt_help,     "show help text"),
		OPT_FLAG("version",  'V', &opt_version,  "show version"));
	err = argconfig_parse_global(argc, argv, global_opts);
	if (err) {
		general_help(plugin, NULL);
		return err;
	}

	argc -= optind;
	argv += optind;

	if (opt_help) {
		__cleanup_free char **help_argv = NULL;
		__cleanup_free char *help_name = NULL;

		if (argc <= 0) {
			general_help(plugin, NULL);
			return 0;
		}

		help_argv = malloc((argc + 1) * sizeof(*help_argv));
		if (!help_argv)
			return -ENOMEM;

		help_name = strdup("help");
		if (!help_name)
			return -ENOMEM;

		help_argv[0] = help_name;
		memcpy(&help_argv[1], argv, argc * sizeof(*argv));
		return help(argc + 1, help_argv, plugin);
	}

	if (opt_version)
		return version_cmd(plugin);

	if (!argc) {
		general_help(plugin, NULL);
		return 0;
	}

	str = argv[0];

	if (!strcmp(str, "help"))
		return help(argc, argv, plugin);
	if (!strcmp(str, "version"))
		return version_cmd(plugin);

	while (*cmd) {
		if (!strcmp(str, (*cmd)->name) ||
		    ((*cmd)->alias && !strcmp(str, (*cmd)->alias))) {
			build_command_usage(use, sizeof(use), prog, plugin, *cmd);
			argconfig_append_usage(use);
			return (*cmd)->fn(argc, argv, *cmd, plugin);
		}
		if (!strncmp(str, (*cmd)->name, strlen(str))) {
			if (cr) {
				cr_valid = false;
			} else {
				cr = *cmd;
				cr_valid = true;
			}
		}
		cmd++;
	}

	if (cr && cr_valid) {
		build_command_usage(use, sizeof(use), prog, plugin, cr);
		argconfig_append_usage(use);
		return cr->fn(argc, argv, cr, plugin);
	}

	/* Check extensions only if this is running the built-in plugin */
	if (plugin->name) {
		fprintf(stderr, "ERROR: Invalid sub-command '%s' for plugin %s\n", str, plugin->name);
		return -ENOTTY;
	}

	extension = plugin->next;
	while (extension) {
		if (!strcmp(str, extension->name))
			return handle_plugin(argc, argv, extension);
		extension = extension->next;
	}

	/*
	 * If the command is executed with the extension name and
	 * command together ("plugin-command"), run the plug in
	 */
	extension = plugin->next;
	while (extension) {
		if (!strncmp(str, extension->name, strlen(extension->name))) {
			__cleanup_free char **sub_argv = NULL;
			__cleanup_free char *name_copy = NULL;

			sub_argv = malloc((argc + 1) * sizeof(*sub_argv));
			if (!sub_argv)
				return -ENOMEM;

			argv[0] += strlen(extension->name);
			while (*argv[0] == '-')
				argv[0]++;

			name_copy = strdup(extension->name);
			if (!name_copy)
				return -ENOMEM;

			sub_argv[0] = name_copy;
			memcpy(&sub_argv[1], argv, argc * sizeof(*argv));

			return handle_plugin(argc + 1, sub_argv, extension);
		}
		extension = extension->next;
	}
	fprintf(stderr, "ERROR: Invalid sub-command '%s'\n", str);
	return -ENOTTY;
}
