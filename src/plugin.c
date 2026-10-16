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

/*
 * The command @name selects: an exact name or alias, otherwise the only
 * command whose name starts with @name.
 */
static struct command *find_command(struct plugin *plugin, const char *name)
{
	struct command **cmd, *match = NULL;
	size_t len = strlen(name);
	bool unique = false;

	for (cmd = plugin->commands; *cmd; cmd++) {
		if (!strcmp(name, (*cmd)->name) ||
		    ((*cmd)->alias && !strcmp(name, (*cmd)->alias)))
			return *cmd;
	}

	for (cmd = plugin->commands; *cmd; cmd++) {
		if (strncmp(name, (*cmd)->name, len))
			continue;
		unique = !match;
		match = *cmd;
	}

	return unique ? match : NULL;
}

static struct plugin *find_extension(struct plugin *plugin, const char *name)
{
	struct plugin *extension;

	for (extension = plugin->next; extension; extension = extension->next) {
		if (!strcmp(name, extension->name))
			return extension;
	}

	return NULL;
}

/*
 * "nvme help <command>" shows the man page of the command "nvme <command>"
 * would run, also for "nvme help <plugin> <command>".
 */
static int help(int argc, char **argv, struct plugin *plugin)
{
	char man[0x100];
	struct program *prog = plugin->parent;
	struct plugin *extension;
	struct command *cmd;

	if (argc == 1) {
		general_help(plugin, NULL);
		return 0;
	}

	cmd = find_command(plugin, argv[1]);
	if (cmd) {
		if (plugin->name)
			snprintf(man, sizeof(man), "%s-%s-%s", prog->name,
				 plugin->name, cmd->name);
		else
			snprintf(man, sizeof(man), "%s-%s", prog->name,
				 cmd->name);
		if (execlp("man", "man", man, (char *)NULL))
			perror(argv[1]);
	} else if (!plugin->name) {
		extension = find_extension(plugin, argv[1]);
		if (extension)
			return help(argc - 1, argv + 1, extension);
	}

	general_help(plugin, argv[1]);

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
	static const char * const device[] = {
		[COMMAND_DEVICE] = " <device>",
		[COMMAND_DEVICE_OPTIONAL] = " [<device>]",
		[COMMAND_NO_DEVICE] = "",
	};

	if (!plugin->name)
		snprintf(use, size, "%s %s%s [OPTIONS]", prog->name, cmd->name,
			 device[cmd->device]);
	else
		snprintf(use, size, "%s %s %s%s [OPTIONS]", prog->name,
			 plugin->name, cmd->name, device[cmd->device]);
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

/* The title of a command group, in bold on a terminal */
static void print_group_title(const char *title)
{
	putchar('\n');
	argconfig_print_heading(stdout, "%s:", title);
	putchar('\n');
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
		if (plugin->commands[i]->device != COMMAND_NO_DEVICE) {
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
					print_group_title(group->title);
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
						print_group_title(group->title);
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

/* Apply the output formats and the operand of a command before it runs */
void command_prepare(struct command *cmd)
{
	nvme_args_set_output_formats(cmd->output_formats ?
				     cmd->output_formats :
				     DEFAULT_OUTPUT_FORMATS,
				     cmd->output_format_desc);
	nvme_args.device_operand = cmd->device;
}

static int run_command(int argc, char **argv, struct plugin *plugin,
		       struct command *cmd)
{
	char use[0x100], path[0x80];
	int err;

	build_command_usage(use, sizeof(use), plugin->parent, plugin, cmd);
	if (plugin->name)
		snprintf(path, sizeof(path), "%s %s", plugin->name, cmd->name);
	else
		snprintf(path, sizeof(path), "%s", cmd->name);
	argconfig_append_usage(use);
	argconfig_set_command(plugin->parent->name, path);
	command_prepare(cmd);

	err = cmd->fn(argc, argv, cmd, plugin);

	/* use and path go out of scope */
	argconfig_append_usage("");
	argconfig_set_command(NULL, NULL);

	return err;
}

/*
 * "nvme <plugin>-<command>": argv[0] starts with the name of an extension.
 * Run the rest as a command of that extension.
 */
static int run_joined_command(int argc, char **argv, struct plugin *plugin)
{
	__cleanup_free char **sub_argv = NULL;
	__cleanup_free char *name = NULL;
	struct plugin *extension;

	for (extension = plugin->next; extension; extension = extension->next) {
		if (!strncmp(argv[0], extension->name, strlen(extension->name)))
			break;
	}
	if (!extension) {
		fprintf(stderr, "ERROR: Invalid sub-command '%s'\n", argv[0]);
		return -ENOTTY;
	}

	sub_argv = malloc((argc + 1) * sizeof(*sub_argv));
	name = strdup(extension->name);
	if (!sub_argv || !name)
		return -ENOMEM;

	argv[0] += strlen(extension->name);
	while (*argv[0] == '-')
		argv[0]++;

	sub_argv[0] = name;
	memcpy(&sub_argv[1], argv, argc * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, extension);
}

/*
 * Warn that @cmd of @plugin is deprecated and run "nvme <extension>
 * @command" with the arguments after argv[0] instead, the extension of
 * @cmd's replacement.
 */
int run_replacement_command(struct plugin *plugin, struct command *cmd,
			    const char *command, int argc, char **argv)
{
	const char *name = cmd->replacement.plugin;
	__cleanup_free char **sub_argv = NULL;
	struct plugin *extension;

	extension = find_extension(plugin, name);
	if (!extension) {
		fprintf(stderr,
			"ERROR: '%s' is deprecated and requires the '%s' plugin, which is not available in this build; use 'nvme %s %s'\n",
			cmd->name, name, name, command);
		return -ENOTTY;
	}

	argconfig_print_warning();
	fprintf(stderr,
		" '%s' is deprecated and will be removed in the next major version, use 'nvme %s %s' instead\n",
		cmd->name, name, command);

	/*
	 * handle_plugin() skips argv[0] like a program name and dispatches
	 * on argv[1], so the arguments move one slot to the right.
	 */
	sub_argv = calloc(argc + 2, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)extension->name;
	sub_argv[1] = (char *)command;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, extension);
}

/* The function of a deprecated command which only forwards */
int run_replacement(int argc, char **argv, struct command *cmd,
		    struct plugin *plugin)
{
	return run_replacement_command(plugin, cmd, cmd->replacement.command,
				       argc, argv);
}

/* "nvme --help <command>" is "nvme help <command>" */
static int run_help(int argc, char **argv, struct plugin *plugin)
{
	__cleanup_free char **help_argv = NULL;
	__cleanup_free char *help_name = NULL;

	if (argc <= 0) {
		general_help(plugin, NULL);
		return 0;
	}

	help_argv = malloc((argc + 1) * sizeof(*help_argv));
	help_name = strdup("help");
	if (!help_argv || !help_name)
		return -ENOMEM;

	help_argv[0] = help_name;
	memcpy(&help_argv[1], argv, argc * sizeof(*argv));

	return help(argc + 1, help_argv, plugin);
}

/*
 * argv[0] is the program or plugin name. The global options come first,
 * then the command of @plugin, or an extension and its command.
 */
int handle_plugin(int argc, char **argv, struct plugin *plugin)
{
	struct plugin *extension;
	struct command *cmd;
	int err, argind;

	if (!argc) {
		general_help(plugin, NULL);
		return 0;
	}

	/*
	 * -h and --help show the help of the command which follows, if any,
	 * -V and --version replace the command.
	 */
	err = argconfig_parse_global(argc, argv, NULL, &argind);
	if (err < 0) {
		general_help(plugin, NULL);
		return err;
	}

	argc -= argind;
	argv += argind;

	if (err & ARGCONFIG_HELP)
		return run_help(argc, argv, plugin);
	if (err & ARGCONFIG_VERSION)
		return version_cmd(plugin);

	if (!argc) {
		general_help(plugin, NULL);
		return 0;
	}

	if (!strcmp(argv[0], "help"))
		return help(argc, argv, plugin);
	if (!strcmp(argv[0], "version"))
		return version_cmd(plugin);

	cmd = find_command(plugin, argv[0]);
	if (cmd)
		return run_command(argc, argv, plugin, cmd);

	/* Only the built-in plugin has extensions */
	if (plugin->name) {
		fprintf(stderr,
			"ERROR: Invalid sub-command '%s' for plugin %s\n",
			argv[0], plugin->name);
		return -ENOTTY;
	}

	extension = find_extension(plugin, argv[0]);
	if (extension)
		return handle_plugin(argc, argv, extension);

	return run_joined_command(argc, argv, plugin);
}
