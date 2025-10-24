// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "plugin.h"
#include "util/argconfig.h"

#include <libnvme.h>

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
		nvme_get_version(NVME_VERSION_PROJECT),
		nvme_get_version(NVME_VERSION_GIT));
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
			sprintf(man, "%s-%s-%s", prog->name,
				plugin->name, command->name);
		else
			sprintf(man, "%s-%s", prog->name, command->name);
		if (execlp("man", "man", man, (char *)NULL))
			perror(argv[1]);
	}

	general_help(plugin, str);

	return 0;
}

static void usage_cmd(struct plugin *plugin)
{
	struct program *prog = plugin->parent;

	if (plugin->name)
		printf("usage: %s %s %s\n", prog->name, plugin->name, prog->usage);
	else
		printf("usage: %s %s\n", prog->name, prog->usage);
}

void general_help(struct plugin *plugin, char *str)
{
	struct program *prog = plugin->parent;
	struct plugin *extension;
	unsigned int i = 0;
	unsigned int padding = 15;
	unsigned int curr_length = 0;

	printf("%s-%s\n", prog->name, prog->version);

	usage_cmd(plugin);

	printf("\n");
	print_word_wrapped(prog->desc, 0, 0, stdout);
	printf("\n");

	if (plugin->desc) {
		printf("\n");
		print_word_wrapped(plugin->desc, 0, 0, stdout);
		printf("\n");
	}

	printf("\nThe following are all implemented sub-commands:\n");
	if (str)
		printf("Note: Only sub-commands including %s\n", str);

	/*
	 * iterate through all commands to get maximum length
	 * Still need to handle the case of ultra long strings, help messages, etc
	 */
	for (; plugin->commands[i]; i++) {
		curr_length = 2 + strlen(plugin->commands[i]->name);
		if (padding < curr_length)
			padding = curr_length;
	}

	i = 0;
	for (; plugin->commands[i]; i++) {
		if (!str || strstr(plugin->commands[i]->name, str))
			printf("  %-*s %s\n", padding, plugin->commands[i]->name,
			       plugin->commands[i]->help);
	}

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
	if (plugin->name)
		return;

	extension = prog->extensions->next;
	if (!extension)
		return;

	printf("\nThe following are all installed plugin extensions:\n");
	if (str)
		printf("Note: Only extensions including %s\n", str);

	while (extension) {
		if (!str || strstr(extension->name, str))
			printf("  %-*s %s\n", 15, extension->name, extension->desc);
		extension = extension->next;
	}
	printf("\nSee '%s <plugin> help' for more information on a plugin\n",
			prog->name);
}

int handle_plugin(int argc, char **argv, struct plugin *plugin)
{
	char *str = argv[0];
	char use[0x100];
	struct plugin *extension;
	struct program *prog = plugin->parent;
	struct command **cmd = plugin->commands;
	struct command *cr = NULL;
	bool cr_valid = false;
	int dash_count = 0;

	if (!argc) {
		general_help(plugin, NULL);
		return 0;
	}

	if (!plugin->name)
		sprintf(use, "%s %s <device> [OPTIONS]", prog->name, str);
	else
		sprintf(use, "%s %s %s <device> [OPTIONS]", prog->name, plugin->name, str);
	argconfig_append_usage(use);

	/* translate --help, -h and --version into commands */
	while (str[dash_count] == '-')
		dash_count++;

	if (dash_count)
		str += dash_count;

	if (!strcmp(str, "help") || (dash_count == 1 && !strcmp(str, "h")))
		return help(argc, argv, plugin);
	if (!strcmp(str, "version"))
		return version_cmd(plugin);

	while (*cmd) {
		if (!strcmp(str, (*cmd)->name) ||
		    ((*cmd)->alias && !strcmp(str, (*cmd)->alias)))
			return (*cmd)->fn(argc, argv, *cmd, plugin);
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
		sprintf(use, "%s %s <device> [OPTIONS]", prog->name, cr->name);
		argconfig_append_usage(use);
		return cr->fn(argc, argv, cr, plugin);
	}

	/* Check extensions only if this is running the built-in plugin */
	if (plugin->name) {
		printf("ERROR: Invalid sub-command '%s' for plugin %s\n", str, plugin->name);
		return -ENOTTY;
	}

	extension = plugin->next;
	while (extension) {
		if (!strcmp(str, extension->name))
			return handle_plugin(argc - 1, &argv[1], extension);
		extension = extension->next;
	}

	/*
	 * If the command is executed with the extension name and
	 * command together ("plugin-command"), run the plug in
	 */
	extension = plugin->next;
	while (extension) {
		if (!strncmp(str, extension->name, strlen(extension->name))) {
			argv[0] += strlen(extension->name);
			while (*argv[0] == '-')
				argv[0]++;
			return handle_plugin(argc, &argv[0], extension);
		}
		extension = extension->next;
	}
	printf("ERROR: Invalid sub-command '%s'\n", str);
	return -ENOTTY;
}
