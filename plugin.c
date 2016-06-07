#include <stdio.h>
#include <stdlib.h>

#include "plugin.h"
#include "argconfig.h"

void usage(struct plugin *plugin)
{
	struct program *prog = plugin->parent;

	printf("usage: %s %s\n", prog->name, prog->usage);
}

void general_help(struct plugin *plugin)
{
	struct program *prog = plugin->parent;
	struct plugin *extension;
	unsigned i = 0;

	printf("%s-%s\n", prog->name, prog->version);

	usage(plugin);

	printf("\n");
	print_word_wrapped(prog->desc, 0, 0);
	printf("\n");

	if (plugin->desc) {
		printf("\n");
		print_word_wrapped(plugin->desc, 0, 0);
		printf("\n");
	}

	printf("\nThe following are all implemented sub-commands:\n");

	for (; plugin->commands[i]; i++)
		printf("  %-*s %s\n", 15, plugin->commands[i]->name,
					plugin->commands[i]->help);
	printf("\n");

	if (plugin->name)
		printf("See '%s %s help <command>' for more information on a specific command\n",
			prog->name, plugin->name);
	else
		printf("See '%s help <command>' for more information on a specific command\n",
			prog->name);

	/* The first plugin is the built-in. If we're not showing help for the
	 * built-in, don't show the program's other extensions */
	if (plugin->name)
		return;

	extension = prog->extensions->next;
	if (!extension)
		return;

	printf("\nThe following are all installed plugin extensions:\n");
	while (extension) {
		printf("  %-*s %s\n", 15, extension->name, extension->desc);
		extension = extension->next;
	}
	printf("\nSee '%s <plugin> help' for more information on a plugin\n",
			prog->name);
}

int handle_plugin(int argc, char **argv, struct plugin *plugin)
{
	unsigned i = 0;
	char *str = argv[0];
	char use[0x100];
	struct plugin *extension;
	struct program *prog = plugin->parent;

	if (!argc) {
		general_help(plugin);
		return 0;
	}

	if (!plugin->name)
		sprintf(use, "%s %s <device> [OPTIONS]", prog->name, str);
	else
		sprintf(use, "%s %s %s <device> [OPTIONS]", prog->name, plugin->name, str);
	argconfig_append_usage(use);

	/* translate --help and --version into commands */
	while (*str == '-')
		str++;

	for (; plugin->commands[i]; i++) {
		struct command *cmd = plugin->commands[i];

		if (strcmp(str, cmd->name))
			continue;

		return (cmd->fn(argc, argv, cmd, plugin));
	}

	/* Check extensions only if this is running the built-in plugin */
	if (plugin->name)
		return -1;

	extension = plugin->next;
	while (extension) {
		if (strcmp(str, extension->name)) {
			extension = extension->next;
			continue;
		}
		return handle_plugin(argc - 1, &argv[1], extension);
	}
	return -1;
}
