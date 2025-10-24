/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdbool.h>

struct program {
	const char *name;
	const char *version;
	const char *usage;
	const char *desc;
	const char *more;
	struct command **commands;
	struct plugin *extensions;
};

struct plugin {
	const char *name;
	const char *desc;
	const char *version;
	struct command **commands;
	struct program *parent;
	struct plugin *next;
	struct plugin *tail;
};

struct command {
	char *name;
	char *help;
	int (*fn)(int argc, char **argv, struct command *acmd, struct plugin *plugin);
	char *alias;
};

void general_help(struct plugin *plugin, char *str);
int handle_plugin(int argc, char **argv, struct plugin *plugin);

#endif
