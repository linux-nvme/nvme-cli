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
	struct command **commands;
	struct program *parent;
	struct plugin *next;
	struct plugin *tail;
};

struct command {
	char *name;
	char *help;
	int (*fn)(int argc, char **argv, struct command *command, struct plugin *plugin);
};

void usage(struct plugin *plugin);
void general_help(struct plugin *plugin);
int handle_plugin(int argc, char **argv, struct plugin *plugin);

#endif
