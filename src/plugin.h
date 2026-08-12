/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "nvme-json.h"

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
	bool core;
};

struct command {
	char *name;
	char *help;
	int (*fn)(int argc, char **argv, struct command *acmd, struct plugin *plugin);
	char *alias;
	bool deprecated;
};

void general_help(struct plugin *plugin, char *str);
int handle_plugin(int argc, char **argv, struct plugin *plugin);

void register_extension(struct plugin *plugin);

int __id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin, void (*vs)(uint8_t *vs, struct json_object *root));
