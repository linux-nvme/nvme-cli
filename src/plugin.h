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
	struct command **commands;
	struct plugin *extensions;
};

struct command_group {
	const char *title;		/* NULL => no heading in --help output */
	struct command **commands;	/* NULL-terminated, same shape as plugin->commands */
	struct command_group *next;
};

struct plugin {
	const char *name;
	const char *desc;
	const char *version;
	struct command **commands;
	struct command_group *groups;
	struct program *parent;
	struct plugin *next;
	struct plugin *tail;
	bool core;
	/*
	 * Optional built-in group title (see plugin_add_group()) this core
	 * plugin is thematically related to. When set, general_help() lists
	 * the plugin right after that group's commands instead of in the
	 * flat "core NVMe/NVMeoF plugins" list.
	 */
	const char *group;
};

struct command {
	char *name;
	char *help;
	int (*fn)(int argc, char **argv, struct command *acmd, struct plugin *plugin);
	char *alias;
	bool deprecated;
	/* Set for commands that don't take a positional <device> argument. */
	bool no_device;
	/*
	 * The values --output-format accepts (enum nvme_print_flags), 0 for
	 * the default ones, OUTPUT_FORMATS_NORMAL for only the normal output.
	 * With OUTPUT_FORMATS_CUSTOM the command parses --output-format
	 * itself, and output_format_desc is its help text.
	 */
	uint32_t output_formats;
	const char *output_format_desc;
};

/*
 * The flat, no-namespace top-level plugin ("nvme <command>", as opposed to
 * "nvme <plugin> <command>"), defined in nvme.c. Built-in command group
 * files attach to it directly with plugin_add_group() rather than going
 * through register_extension(), since it's already the root of the
 * extensions list.
 */
extern struct plugin builtin;

void general_help(struct plugin *plugin, char *str);
void command_set_output_formats(struct command *cmd);
int handle_plugin(int argc, char **argv, struct plugin *plugin);

void register_extension(struct plugin *plugin);

/*
 * Attach one file's worth of commands to a plugin (built-in or named).
 * commands must be a NULL-terminated array with static storage duration
 * (it is not copied). title is shown as a heading in --help output when
 * non-NULL; pass NULL for plugins that don't want sub-grouping.
 */
void plugin_add_group(struct plugin *plugin, const char *title,
		      struct command **commands);

int __id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin, void (*vs)(uint8_t *vs, struct json_object *root));
