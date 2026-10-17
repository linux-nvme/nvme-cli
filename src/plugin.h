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

/* The operand of a command */
enum command_device {
	COMMAND_DEVICE,			/* <device>, the default */
	COMMAND_DEVICE_OPTIONAL,	/* [<device>] */
	COMMAND_NO_DEVICE,		/* no operand */
};

struct command {
	char *name;
	char *help;
	int (*fn)(int argc, char **argv, struct command *acmd, struct plugin *plugin);
	char *alias;
	bool deprecated;
	/* "nvme <plugin> <command>" which replaces a deprecated command */
	struct {
		const char *plugin;
		const char *command;
	} replacement;
	enum command_device device;
	/*
	 * The values --output-format accepts (enum nvme_print_flags), 0 for
	 * the default ones, OUTPUT_FORMATS_NORMAL for only the normal output.
	 * With OUTPUT_FORMATS_CUSTOM the command parses --output-format
	 * itself, and output_format_desc is its help text.
	 */
	uint32_t output_formats;
	const char *output_format_desc;
	/*
	 * Set for commands that keep the root privileges when nvme-cli runs
	 * with privilege separation. All other commands drop them before
	 * parsing their options and open devices through the helper.
	 */
	bool needs_root;
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
void command_prepare(struct command *cmd);
int handle_plugin(int argc, char **argv, struct plugin *plugin);

enum plugin_action {
	PLUGIN_RUN,		/* run @cmd */
	PLUGIN_HELP,		/* the help sub-command */
	PLUGIN_VERSION,		/* the version sub-command */
	PLUGIN_GENERAL_HELP,	/* list the commands */
	PLUGIN_ERROR,		/* return @err, @str is no sub-command */
};

/* What handle_plugin() does for a command line */
struct plugin_call {
	enum plugin_action action;
	struct plugin *plugin;
	struct command *cmd;
	int argc;
	char **argv;
	char *str;
	int err;
	/* argv when a name is prepended, freed by plugin_call_free() */
	char **alloc_argv;
	char *alloc_name;
};

/*
 * plugin_lookup() - Find what handle_plugin() does for a command line
 *
 * Parses the global options in front of the command, as handle_plugin()
 * does, but runs nothing. Only the usage errors of the global options are
 * printed, the rest by plugin_call_run().
 *
 * Return: 0, or a negative error code.
 */
int plugin_lookup(int argc, char **argv, struct plugin *plugin,
		  struct plugin_call *call);
int plugin_call_run(struct plugin_call *call);
void plugin_call_free(struct plugin_call *call);
int run_replacement(int argc, char **argv, struct command *cmd,
		    struct plugin *plugin);
int run_replacement_command(struct plugin *plugin, struct command *cmd,
			    const char *command, int argc, char **argv);

void register_extension(struct plugin *plugin);

/* The program: main() in main.c, and the fuzz tests, call it */
int nvme_main(int argc, char **argv);

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
