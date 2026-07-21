// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Command/option metadata dump for nvme-cli.
 *
 * Builds an in-memory model of every command and its options, then writes it to
 * stdout as JSON for the `dump-command-metadata` subcommand. The JSON is a
 * machine-readable description of the CLI surface, intended for tooling such as
 * shell-completion generators, documentation, and drift checks.
 *
 * The model is captured by walking the live plugin/command tree and, for each
 * command, intercepting the options array it builds on its stack via NVME_ARGS.
 * Capture installs a hook in argconfig_parse() (see argconfig_set_parse_hook):
 * when a command calls into the parser, the hook copies the options array into
 * the model and returns a sentinel so the command unwinds before opening any
 * device.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command-metadata.h"
#include "common.h"
#include "nvme.h"
#include "util/json.h"

/*
 * The whole command is JSON-only, so it is compiled out entirely without
 * json-c support: nvme-builtin.h does not register it and nvme.c does not
 * define its handler, so dump_command_metadata() is never referenced.
 */
#ifdef CONFIG_JSONC

/*
 * Returned by the capture hook so argconfig_parse() unwinds before the
 * command's fn opens a device.
 */
#define METADATA_CAPTURE_SENTINEL (-ECANCELED)

/*
 * Version of the emitted JSON schema, bumped on any breaking change to the
 * output structure (renamed/removed keys, changed value semantics). Additive
 * changes that keep existing keys stable do not require a bump. Consumers
 * should reject a major version they do not understand.
 */
#define COMMAND_METADATA_SCHEMA_VERSION 1

/*
 * The command currently being captured; set by capture_command()
 * before it invokes the command fn, read by metadata_capture_hook().
 */
static struct command_metadata_command *command_metadata_cur_command;

/*
 * Capture OOM, reported out-of-band because the hook's return value is reserved
 * for the parser-unwind sentinel; checked after each command fn returns.
 */
static int command_metadata_capture_error;

/* ------------------------------------------------------------------ */
/* Pass 1: capture                                                    */
/* ------------------------------------------------------------------ */

static char *xstrdup(const char *s)
{
	return s ? strdup(s) : NULL;
}

/*
 * Deep-copy an opt_val table into *out. A NULL src is not an error: *out is set
 * to NULL, the "no value table" sentinel consumers expect. Returns -ENOMEM on
 * allocation failure so the caller can abort rather than silently drop values.
 */
static int copy_opt_val(const struct argconfig_opt_val *src, const struct argconfig_opt_val **out)
{
	struct argconfig_opt_val *dst;
	size_t n = 0, i;

	*out = NULL;
	if (!src)
		return 0;

	for (; src[n].str; n++)
		;

	dst = calloc(n + 1, sizeof(*dst));
	if (!dst)
		return -ENOMEM;

	for (i = 0; i < n; i++) {
		dst[i] = src[i];
		/* src[i].str is non-NULL for i < n, so NULL here means OOM. */
		dst[i].str = strdup(src[i].str);
		if (!dst[i].str)
			return -ENOMEM;
	}
	dst[n].str = NULL;

	*out = dst;
	return 0;
}

/*
 * Duplicate a possibly-NULL string: NULL src succeeds (copies to NULL); a
 * non-NULL src that fails to duplicate returns -ENOMEM.
 */
static int dup_field(const char *src, const char **dst)
{
	*dst = xstrdup(src);
	if (src && !*dst)
		return -ENOMEM;
	return 0;
}

/*
 * Deep-copy an options array into *out (a heap array of *n_out entries).
 * Returns -ENOMEM on failure; the partial allocation is left for process exit
 * to reclaim, as the model is never explicitly freed.
 */
static int copy_options(const struct argconfig_commandline_options *opts,
			struct command_metadata_option **out, size_t *n_out)
{
	const struct argconfig_commandline_options *s;
	struct command_metadata_option *dst;
	size_t n = 0, i;

	*out = NULL;
	*n_out = 0;

	for (s = opts; s->option; s++)
		n++;

	if (!n)	/* calloc(0) may return NULL, indistinguishable from OOM */
		return 0;

	dst = calloc(n, sizeof(*dst));
	if (!dst)
		return -ENOMEM;

	/*
	 * Deep-copy: option/meta/help and the opt_val table are valid while the
	 * parser runs but may point at command-local storage that is freed once
	 * the command's fn returns, so duplicate rather than alias them.
	 */
	for (i = 0; i < n; i++) {
		if (dup_field(opts[i].option, &dst[i].option) ||
		    dup_field(opts[i].meta, &dst[i].meta) ||
		    dup_field(opts[i].help, &dst[i].help) ||
		    copy_opt_val(opts[i].opt_val, &dst[i].opt_val))
			return -ENOMEM;
		dst[i].short_option = opts[i].short_option;
		dst[i].config_type = opts[i].config_type;
		dst[i].argument_type = opts[i].argument_type;
		dst[i].hidden = opts[i].hidden;
	}

	*out = dst;
	*n_out = n;
	return 0;
}

/*
 * argconfig_parse() hook installed by build_model(): copies the current
 * command's options into the model, then returns the sentinel so the parser
 * unwinds before the command opens a device.
 */
static int metadata_capture_hook(int argc, char **argv, const char *program_desc,
				 struct argconfig_commandline_options *options)
{
	(void)argc;
	(void)argv;
	(void)program_desc;

	if (command_metadata_cur_command && !command_metadata_cur_command->captured) {
		int err = copy_options(options,
				&command_metadata_cur_command->options,
				&command_metadata_cur_command->num_options);
		if (err)
			command_metadata_capture_error = err;
		command_metadata_cur_command->captured = true;
	}

	return METADATA_CAPTURE_SENTINEL;
}

/* Returns 0 on success, or -ENOMEM if the capture hook failed to allocate. */
static int capture_command(struct command_metadata_command *mc, struct command *cmd,
			   struct plugin *plugin)
{
	/*
	 * argv[1] is a placeholder device; the sentinel returns before it is
	 * ever opened, so it need not (and must not) name a real device.
	 */
	char *argv[] = { cmd->name, (char *)"metadata-dump-dummy-device", NULL };

	mc->name = cmd->name;
	mc->alias = cmd->alias;
	mc->help = cmd->help;
	mc->captured = false;

	/*
	 * Don't invoke the dump command itself: it would re-enter
	 * dump_command_metadata() and recurse forever. It has no
	 * completable options, so leave its options array empty.
	 */
	if (!strcmp(cmd->name, "dump-command-metadata"))
		return 0;

	command_metadata_capture_error = 0;
	command_metadata_cur_command = mc;
	(void)cmd->fn(2, argv, cmd, plugin);
	command_metadata_cur_command = NULL;

	/*
	 * If the hook never fired, the command returned before reaching the
	 * parser (e.g. gen-hostnqn) and has no completable options; its options
	 * array is simply left empty.
	 */
	return command_metadata_capture_error;
}

static size_t count_commands(struct command **commands)
{
	size_t n = 0;

	while (commands && commands[n])
		n++;

	return n;
}

static size_t count_plugins(struct plugin *p)
{
	size_t n = 0;

	for (; p; p = p->next)
		n++;

	return n;
}

static struct command_metadata_program *build_model(struct program *prog)
{
	struct command_metadata_program *model;
	struct plugin *plugin;
	int saved_stdout = -1, saved_stderr = -1, devnull;
	int err = 0;
	size_t pi;

	model = calloc(1, sizeof(*model));
	if (!model)
		return NULL;

	model->name = prog->name;
	model->version = prog->version;
	model->desc = prog->desc;
	model->num_plugins = count_plugins(prog->extensions);
	if (model->num_plugins) {
		model->plugins = calloc(model->num_plugins, sizeof(*model->plugins));
		if (!model->plugins) {
			free(model);
			return NULL;
		}
	}

	/*
	 * Suppress stdout/stderr while invoking command fns: some commands
	 * may print before or during option capture, which would corrupt the
	 * JSON output.
	 */
	fflush(stdout);
	fflush(stderr);
	devnull = open(DEV_NULL, O_WRONLY);
	if (devnull >= 0) {
		saved_stdout = dup(STDOUT_FILENO);
		saved_stderr = dup(STDERR_FILENO);
		if (saved_stdout >= 0)
			dup2(devnull, STDOUT_FILENO);
		if (saved_stderr >= 0)
			dup2(devnull, STDERR_FILENO);
	}

	argconfig_set_parse_hook(metadata_capture_hook);

	for (pi = 0, plugin = prog->extensions; plugin; plugin = plugin->next, pi++) {
		struct command_metadata_plugin *mp = &model->plugins[pi];
		size_t ci;

		mp->name = plugin->name;
		mp->desc = plugin->desc;
		mp->num_commands = count_commands(plugin->commands);
		if (!mp->num_commands)
			continue;
		mp->commands = calloc(mp->num_commands, sizeof(*mp->commands));
		if (!mp->commands) {
			mp->num_commands = 0;
			err = -ENOMEM;
			break;
		}

		for (ci = 0; ci < mp->num_commands; ci++) {
			err = capture_command(&mp->commands[ci],
					plugin->commands[ci], plugin);
			if (err)
				break;
		}
		if (err)
			break;
	}

	argconfig_set_parse_hook(NULL);

	fflush(stdout);
	fflush(stderr);
	if (saved_stdout >= 0) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
	}
	if (saved_stderr >= 0) {
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stderr);
	}
	if (devnull >= 0)
		close(devnull);

	/*
	 * An allocation failure while capturing would leave an incomplete model
	 * that looks complete in the emitted JSON; fail the dump instead. The
	 * partial model is left for process exit to reclaim (it is never freed
	 * on the success path either).
	 */
	if (err)
		return NULL;

	return model;
}

/* ------------------------------------------------------------------ */
/* Model helpers shared by emitters                                   */
/* ------------------------------------------------------------------ */

static bool opt_is_separator(const struct command_metadata_option *o)
{
	return o->config_type == CFG_GROUP_SEPARATOR;
}

static bool opt_is_global_separator(const struct command_metadata_option *o)
{
	return opt_is_separator(o) && o->help && !strcmp(o->help, "Global options");
}

/* "none" / "required" / "optional" — how the option consumes its argument. */
static const char *opt_argument(const struct command_metadata_option *o)
{
	switch (o->argument_type) {
	case optional_argument:
		return "optional";
	case no_argument:
		return "none";
	default:
		return "required";
	}
}

static bool opt_takes_value(const struct command_metadata_option *o)
{
	return o->argument_type != no_argument;
}

/*
 * True for an option that should be emitted: a real, named, non-separator
 * option. Hidden options are emitted too (tagged "hidden" in the output) so
 * the dump describes the full set of accepted options; consumers that only
 * want user-facing options (e.g. completion generators) filter on that tag.
 */
static bool opt_is_emittable(const struct command_metadata_option *o)
{
	return !opt_is_separator(o) && o->option && o->option[0];
}

/* ------------------------------------------------------------------ */
/* Pass 2: JSON                                                       */
/* ------------------------------------------------------------------ */

/*
 * The value set for an option, when the generator can derive it. Returns a
 * json array of strings, or NULL if the option has no known value set. The
 * caller owns the returned array.
 *
 * output-format is special-cased because its values are not represented via an
 * opt_val table; keep the hard-coded list below in sync with
 * validate_output_format() / DESC_OUTPUT_FORMAT. Since the whole command is
 * compiled out without json-c, "json" is always a valid value here. Every
 * other value set comes from the option's opt_val table, which is the set the
 * parser actually enforces; options whose value is unconstrained (e.g. any
 * OPT_UINT such as output-format-version) have no values array.
 */
static struct json_object *json_option_values(const struct command_metadata_option *o)
{
	const struct argconfig_opt_val *v;
	struct json_object *vals;

	if (!strcmp(o->option, "output-format")) {
		vals = json_create_array();
		json_array_add_value_string(vals, "normal");
		json_array_add_value_string(vals, "json");
		json_array_add_value_string(vals, "binary");
		json_array_add_value_string(vals, "tabular");
		return vals;
	}
	if (!o->opt_val)
		return NULL;

	vals = json_create_array();
	for (v = o->opt_val; v->str; v++)
		json_array_add_value_string(vals, v->str);
	return vals;
}

/* Build one option as a json object and add it to the given array. */
static void json_option(struct json_object *arr, const struct command_metadata_option *o,
			bool global)
{
	struct json_object *jo, *vals;
	char shortbuf[2] = { o->short_option, '\0' };

	if (!opt_is_emittable(o))
		return;

	jo = json_create_object();
	json_object_add_value_string(jo, "long", o->option);
	if (o->short_option)
		json_object_add_value_string(jo, "short", shortbuf);
	json_object_add_value_string(jo, "argument", opt_argument(o));
	if (o->meta && opt_takes_value(o))
		json_object_add_value_string(jo, "metavar", o->meta);
	if (o->help)
		json_object_add_value_string(jo, "description", o->help);
	if (global)
		json_object_add_value_bool(jo, "global", true);
	if (o->hidden)
		json_object_add_value_bool(jo, "hidden", true);

	vals = json_option_values(o);
	if (vals)
		json_object_add_value_array(jo, "values", vals);

	json_array_add_value_object(arr, jo);
}

/* Build one command as a json object: name, alias, description, and options. */
static struct json_object *json_command(const struct command_metadata_command *c)
{
	struct json_object *jc, *opts;
	bool global = false;
	size_t i;

	jc = json_create_object();
	json_object_add_value_string(jc, "name", c->name);
	if (c->alias)
		json_object_add_value_string(jc, "alias", c->alias);
	if (c->help)
		json_object_add_value_string(jc, "description", c->help);

	opts = json_create_array();
	for (i = 0; i < c->num_options; i++) {
		/*
		 * Options after the "Global options" separator are the shared
		 * NVME_ARGS globals; flag them so generators can group them.
		 */
		if (opt_is_global_separator(&c->options[i])) {
			global = true;
			continue;
		}
		json_option(opts, &c->options[i], global);
	}
	json_object_add_value_array(jc, "options", opts);

	return jc;
}

/* Build one named plugin as a json object: name, description, commands. */
static struct json_object *json_plugin(const struct command_metadata_plugin *p)
{
	struct json_object *jp, *cmds;
	size_t i;

	jp = json_create_object();
	assert(p->name);	/* builtin (NULL-name) is emitted inline by json_program() */
	json_object_add_value_string(jp, "name", p->name);
	if (p->desc)
		json_object_add_value_string(jp, "description", p->desc);

	cmds = json_create_array();
	for (i = 0; i < p->num_commands; i++)
		json_array_add_value_object(cmds, json_command(&p->commands[i]));
	json_object_add_value_array(jp, "commands", cmds);

	return jp;
}

static void json_program(const struct command_metadata_program *m)
{
	struct json_object *root, *builtin, *plugins;
	size_t i;

	root = json_create_object();
	json_object_add_value_int(root, "schema_version",
				  COMMAND_METADATA_SCHEMA_VERSION);
	json_object_add_value_string(root, "name", m->name);
	if (m->version)
		json_object_add_value_string(root, "version", m->version);
	if (m->desc)
		json_object_add_value_string(root, "description", m->desc);

	/*
	 * Builtin (top-level) commands live in their own array; named plugins
	 * go under "plugins" so generators can build the dispatch nesting.
	 */
	builtin = json_create_array();
	plugins = json_create_array();
	for (i = 0; i < m->num_plugins; i++) {
		const struct command_metadata_plugin *p = &m->plugins[i];
		size_t j;

		if (!p->name) {
			for (j = 0; j < p->num_commands; j++)
				json_array_add_value_object(builtin,
					json_command(&p->commands[j]));
		} else {
			json_array_add_value_object(plugins, json_plugin(p));
		}
	}
	json_object_add_value_array(root, "commands", builtin);
	json_object_add_value_array(root, "plugins", plugins);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

int dump_command_metadata(struct program *prog)
{
	struct command_metadata_program *model;

	model = build_model(prog);
	if (!model)
		return -ENOMEM;

	json_program(model);

	return 0;
}

#endif /* CONFIG_JSONC */
