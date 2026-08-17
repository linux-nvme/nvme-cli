// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Unit tests for handle_plugin() in src/plugin.c: the CLI's sub-command
 * dispatcher. These drive it purely through argv (as the real "nvme"
 * binary would) against a small fake command/plugin tree, and check the
 * observable outcome: return code, which stub command ran, and what
 * general_help()/version_cmd() printed.
 *
 * One dispatch path is intentionally NOT exercised here: help(argc, argv,
 * plugin) with argv[1] matching a real command name calls execlp("man",
 * ...), which replaces the calling process on success. That's unsafe to
 * trigger from an in-process unit test (environment-dependent, and would
 * kill the test binary if a "man" executable is present). Every case
 * below that reaches help() uses a target that matches no command, which
 * keeps it on the safe general_help() fallback path.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>

#include "../src/args.h"
#include "../src/plugin.h"

const char *libnvme_strerror(int errnum);

struct nvme_args nvme_args = {
	.output_format = "normal",
	.output_format_ver = 2,
	.timeout = 5000,
	.supported_output_formats = NORMAL,
};

static int test_rc;

struct last_call_info {
	const char *cmd_name;
	int argc;
};

static struct last_call_info last_call;

static void reset_last_call(void)
{
	last_call.cmd_name = NULL;
	last_call.argc = -1;
}

static void record_call(const char *name, int argc)
{
	last_call.cmd_name = name;
	last_call.argc = argc;
}

#define DEFINE_STUB(fnname, cmdname, retval)                                     \
	static int fnname(int argc, char **argv, struct command *acmd,          \
			  struct plugin *plugin)                                 \
	{                                                                         \
		(void)argv;                                                      \
		(void)acmd;                                                      \
		(void)plugin;                                                    \
		record_call(cmdname, argc);                                      \
		return retval;                                                   \
	}

DEFINE_STUB(foo_fn, "foo", 11)
DEFINE_STUB(bar_fn, "bar", 22)
DEFINE_STUB(status_fn, "status", 33)
DEFINE_STUB(old_fn, "old-cmd", 44)
DEFINE_STUB(list_a_fn, "list-a", 55)
DEFINE_STUB(list_b_fn, "list-b", 66)
DEFINE_STUB(sub_fn, "sub", 77)

static struct command cmd_foo = { "foo", "foo command", foo_fn, "f", false };
static struct command cmd_bar = { "bar", "bar command", bar_fn, NULL, false };
static struct command cmd_status = { "status", "status command", status_fn, NULL, false };
static struct command cmd_old = { "old-cmd", "deprecated command", old_fn, NULL, true };
static struct command cmd_list_a = { "list-a", "list-a command", list_a_fn, NULL, false };
static struct command cmd_list_b = { "list-b", "list-b command", list_b_fn, NULL, false };

/*
 * Split across two groups (rather than one flat array) to exercise
 * plugin_add_group()'s merging: dispatch and help-listing must both see
 * commands from every group a plugin has registered, and general_help()
 * must print each group's title as its own heading.
 */
static struct command *core_commands[] = {
	&cmd_foo, &cmd_bar, &cmd_status, &cmd_old, NULL
};
static struct command *list_commands[] = {
	&cmd_list_a, &cmd_list_b, NULL
};

static struct command cmd_sub = { "sub", "sub command", sub_fn, NULL, false };
static struct command *ext_commands[] = { &cmd_sub, NULL };

static struct plugin ext_plugin = {
	.name = "ext",
	.desc = "test extension",
	.version = "1.0",
	.core = true,
};

static struct plugin builtin_plugin = {
	.name = NULL,
	.desc = "test built-in",
	.version = "1.0",
	.next = &ext_plugin,
};

static struct program prog = {
	.name = "test-prog",
	.version = "9.9",
	.usage = "<args>",
	.desc = "test program description",
	.extensions = &builtin_plugin,
};

struct captured_output {
	char out[4096];
	char err[4096];
};

static int run_handle_plugin(char *argv[], int argc, struct plugin *plugin,
			     struct captured_output *cap)
{
	FILE *tmp_out, *tmp_err;
	int saved_stdout, saved_stderr;
	int ret = -EIO;
	size_t n;

	cap->out[0] = '\0';
	cap->err[0] = '\0';

	tmp_out = tmpfile();
	tmp_err = tmpfile();
	if (!tmp_out || !tmp_err) {
		printf("ERROR: tmpfile failed: %s\n", libnvme_strerror(errno));
		test_rc = 1;
		goto done;
	}

	saved_stdout = dup(STDOUT_FILENO);
	saved_stderr = dup(STDERR_FILENO);
	if (saved_stdout < 0 || saved_stderr < 0) {
		printf("ERROR: dup failed: %s\n", libnvme_strerror(errno));
		test_rc = 1;
		goto done;
	}

	fflush(stdout);
	fflush(stderr);
	dup2(fileno(tmp_out), STDOUT_FILENO);
	dup2(fileno(tmp_err), STDERR_FILENO);

	ret = handle_plugin(argc, argv, plugin);

	fflush(stdout);
	fflush(stderr);
	dup2(saved_stdout, STDOUT_FILENO);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stdout);
	close(saved_stderr);

	fseek(tmp_out, 0, SEEK_SET);
	n = fread(cap->out, 1, sizeof(cap->out) - 1, tmp_out);
	cap->out[n] = '\0';

	fseek(tmp_err, 0, SEEK_SET);
	n = fread(cap->err, 1, sizeof(cap->err) - 1, tmp_err);
	cap->err[n] = '\0';

done:
	if (tmp_out)
		fclose(tmp_out);
	if (tmp_err)
		fclose(tmp_err);

	return ret;
}

static void check(bool cond, const char *desc)
{
	if (!cond) {
		printf("ERROR: %s\n", desc);
		test_rc = 1;
	}
}

static void test_dispatch_exact(void)
{
	char *argv[] = { "test-prog", "bar" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 22, "dispatch_exact: return code");
	check(last_call.cmd_name && !strcmp(last_call.cmd_name, "bar"),
	      "dispatch_exact: bar_fn ran");
}

static void test_dispatch_alias(void)
{
	char *argv[] = { "test-prog", "f" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 11, "dispatch_alias: return code");
	check(last_call.cmd_name && !strcmp(last_call.cmd_name, "foo"),
	      "dispatch_alias: alias 'f' dispatched to foo_fn");
}

static void test_dispatch_prefix_unique(void)
{
	char *argv[] = { "test-prog", "sta" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 33, "dispatch_prefix_unique: return code");
	check(last_call.cmd_name && !strcmp(last_call.cmd_name, "status"),
	      "dispatch_prefix_unique: unique prefix 'sta' dispatched to status_fn");
}

static void test_dispatch_prefix_ambiguous(void)
{
	char *argv[] = { "test-prog", "list" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == -ENOTTY, "dispatch_prefix_ambiguous: return code");
	check(last_call.cmd_name == NULL,
	      "dispatch_prefix_ambiguous: neither list-a nor list-b ran");
	check(strstr(cap.err, "Invalid sub-command 'list'") != NULL,
	      "dispatch_prefix_ambiguous: stderr reports invalid sub-command");
}

static void test_no_args(void)
{
	char *argv[] = { "test-prog" };
	struct captured_output cap;
	char *banner, *old_cmd, *core_heading, *list_heading, *bar_pos, *list_a_pos;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, 0, &builtin_plugin, &cap);

	check(ret == 0, "no_args: return code");
	check(strstr(cap.out, "test-prog") != NULL, "no_args: prints program name");
	check(strstr(cap.out, "bar") != NULL, "no_args: lists 'bar' command");

	/* Deprecated commands are omitted from the main listing but still
	 * shown afterwards, under their own "deprecated" banner.
	 */
	banner = strstr(cap.out, "deprecated and will be removed");
	old_cmd = strstr(cap.out, "old-cmd");
	check(banner != NULL, "no_args: deprecated-commands banner present");
	check(old_cmd != NULL && banner != NULL && old_cmd > banner,
	      "no_args: old-cmd listed only after the deprecated banner, not in the main listing");

	check(strstr(cap.out, "ext") != NULL, "no_args: lists 'ext' extension");

	/*
	 * builtin_plugin was assembled from two plugin_add_group() calls
	 * ("Core Commands" holding foo/bar/status/old-cmd, "List Commands"
	 * holding list-a/list-b). Each group's title must appear as its own
	 * heading, in order, with that group's commands listed under it --
	 * not merged into one flat, unheaded list.
	 */
	core_heading = strstr(cap.out, "Core Commands:");
	list_heading = strstr(cap.out, "List Commands:");
	bar_pos = strstr(cap.out, "bar");
	list_a_pos = strstr(cap.out, "list-a");
	check(core_heading != NULL, "no_args: 'Core Commands' heading printed");
	check(list_heading != NULL, "no_args: 'List Commands' heading printed");
	check(core_heading && list_heading && core_heading < list_heading,
	      "no_args: group headings appear in registration order");
	check(bar_pos && core_heading && bar_pos > core_heading,
	      "no_args: 'bar' listed under the 'Core Commands' heading");
	check(list_a_pos && list_heading && list_a_pos > list_heading,
	      "no_args: 'list-a' listed under the 'List Commands' heading");
}

static void test_dispatch_second_group(void)
{
	char *argv[] = { "test-prog", "list-a" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 55, "dispatch_second_group: return code");
	check(last_call.cmd_name && !strcmp(last_call.cmd_name, "list-a"),
	      "dispatch_second_group: exact match on a second-group command "
	      "dispatches despite prefix ambiguity with a sibling in the same group");
}

static void test_help_bare(void)
{
	char *argv[] = { "test-prog", "help" };
	struct captured_output cap;
	int ret;

	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 0, "help_bare: return code");
	check(strstr(cap.out, "bar") != NULL, "help_bare: lists commands like general help");
}

static void test_help_filtered_unknown(void)
{
	char *argv[] = { "test-prog", "help", "zzz" };
	struct captured_output cap;
	int ret;

	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 0, "help_filtered_unknown: return code");
	check(strstr(cap.out, "Only sub-commands including zzz") != NULL,
	      "help_filtered_unknown: filter note printed");
	check(strstr(cap.out, "bar") == NULL,
	      "help_filtered_unknown: non-matching commands filtered out");
}

static void test_version_subcommand(void)
{
	char *argv[] = { "test-prog", "version" };
	struct captured_output cap;
	int ret;

	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 0, "version_subcommand: return code");
	check(strstr(cap.out, "test-prog version 9.9") != NULL,
	      "version_subcommand: prints program name and version");
}

static void test_global_version_flag(void)
{
	char *argv[] = { "test-prog", "-V" };
	struct captured_output cap;
	int ret;

	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 0, "global_version_flag: return code");
	check(strstr(cap.out, "test-prog version 9.9") != NULL,
	      "global_version_flag: '-V' before subcommand prints version");
}

static void test_global_help_flag_bare(void)
{
	char *argv[] = { "test-prog", "-h" };
	struct captured_output cap;
	int ret;

	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 0, "global_help_flag_bare: return code");
	check(strstr(cap.out, "bar") != NULL,
	      "global_help_flag_bare: '-h' with no subcommand shows general help");
}

static void test_global_help_flag_with_target(void)
{
	char *argv[] = { "test-prog", "--help", "zzz" };
	struct captured_output cap;
	int ret;

	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 0, "global_help_flag_with_target: return code");
	check(strstr(cap.out, "Only sub-commands including zzz") != NULL,
	      "global_help_flag_with_target: '--help zzz' filters help output");
}

static void test_unknown_subcommand(void)
{
	char *argv[] = { "test-prog", "zzz" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == -ENOTTY, "unknown_subcommand: return code");
	check(strstr(cap.err, "Invalid sub-command 'zzz'") != NULL,
	      "unknown_subcommand: stderr reports invalid sub-command");
}

static void test_extension_dispatch_separate_token(void)
{
	char *argv[] = { "test-prog", "ext", "sub" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 77, "extension_dispatch_separate_token: return code");
	check(last_call.cmd_name && !strcmp(last_call.cmd_name, "sub"),
	      "extension_dispatch_separate_token: 'ext sub' dispatched to sub_fn");
}

static void test_extension_dispatch_concatenated(void)
{
	char *argv[] = { "test-prog", "ext-sub" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == 77, "extension_dispatch_concatenated: return code");
	check(last_call.cmd_name && !strcmp(last_call.cmd_name, "sub"),
	      "extension_dispatch_concatenated: 'ext-sub' dispatched to sub_fn");
}

static void test_extension_unknown_subcommand(void)
{
	char *argv[] = { "test-prog", "ext", "zzz" };
	struct captured_output cap;
	int ret;

	reset_last_call();
	ret = run_handle_plugin(argv, ARRAY_SIZE(argv), &builtin_plugin, &cap);

	check(ret == -ENOTTY, "extension_unknown_subcommand: return code");
	check(strstr(cap.err, "Invalid sub-command 'zzz' for plugin ext") != NULL,
	      "extension_unknown_subcommand: stderr names the extension");
}

int main(void)
{
	test_rc = 0;

	builtin_plugin.parent = &prog;
	ext_plugin.parent = &prog;

	plugin_add_group(&builtin_plugin, "Core Commands", core_commands);
	plugin_add_group(&builtin_plugin, "List Commands", list_commands);
	plugin_add_group(&ext_plugin, NULL, ext_commands);

	test_dispatch_exact();
	test_dispatch_alias();
	test_dispatch_prefix_unique();
	test_dispatch_prefix_ambiguous();
	test_dispatch_second_group();
	test_no_args();
	test_help_bare();
	test_help_filtered_unknown();
	test_version_subcommand();
	test_global_version_flag();
	test_global_help_flag_bare();
	test_global_help_flag_with_target();
	test_unknown_subcommand();
	test_extension_dispatch_separate_token();
	test_extension_dispatch_concatenated();
	test_extension_unknown_subcommand();

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
