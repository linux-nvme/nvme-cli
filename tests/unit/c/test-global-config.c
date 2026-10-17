// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Unit tests for global-config.c: mapping /etc/nvme/nvme-cli.conf's
 * [Global] keys onto struct nvme_args, and its fail-safe handling of
 * unknown keys, malformed values, and a missing file.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <shared/assert-util.h>
#include <shared/fs-util.h>
#include <shared/sandbox-util.h>

#include "../src/argconfig.h"
#include "../src/args.h"
#include "../src/global-config.h"

struct nvme_args nvme_args = {
	.output_format = "normal",
	.output_format_ver = 2,
	.timeout = 5000,
	.supported_output_formats = NORMAL,
};

/*
 * The throwaway .conf files land in the current directory, which meson
 * sets to the build directory. A relative template keeps this off "/tmp",
 * which isn't a usable temp directory on Windows.
 */
static char *write_temp(const char *content)
{
	char *path = strdup("nvme-cli-conf-test-XXXXXX");
	int fd;

	shr_assert(path);

	fd = shr_mkstemp(path);
	shr_assert(fd >= 0);
	shr_assert(write(fd, content, strlen(content)) == (ssize_t)strlen(content));
	close(fd);

	return path;
}

static bool test_valid_keys(void)
{
	char *path = write_temp(
		"[Global]\n"
		"verbose = 2\n"
		"quiet = true\n"
		"output-format = json\n"
		"timeout = 12345\n"
		"dry-run = yes\n"
		"no-retries = on\n"
		"no-ioctl-probing = 1\n"
		"output-format-version = 1\n"
		"set-options = foo=bar\n");
	bool pass = true;

	printf("test_valid_keys:\n");

	nvme_load_global_config_from(path);
	unlink(path);
	free(path);

	if (nvme_args.verbose != 2 || !nvme_args.quiet ||
	    strcmp(nvme_args.output_format, "json") ||
	    nvme_args.timeout != 12345 || !nvme_args.dry_run ||
	    !nvme_args.no_retries || !nvme_args.no_ioctl_probing ||
	    nvme_args.output_format_ver != 1 ||
	    strcmp(nvme_args.set_options, "foo=bar")) {
		printf(" - values applied to nvme_args [FAIL]\n");
		pass = false;
	} else {
		printf(" - values applied to nvme_args [PASS]\n");
	}

	return pass;
}

static bool test_unknown_key_ignored(void)
{
	char *path = write_temp(
		"[Global]\n"
		"timeout = 999\n"
		"bogus-key = whatever\n");
	bool pass = true;

	printf("test_unknown_key_ignored:\n");

	nvme_load_global_config_from(path);
	unlink(path);
	free(path);

	/* An unknown key must not abort parsing of the rest of the file. */
	if (nvme_args.timeout != 999) {
		printf(" - sibling keys still applied [FAIL]\n");
		pass = false;
	} else {
		printf(" - sibling keys still applied [PASS]\n");
	}

	return pass;
}

static bool test_value_names(void)
{
	char *path = write_temp(
		"[Global]\n"
		"timeout = infinite\n");
	bool pass = true;

	printf("test_value_names:\n");

	nvme_args.timeout = 5000;
	nvme_load_global_config_from(path);
	unlink(path);
	free(path);

	/* The names the command line takes work in the file too */
	if (nvme_args.timeout != UINT32_MAX) {
		printf(" - timeout = infinite [FAIL]\n");
		pass = false;
	} else {
		printf(" - timeout = infinite [PASS]\n");
	}

	return pass;
}

static bool test_strict_numbers_and_buf(void)
{
	bool pass = true;

	printf("test_strict_numbers_and_buf:\n");

	nvme_args.timeout = 42;
	nvme_load_global_config_buf("[Global]\ntimeout = +5\n", "buf");
	if (nvme_args.timeout != 42) {
		printf(" - '+5' rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - '+5' rejected [PASS]\n");
	}

	nvme_load_global_config_buf("[Global]\ntimeout = 0x10\n", "buf");
	if (nvme_args.timeout != 16) {
		printf(" - '0x10' taken from a buffer [FAIL]\n");
		pass = false;
	} else {
		printf(" - '0x10' taken from a buffer [PASS]\n");
	}

	nvme_args.timeout = 42;
	nvme_load_global_config_buf("[Global]\ntimeout = 010\n", "buf");
	if (nvme_args.timeout != 42) {
		printf(" - '010' rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - '010' rejected [PASS]\n");
	}

	nvme_args.output_format_ver = 2;
	nvme_load_global_config_buf("[Global]\noutput-format-version = 3\n",
				    "buf");
	if (nvme_args.output_format_ver != 2) {
		printf(" - '3' out of range rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - '3' out of range rejected [PASS]\n");
	}

	return pass;
}

static bool test_repeated_string(void)
{
	bool pass = true;

	printf("test_repeated_string:\n");

	nvme_load_global_config_buf("[Global]\noutput-format = json\n"
				    "output-format = binary\n", "buf");
	if (strcmp(nvme_args.output_format, "binary")) {
		printf(" - the last value counts [FAIL]\n");
		pass = false;
	} else {
		printf(" - the last value counts [PASS]\n");
	}
	nvme_global_config_free();
	nvme_args.output_format = "normal";

	return pass;
}

static bool test_malformed_value_skipped(void)
{
	char *path;
	bool pass = true;

	nvme_args.timeout = 42;
	path = write_temp(
		"[Global]\n"
		"timeout = not-a-number\n"
		"verbose = also-not-a-number\n");

	printf("test_malformed_value_skipped:\n");

	nvme_load_global_config_from(path);
	unlink(path);
	free(path);

	if (nvme_args.timeout != 42) {
		printf(" - bad uint value left field untouched [FAIL]\n");
		pass = false;
	} else {
		printf(" - bad uint value left field untouched [PASS]\n");
	}

	return pass;
}

/*
 * The keys are the global options the help shows; the hidden
 * human-readable is none. A verbose count beyond INT_MAX is rejected.
 */
static bool test_hidden_and_out_of_range(void)
{
	char *path;
	bool pass = true;

	nvme_args.verbose = 1;
	path = write_temp(
		"[Global]\n"
		"human-readable = 5\n"
		"verbose = 4294967295\n");

	printf("test_hidden_and_out_of_range:\n");

	nvme_load_global_config_from(path);
	unlink(path);
	free(path);

	if (nvme_args.verbose != 1) {
		printf(" - hidden key and huge verbose ignored [FAIL]\n");
		pass = false;
	} else {
		printf(" - hidden key and huge verbose ignored [PASS]\n");
	}

	return pass;
}

static bool test_keys_outside_global_ignored(void)
{
	char *path;
	bool pass = true;

	nvme_args.timeout = 7;
	path = write_temp(
		"timeout = 111\n"
		"[Other]\n"
		"timeout = 222\n");

	printf("test_keys_outside_global_ignored:\n");

	nvme_load_global_config_from(path);
	unlink(path);
	free(path);

	if (nvme_args.timeout != 7) {
		printf(" - keys outside [Global] ignored [FAIL]\n");
		pass = false;
	} else {
		printf(" - keys outside [Global] ignored [PASS]\n");
	}

	return pass;
}

static bool test_missing_file_is_noop(void)
{
	bool pass = true;

	nvme_args.timeout = 55;

	printf("test_missing_file_is_noop:\n");

	nvme_load_global_config_from("/nonexistent/nvme-cli.conf");

	if (nvme_args.timeout != 55) {
		printf(" - missing file leaves nvme_args untouched [FAIL]\n");
		pass = false;
	} else {
		printf(" - missing file leaves nvme_args untouched [PASS]\n");
	}

	return pass;
}

/* The global options in front of the command win over the file */
static bool test_command_line_wins(void)
{
	static const char * const args[] = {
		"nvme", "-o", "binary", "-v", "--timeout=7", "list",
	};
	char *argv[ARRAY_SIZE(args) + 1] = {};
	bool pass = true;
	int argind;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(args); i++)
		argv[i] = (char *)args[i];

	printf("test_command_line_wins:\n");

	nvme_args_register();
	nvme_args.verbose = 0;
	nvme_args.timeout = 42;
	if (argconfig_parse_global(6, argv, NULL, &argind) || argind != 5) {
		printf(" - global options parsed [FAIL]\n");
		return false;
	}

	nvme_load_global_config_buf("[Global]\n"
				    "output-format = json\n"
				    "verbose = 2\n"
				    "timeout = not-a-number\n"
				    "timeout = 9\n"
				    "quiet = true\n", "buf");
	if (strcmp(nvme_args.output_format, "binary")) {
		printf(" - the given string stays [FAIL]\n");
		pass = false;
	} else {
		printf(" - the given string stays [PASS]\n");
	}
	if (nvme_args.timeout != 7) {
		printf(" - the given number stays [FAIL]\n");
		pass = false;
	} else {
		printf(" - the given number stays [PASS]\n");
	}
	if (nvme_args.verbose != 3) {
		printf(" - the count adds up [FAIL]\n");
		pass = false;
	} else {
		printf(" - the count adds up [PASS]\n");
	}
	if (!nvme_args.quiet) {
		printf(" - an option not given is set [FAIL]\n");
		pass = false;
	} else {
		printf(" - an option not given is set [PASS]\n");
	}

	/* registering the options again forgets what was given */
	nvme_args_register();
	nvme_load_global_config_buf("[Global]\ntimeout = 9\n", "buf");
	if (nvme_args.timeout != 9) {
		printf(" - a new register starts over [FAIL]\n");
		pass = false;
	} else {
		printf(" - a new register starts over [PASS]\n");
	}

	nvme_global_config_free();
	nvme_args.output_format = "normal";
	nvme_args.verbose = 0;
	nvme_args.quiet = false;

	return pass;
}

static bool run_tests(void)
{
	bool pass = true;

	nvme_args_register();

	pass &= test_valid_keys();
	pass &= test_unknown_key_ignored();
	pass &= test_value_names();
	pass &= test_strict_numbers_and_buf();
	pass &= test_repeated_string();
	pass &= test_malformed_value_skipped();
	pass &= test_hidden_and_out_of_range();
	pass &= test_keys_outside_global_ignored();
	pass &= test_missing_file_is_noop();
	pass &= test_command_line_wins();

	return pass;
}

int main(void)
{
	struct nvme_args initial = nvme_args;
	bool pass = true;

	printf("in process:\n");
	shr_sandbox_enable(false);
	pass &= run_tests();

	/* The same results when the file is parsed in the sandbox */
	printf("sandboxed:\n");
	nvme_global_config_free();
	nvme_args = initial;
	shr_sandbox_enable(true);
	pass &= run_tests();
	shr_sandbox_enable(false);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
