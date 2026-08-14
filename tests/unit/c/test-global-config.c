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

#include <shared/shr-assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/fs-util.h>

#include "../src/global-config.h"
#include "../src/args.h"

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

int main(void)
{
	bool pass = true;

	pass &= test_valid_keys();
	pass &= test_unknown_key_ignored();
	pass &= test_malformed_value_skipped();
	pass &= test_keys_outside_global_ignored();
	pass &= test_missing_file_is_noop();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
