// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <daemon-util/log.h>

#include "config.h"

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

/* Write @text to a temp file and load it as an nvme-keysd config. */
static struct keysd_config *load_text(const char *text)
{
	char path[] = "/tmp/nvme-keysd-config-XXXXXX";
	struct keysd_config *cfg;
	size_t len = strlen(text);
	int fd;

	fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "mkstemp: failed\n");
		exit(EXIT_FAILURE);
	}
	if (write(fd, text, len) != (ssize_t)len) {
		fprintf(stderr, "write: failed\n");
		exit(EXIT_FAILURE);
	}
	close(fd);

	cfg = config_load(path);
	unlink(path);

	return cfg;
}

static bool test_missing_file_defaults(void)
{
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_missing_file_defaults:\n");

	cfg = config_load("/nonexistent/nvme-keysd.conf");
	pass &= check(cfg != NULL, "config_load never returns NULL");
	pass &= check(cfg->debug_level == DMN_LOG_INFO,
		      "debug-level defaults to info");

	config_free(cfg);

	return pass;
}

static bool test_global_parsed(void)
{
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_global_parsed:\n");

	cfg = load_text("[Global]\n"
			"debug-level = DEBUG\n");
	pass &= check(cfg->debug_level == DMN_LOG_DEBUG,
		      "debug-level parses, case-insensitive");

	config_free(cfg);

	return pass;
}

static bool test_invalid_values_ignored(void)
{
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_invalid_values_ignored:\n");

	cfg = load_text("[Global]\n"
			"debug-level = verbose\n");
	pass &= check(cfg->debug_level == DMN_LOG_INFO,
		      "unknown debug-level ignored, default kept");

	config_free(cfg);

	return pass;
}

static bool test_unknown_key_and_section_ignored(void)
{
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_unknown_key_and_section_ignored:\n");

	cfg = load_text("[Global]\n"
			"bogus-key = 1\n"
			"debug-level = warn\n"
			"\n"
			"[Bogus]\n"
			"debug-level = debug\n");
	pass &= check(cfg->debug_level == DMN_LOG_WARN,
		      "valid key applies, other section ignored");

	config_free(cfg);

	return pass;
}

static bool test_malformed_line_ignored(void)
{
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_malformed_line_ignored:\n");

	cfg = load_text("[Global]\n"
			"not a key value line\n"
			"debug-level = warn\n");
	pass &= check(cfg->debug_level == DMN_LOG_WARN,
		      "malformed line skipped, next line applies");

	config_free(cfg);

	return pass;
}

static bool test_unreadable_file_defaults(void)
{
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_unreadable_file_defaults:\n");

	cfg = config_load("/");
	pass &= check(cfg != NULL, "a directory as config file");
	pass &= check(cfg->debug_level == DMN_LOG_INFO,
		      "debug-level defaults to info");

	config_free(cfg);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_missing_file_defaults();
	pass &= test_global_parsed();
	pass &= test_invalid_values_ignored();
	pass &= test_unknown_key_and_section_ignored();
	pass &= test_malformed_line_ignored();
	pass &= test_unreadable_file_defaults();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
