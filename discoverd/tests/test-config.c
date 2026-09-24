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

#include <shared/time-util.h>

#include "config.h"

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

/* Write @text to a temp file and load it as a discoverd config. */
static struct discoverd_config *load_text(const char *text)
{
	char path[] = "/tmp/nvme-discoverd-config-XXXXXX";
	struct discoverd_config *cfg;
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
	struct discoverd_config *cfg;
	bool pass = true;

	printf("test_missing_file_defaults:\n");

	cfg = config_load("/nonexistent/nvme-discoverd.conf");
	pass &= check(cfg != NULL, "config_load never returns NULL");
	pass &= check(cfg->nbft, "nbft defaults true");
	pass &= check(cfg->epcsd_poll_interval_minutes == 15,
		      "epcsd-poll-interval-minutes defaults 15");
	pass &= check(cfg->fc_kickstart_interval_minutes == 0,
		      "fc-kickstart-interval-minutes defaults 0");
	pass &= check(cfg->dc_giveup_timeout_usec == 72 * SHR_USEC_PER_HOUR,
		      "dc-giveup-timeout defaults 72hours");

	config_free(cfg);

	return pass;
}

static bool test_discovery_section_parsed(void)
{
	struct discoverd_config *cfg;
	bool pass = true;

	printf("test_discovery_section_parsed:\n");

	cfg = load_text("[Global]\n"
			"nbft = false\n"
			"\n"
			"[Discovery]\n"
			"epcsd-poll-interval-minutes = 30\n"
			"fc-kickstart-interval-minutes = 5\n"
			"dc-giveup-timeout = 2hours\n");
	pass &= check(!cfg->nbft, "[Global] nbft parses");
	pass &= check(cfg->epcsd_poll_interval_minutes == 30,
		      "[Discovery] epcsd-poll-interval-minutes parses");
	pass &= check(cfg->fc_kickstart_interval_minutes == 5,
		      "[Discovery] fc-kickstart-interval-minutes parses");
	pass &= check(cfg->dc_giveup_timeout_usec == 2 * SHR_USEC_PER_HOUR,
		      "[Discovery] dc-giveup-timeout parses");

	config_free(cfg);

	return pass;
}

static bool test_discovery_key_in_global_ignored(void)
{
	struct discoverd_config *cfg;
	bool pass = true;

	printf("test_discovery_key_in_global_ignored:\n");

	cfg = load_text("[Global]\n"
			"epcsd-poll-interval-minutes = 30\n");
	pass &= check(cfg->epcsd_poll_interval_minutes == 15,
		      "epcsd-poll-interval-minutes in [Global] ignored");

	config_free(cfg);

	return pass;
}

static bool test_global_key_in_discovery_ignored(void)
{
	struct discoverd_config *cfg;
	bool pass = true;

	printf("test_global_key_in_discovery_ignored:\n");

	cfg = load_text("[Discovery]\n"
			"nbft = false\n");
	pass &= check(cfg->nbft, "nbft in [Discovery] ignored");

	config_free(cfg);

	return pass;
}

static bool test_invalid_and_unknown_ignored(void)
{
	struct discoverd_config *cfg;
	bool pass = true;

	printf("test_invalid_and_unknown_ignored:\n");

	cfg = load_text("[Discovery]\n"
			"fc-kickstart-interval-minutes = -1\n"
			"bogus-key = 1\n"
			"epcsd-poll-interval-minutes = 30\n"
			"\n"
			"[Bogus Section]\n"
			"epcsd-poll-interval-minutes = 9\n");
	pass &= check(cfg->fc_kickstart_interval_minutes == 0,
		      "invalid value ignored, default kept");
	pass &= check(cfg->epcsd_poll_interval_minutes == 30,
		      "valid keys apply despite invalid siblings");

	config_free(cfg);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_missing_file_defaults();
	pass &= test_discovery_section_parsed();
	pass &= test_discovery_key_in_global_ignored();
	pass &= test_global_key_in_discovery_ignored();
	pass &= test_invalid_and_unknown_ignored();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
