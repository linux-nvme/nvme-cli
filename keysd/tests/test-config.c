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
#include <shared/string-util.h>

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

static bool test_kmip_parsed(void)
{
	const struct keysd_kmip *kms;
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_kmip_parsed:\n");

	cfg = load_text("[kmip:primary]\n"
			"server = kms1.example.com\n"
			"server = kms2.example.com\n"
			"server = kms1.example.com\n"
			"port = 5697\n"
			"ca = /etc/nvme/kmip/ca.pem\n"
			"client-cert = /etc/nvme/kmip/client.pem\n"
			"client-key = primary\n"
			"timeout = 500ms\n"
			"\n"
			"[kmip:backup]\n"
			"server = 192.0.2.1\n");
	pass &= check(cfg->nr_kmip == 2 &&
		      shr_streq0(cfg->kmip[0].name, "primary") &&
		      shr_streq0(cfg->kmip[1].name, "backup"),
		      "two KMSes, in the order of the file");

	kms = config_find_kmip(cfg, "primary");
	pass &= check(kms && kms->nr_servers == 2 &&
		      shr_streq0(kms->servers[0], "kms1.example.com") &&
		      shr_streq0(kms->servers[1], "kms2.example.com") &&
		      shr_streq0(kms->port, "5697") &&
		      shr_streq0(kms->ca, "/etc/nvme/kmip/ca.pem") &&
		      shr_streq0(kms->client_cert,
				 "/etc/nvme/kmip/client.pem") &&
		      shr_streq0(kms->client_key, "primary") &&
		      kms->timeout_ms == 500,
		      "all keys parsed");

	kms = config_find_kmip(cfg, "backup");
	pass &= check(kms && shr_streq0(kms->port, KEYSD_KMIP_PORT) &&
		      !kms->ca && !kms->client_cert && !kms->client_key &&
		      kms->timeout_ms == KEYSD_KMIP_TIMEOUT_MS,
		      "defaults");
	pass &= check(!config_find_kmip(cfg, "other"), "unknown name");

	config_free(cfg);

	return pass;
}

static bool test_kmip_invalid(void)
{
	const struct keysd_kmip *kms;
	struct keysd_config *cfg;
	bool pass = true;

	printf("test_kmip_invalid:\n");

	cfg = load_text("[kmip:a]\n"
			"server = kms-a\n"
			"server = kms a\n"
			"port = 0\n"
			"ca = ca.pem\n"
			"client-key = ../key\n"
			"timeout = 1h\n"
			"bogus = 1\n"
			"\n"
			"[kmip:a]\n"
			"server = kms-dup\n"
			"\n"
			"[kmip:b/c]\n"
			"server = kms-bc\n"
			"\n"
			"[kmip:no-server]\n"
			"port = 5696\n"
			"\n"
			"[kmip:cert-only]\n"
			"server = kms-cert\n"
			"client-cert = /etc/nvme/kmip/client.pem\n");
	pass &= check(cfg->nr_kmip == 1, "invalid sections dropped");

	kms = config_find_kmip(cfg, "a");
	pass &= check(kms && kms->nr_servers == 1 &&
		      shr_streq0(kms->servers[0], "kms-a"),
		      "duplicate section and invalid server ignored");
	pass &= check(kms && shr_streq0(kms->port, KEYSD_KMIP_PORT) &&
		      !kms->ca && !kms->client_key &&
		      kms->timeout_ms == KEYSD_KMIP_TIMEOUT_MS,
		      "invalid values ignored");

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
	pass &= test_kmip_parsed();
	pass &= test_kmip_invalid();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
