// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "log.h"
#include "string-util.h"

static void config_set_defaults(struct discoverd_config *cfg)
{
	cfg->nbft = true;
	cfg->debug_level = DISC_LOG_INFO;
	cfg->fc_kickstart_interval_minutes = 0;
}

/* systemd parse_boolean() convention: 1/yes/y/true/t/on, 0/no/n/false/f/off. */
static int parse_bool(const char *val, bool *out)
{
	static const char * const truthy[] = { "1", "yes", "y", "true", "t", "on" };
	static const char * const falsy[]  = { "0", "no", "n", "false", "f", "off" };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(truthy); i++) {
		if (!strcasecmp(val, truthy[i])) {
			*out = true;
			return 0;
		}
	}
	for (i = 0; i < ARRAY_SIZE(falsy); i++) {
		if (!strcasecmp(val, falsy[i])) {
			*out = false;
			return 0;
		}
	}
	return -EINVAL;
}

static int parse_debug_level(const char *val, int *out)
{
	static const char * const names[] = {
		[DISC_LOG_ERR]   = "err",
		[DISC_LOG_WARN]  = "warn",
		[DISC_LOG_INFO]  = "info",
		[DISC_LOG_DEBUG] = "debug",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (!strcasecmp(val, names[i])) {
			*out = (int)i;
			return 0;
		}
	}
	return -EINVAL;
}

static int parse_uint(const char *val, unsigned int *out)
{
	char *end;
	unsigned long v;

	if (val[0] == '-')
		return -EINVAL;

	v = strtoul(val, &end, 10);
	if (end == val || *end != '\0' || v > UINT_MAX)
		return -EINVAL;
	*out = (unsigned int)v;
	return 0;
}

/* Apply one "key = value" line from [Global]; @lineno is for diagnostics. */
static void apply_global_key(struct discoverd_config *cfg, const char *key,
			     const char *val, const char *conf_path, int lineno)
{
	int r = 0;

	if (streq(key, "nbft"))
		r = parse_bool(val, &cfg->nbft);
	else if (streq(key, "debug-level"))
		r = parse_debug_level(val, &cfg->debug_level);
	else if (streq(key, "fc-kickstart-interval-minutes"))
		r = parse_uint(val, &cfg->fc_kickstart_interval_minutes);
	else
		disc_warn("%s:%d: unknown key '%s', ignored", conf_path,
			  lineno, key);

	if (r < 0)
		disc_warn("%s:%d: invalid value for '%s', ignored", conf_path,
			  lineno, key);
}

struct discoverd_config *config_load(const char *conf_path)
{
	struct discoverd_config *cfg;
	FILE *f;
	char line[256];
	char section[64] = "";
	int lineno = 0;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;
	config_set_defaults(cfg);

	if (!conf_path)
		conf_path = DISCOVERD_CONF_PATH;

	f = fopen(conf_path, "r");
	if (!f) {
		/* A missing config file is not an error — defaults apply. */
		if (errno != ENOENT)
			disc_warn("%s: %s, using defaults", conf_path,
				 strerror(errno));
		return cfg;
	}

	while (fgets(line, sizeof(line), f)) {
		char *s = trim(line);
		char *eq, *key, *val;
		size_t len;

		lineno++;
		if (*s == '\0' || *s == '#' || *s == ';')
			continue;

		len = strlen(s);
		if (s[0] == '[' && s[len - 1] == ']') {
			s[len - 1] = '\0';
			snprintf(section, sizeof(section), "%s", trim(s + 1));
			continue;
		}

		eq = strchr(s, '=');
		if (!eq) {
			disc_warn("%s:%d: malformed line, ignored", conf_path,
				  lineno);
			continue;
		}
		*eq = '\0';
		key = trim(s);
		val = trim(eq + 1);
		if (*key == '\0' || *val == '\0') {
			disc_warn("%s:%d: malformed line, ignored", conf_path,
				  lineno);
			continue;
		}

		if (streq(section, "Global"))
			apply_global_key(cfg, key, val, conf_path, lineno);
		else
			disc_warn("%s:%d: key outside [Global], ignored",
				  conf_path, lineno);
	}

	fclose(f);
	return cfg;
}

void config_free(struct discoverd_config *cfg)
{
	free(cfg);
}
