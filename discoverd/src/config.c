// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>
#include <shared/ini.h>
#include <shared/parse-util.h>

#include "config.h"
#include "log.h"

static void config_set_defaults(struct discoverd_config *cfg)
{
	cfg->nbft = true;
	cfg->debug_level = DISC_LOG_INFO;
	cfg->fc_kickstart_interval_minutes = 0;
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
			     const char *val, const char *conf_path,
			     unsigned int lineno)
{
	int r = 0;

	if (streq(key, "nbft"))
		r = shr_parse_bool(val, &cfg->nbft);
	else if (streq(key, "debug-level"))
		r = parse_debug_level(val, &cfg->debug_level);
	else if (streq(key, "fc-kickstart-interval-minutes"))
		r = parse_uint(val, &cfg->fc_kickstart_interval_minutes);
	else
		disc_warn("%s:%u: unknown key '%s', ignored", conf_path,
			  lineno, key);

	if (r < 0)
		disc_warn("%s:%u: invalid value for '%s', ignored", conf_path,
			  lineno, key);
}

struct config_parse_ctx {
	struct discoverd_config *cfg;
	const char *conf_path;
};

static int config_event(enum shr_ini_event event, const char *section,
			const char *key, const char *value,
			unsigned int line, void *user_data)
{
	struct config_parse_ctx *pc = user_data;

	switch (event) {
	case SHR_INI_SECTION:
		break;
	case SHR_INI_KV:
		if (section && streq(section, "Global"))
			apply_global_key(pc->cfg, key, value, pc->conf_path,
					 line);
		else
			disc_warn("%s:%u: key outside [Global], ignored",
				  pc->conf_path, line);
		break;
	case SHR_INI_JUNK:
		disc_warn("%s:%u: malformed line, ignored", pc->conf_path,
			  line);
		break;
	}
	return 0;
}

struct discoverd_config *config_load(const char *conf_path)
{
	struct discoverd_config *cfg;
	struct config_parse_ctx pc;
	int ret;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;
	config_set_defaults(cfg);

	if (!conf_path)
		conf_path = DISCOVERD_CONF_PATH;

	pc.cfg = cfg;
	pc.conf_path = conf_path;

	/* A missing config file is not an error — defaults apply. */
	ret = shr_ini_parse_file(conf_path, config_event, &pc);
	if (ret && ret != -ENOENT)
		disc_warn("%s: %s, using defaults", conf_path,
			 strerror(-ret));

	return cfg;
}

void config_free(struct discoverd_config *cfg)
{
	free(cfg);
}
