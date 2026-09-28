// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/str/str.h>
#include <daemon-util/log.h>
#include <shared/ini-util.h>

#include "config.h"

static void config_set_defaults(struct keysd_config *cfg)
{
	cfg->debug_level = DMN_DEFAULT_LOGLEVEL;
}

static void apply_global_key(struct keysd_config *cfg, const char *key,
			     const char *val, const char *conf_path,
			     unsigned int lineno)
{
	int r;

	if (streq(key, "debug-level")) {
		r = dmn_parse_log_level(val, &cfg->debug_level);
	} else {
		log_warn("%s:%u: unknown key '%s', ignored", conf_path,
			 lineno, key);
		return;
	}

	if (r < 0)
		log_warn("%s:%u: invalid value for '%s', ignored", conf_path,
			 lineno, key);
}

struct config_parse_ctx {
	struct keysd_config *cfg;
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
			log_warn("%s:%u: key outside [Global], ignored",
				 pc->conf_path, line);
		break;
	case SHR_INI_JUNK:
		log_warn("%s:%u: malformed line, ignored", pc->conf_path,
			 line);
		break;
	}

	return 0;
}

struct keysd_config *config_load(const char *conf_path)
{
	struct config_parse_ctx pc;
	struct keysd_config *cfg;
	int ret;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;
	config_set_defaults(cfg);

	if (!conf_path)
		conf_path = KEYSD_CONF_PATH;

	pc.cfg = cfg;
	pc.conf_path = conf_path;

	ret = shr_ini_parse_file(conf_path, config_event, &pc);
	if (ret && ret != -ENOENT)
		log_warn("%s: %s, using defaults", conf_path, strerror(-ret));

	return cfg;
}

void config_free(struct keysd_config *cfg)
{
	free(cfg);
}
