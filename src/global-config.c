// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * /etc/nvme/nvme-cli.conf: a global INI config file for the global options
 * (global-options.c, struct nvme_args). Its keys are their long names.
 * Values from this file become the new defaults; any command-line flag
 * still overrides them, since this is loaded before argument parsing runs.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/ini-util.h>
#include <shared/parse-util.h>

#include "argconfig.h"
#include "global-config.h"

struct global_config_ctx {
	const char *path;
};

static int parse_uint(const char *value, unsigned int *out)
{
	unsigned long v;
	char *end;

	if (!value || !*value || *value == '-')
		return -EINVAL;

	errno = 0;
	v = strtoul(value, &end, 0);
	if (errno || *end || v > (unsigned long)~0U)
		return -EINVAL;

	*out = (unsigned int)v;
	return 0;
}

/* The keys are the global options which the help shows */
static struct argconfig_commandline_options *find_key(const char *key)
{
	struct argconfig_commandline_options *s;

	for (s = argconfig_get_global_options(); s && s->option; s++) {
		if (s->config_type == CFG_GROUP_SEPARATOR || s->deprecated)
			continue;
		if (!strcmp(s->option, key))
			return s;
	}

	return NULL;
}

static int apply_kv(struct global_config_ctx *gc, const char *key,
		     const char *value, unsigned int line)
{
	struct argconfig_commandline_options *s = find_key(key);
	unsigned int uval;
	bool bval;
	char *dup;
	int err;

	if (!s || !s->default_value) {
		fprintf(stderr, "%s:%u: unknown key \"%s\", ignoring\n",
			gc->path, line, key);
		return 0;
	}

	/* 'timeout = infinite' like on the command line */
	if (argconfig_set_value_name(s, value))
		return 0;

	switch (s->config_type) {
	case CFG_FLAG:
		err = shr_parse_bool(value, &bval);
		if (err)
			goto bad_value;
		*(bool *)s->default_value = bval;
		break;
	case CFG_INCREMENT:
		/* the number of times the option is given */
		err = parse_uint(value, &uval);
		if (!err && uval > INT_MAX)
			err = -EINVAL;
		if (err)
			goto bad_value;
		*(int *)s->default_value = uval;
		break;
	case CFG_POSITIVE:
		err = parse_uint(value, &uval);
		if (err)
			goto bad_value;
		*(uint32_t *)s->default_value = uval;
		break;
	case CFG_STRING:
		dup = strdup(value);
		if (!dup)
			return -ENOMEM;
		*(char **)s->default_value = dup;
		break;
	default:
		fprintf(stderr, "%s:%u: key \"%s\" can't be set, ignoring\n",
			gc->path, line, key);
		break;
	}

	return 0;

bad_value:
	if (err == -EINVAL) {
		fprintf(stderr,
			"%s:%u: invalid value \"%s\" for \"%s\", ignoring\n",
			gc->path, line, value, key);
		err = 0;
	}
	return err;
}

static int global_config_event(enum shr_ini_event event, const char *section,
				const char *key, const char *value,
				unsigned int line, void *user_data)
{
	struct global_config_ctx *gc = user_data;

	switch (event) {
	case SHR_INI_SECTION:
		return 0;
	case SHR_INI_KV:
		if (section && !strcmp(section, "Global"))
			return apply_kv(gc, key, value, line);
		fprintf(stderr,
			"%s:%u: \"%s\" outside the [Global] section, ignoring\n",
			gc->path, line, key);
		return 0;
	case SHR_INI_JUNK:
		fprintf(stderr, "%s:%u: malformed line \"%s\", ignoring\n",
			gc->path, line, key);
		return 0;
	}

	return 0;
}

int nvme_load_global_config_from(const char *path)
{
	struct global_config_ctx gc = { .path = path };
	int err;

	err = shr_ini_parse_file(path, global_config_event, &gc);
	if (err && err == -ENOENT)
		err = 0;
	return err;
}

int nvme_load_global_config(void)
{
	return nvme_load_global_config_from(PATH_NVME_CLI_INI);
}
